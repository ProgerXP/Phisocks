<?php
/*
  Phisocks - SOCKS4/4a/5/5h client implementation for PHP 5.2+
  in public domain | by Proger_XP | http://proger.me
  https://github.com/ProgerXP/Phisocks

  Standalone using native PHP sockets.
  Supports basic authentication and CONNECT command.
  Supports TCP and IPv4 only.
  Switch between 4(5) and 4a(5h) by adjusting $remoteDNS.

 ***

  SOCKS 4 spec:   http://www.openssh.com/txt/socks4.protocol
  SOCKS 4a spec:  http://www.openssh.com/txt/socks4a.protocol
  SOCKS 5 spec:   https://www.ietf.org/rfc/rfc1928.txt
  SOCKS 5h is (per cURL definition) SOCKS 5 with remote DNS resolution
  SOCKS 5 Username/Password auth spec:
                  https://tools.ietf.org/html/rfc1929

 ***

  // Create new instance and set it up.
  $phisocks = Phisocks::make('127.0.0.1');
  $phisocks->remoteDNS = true;
  $phisocks->basicAuth('socksy', 'sassy');

  // Open remote connection to SOCKS server which opens it to the target
  // (google.com:80) and fails on error.
  $phisocks->connect('google.com', 443);

  // For plain HTTP requests this is not necessary but if HTTPS is expected
  // you will get blank response without enavling client crypto.
  $phisocks->enableCrypto();

  // Everything is up to the plan - tunnel some data. HTTP here is just
  // an example.
  echo $phisocks->httpGET('/');

  // Connection will also be dropped when the object is destroyed.
  $phisocks->close();
*/

class EPhisocks extends Exception {
  public $obj;    //= Phisocks, null

  static function fail($msg, Phisocks $obj = null) {
    $e = new static("Phisocks: $msg");
    $e->obj = $obj;
    throw $e;
  }
}

class Phisocks {
  public $host;           //= str IP or hostname
  public $port = 1080;    //= int
  public $version = 5;    //= int 4 or 5
  public $timeout;        //= int, null defaults to default_socket_timeout

  //= true let $host resolve $targetHost
  //= false to resolve it locally and fail if cannot
  //= 'try' to try resolving locally and if fails - pass on
  public $remoteDNS = 'try';

  //= string for SOCKS4
  public $userID = '';

  //= array of PhisocksAuth
  protected $auth = array();
  protected $protocol;    //= PhisocksProtocol

  // Specify what is the final target (connected thru to).
  protected $targetHost;  //= str IP or hostname
  protected $targetPort;  //= int

  protected $handle;      //= resource fsockopen()

  // Either call as make(array('host' => '1.2.3.4')) or make('1.2.3.4').
  // If one argument is given then $settings must be an array of options
  // (this object's public properties). If two - $settings is the SOCKS
  // server's IP/hostname.
  //
  //? make(array('host' => '127.0.0.1', 'port' => 1085, 'version' => 4))
  //? make('127.0.0.1', 1085)
  static function make($settings, $port = 1080) {
    return new static($settings);
  }

  function __construct($settings, $port = 1080) {
    is_array($settings) or $settings = array('host' => $settings);
    func_num_args() > 1 and $settings += compact('port');

    $props = get_object_vars($this);
    $this->auth[0] = new PhisocksNoAuth;

    foreach ($settings as $prop => $value) {
      array_key_exists($prop, $props) and $this->$prop = $value;
    }
  }

  function __destruct() {
    $this->close();
  }

  function basicAuth($login, $password) {
    $this->auth[__FUNCTION__] = new PhisocksBasicAuth($login, $password);
    return $this;
  }

  // Can be called multiple times on one Phisocks object. Each call
  // closes the previous connection, if any.
  function connect($host, $port) {
    if (!filter_var($port, FILTER_VALIDATE_INT) or $port < 1 or $port > 0xFFFF) {
      EPhisocks::fail("target port [$port] is invalid", $this);
    } elseif (!$this->host) {
      EPhisocks::fail("SOCKS server host is unspecified", $this);
    }

    $this->targetHost = (string) $host;
    $this->targetPort = (int) $port;

    $this->close();
    $this->protocol = $this->makeProtocol($this->version);

    $timeout = $this->timeout ?: ini_get('default_socket_timeout');
    $this->handle = fsockopen($this->host, $this->port, $code, $error, $timeout);

    if (!$this->handle) {
      EPhisocks::fail("cannot fsockopen($this->host, $this->port) due to #$code: $error", $this);
    }

    try {
      $this->protocol->connect();
      $this->protocol->startRelaying();
    } catch (Exception $e) {
      try {
        $this->close();
      } catch (Exception $e) {
        // Ignore.
      }

      throw $e;
    }

    return $this;
  }

  protected function makeProtocol($version) {
    switch ($version) {
    case 4:
      return new Phisocks4($this);
    case 5:
      return new Phisocks5($this);
    default:
      EPhisocks::fail("unknown SOCKS protocol version [$version]", $this);
    }
  }

  function close($return = null) {
    $this->isOpened() and fclose($this->handle);
    $this->handle = null;
    return func_num_args() ? $return : $this;
  }

  function isOpened() {
    return is_resource($this->handle);
  }

  function ensureOpened($func = 'function') {
    if (!$this->isOpened()) {
      EPhisocks::fail("$func must be called after a connection has been opened", $this);
    }
  }

  function handle() {
    return $this->handle;
  }

  function auth() {
    return $this->auth;
  }

  // Returns array(0x11223344, true) or array('host.name', false).
  // 3rd element is $targetPort in native order (not network order).
  //
  //= array(int $ip or str 'host.name', bool $isIP, int $port)
  function resolveTarget() {
    $host = $this->targetHost;
    $isIP = filter_var($host, FILTER_VALIDATE_IP);

    if ($isIP) {
      $host = ip2long($host);
    } elseif (true === $mode = $this->remoteDNS) {
      // Fall through.
    } elseif ($ip = gethostbyname($host)) {
      $host = ip2long($ip);
      $isIP = true;
    } elseif ($mode === 'try') {
      // Fall through.
    } else {
      EPhisocks::fail("cannot resolve [$host] target locally", $this);
    }

    if ($isIP and !$host) {
      EPhisocks::fail("unexpected ip2long() problem with target resolution", $this);
    }

    return array($host, $isIP, $this->targetPort);
  }

  function write($s) {
    $num = fwrite($this->handle, $s);
    if (strlen($s) !== $num) {
      EPhisocks::fail("written only $num bytes out of ".strlen($s), $this);
    } else {
      return $this;
    }
  }

  function read($num, $orLess = false) {
    $s = fread($this->handle, $num);
    if (strlen($s) !== $num) {
      EPhisocks::fail("read only ".strlen($s)." bytes out of $num", $this);
    } else {
      return $s;
    }
  }

  function readAll() {
    return stream_get_contents($this->handle);
  }

  function readAllAndClose() {
    return $this->close($this->readAll());
  }

  function enableCrypto($type = STREAM_CRYPTO_METHOD_TLS_CLIENT) {
    $this->ensureOpened(__FUNCTION__);
    stream_socket_enable_crypto($this->handle, true, $type);
    return $this;
  }

  //* $url str - relative to site root.
  //* $headers str - each header must end with \r\n.
  //
  //? httpGET('/image.jpg', 'Host: example.com')
  function httpGET($url = '/', $headers = '') {
    $this->ensureOpened(__FUNCTION__);
    ($headers = trim($headers)) === '' or $headers .= "\r\n";

    // Note: in HTTP/1.1 Connection defaults to Keep Alive which will keep
    // the connection hanging unless you send 'Connection: close'. Its output
    // also changes due to chunked transfer encoding.
    $headers = "GET $url HTTP/1.0\r\n".
               $headers."\r\n";

    $this->write($headers);
    return $this->readAll();
  }

  //? httpPOST('/form.php', array('name' => 'Joe'))
  function httpPOST($url, array $data, $headers = '') {
    $this->ensureOpened(__FUNCTION__);
    $query = http_build_query($data, '', '&');
    ($headers = trim($headers) === '') or $headers .= "\r\n";

    $headers = "POST $url HTTP/1.0\r\n".
               $headers.
               "Content-Type: application/x-www-form-urlencoded\r\n".
               "Content-Length: ".strlen($query)."\r\n".
               "$query\r\n";

    $this->write($headers);
    return $this->readAllAndClose();
  }
}

abstract class PhisocksProtocol {
  protected $obj;   //= Phisocks

  function __construct(Phisocks $obj) {
    $this->obj = $obj;
  }

  // Initiate a CONNECT request.
  abstract function connect();

  // Called after successful handshake.
  function startRelaying() { }
}

class Phisocks4 extends PhisocksProtocol {
  function connect() {
    list($target, $isIP, $port) = $this->obj->resolveTarget();

    $s = "\4\1".pack('n', $port).
         ($isIP ? pack('N', $target) : "\0\0\0\x2C").
         $this->obj->userID."\0";

    $isIP or $s .= "$target\0";

    $this->obj->write($s);

    extract(unpack('Cversion/Ccode/ndestPort/NdestIP', $this->obj->read(8)));

    if ($version !== 0) {
      EPhisocks::fail("wrong SOCKS4 response version [$version]", $this->obj);
    }

    switch ($code) {
    case 90:
      break;
    case 91:
      EPhisocks::fail("SOCKS4 request rejected or has failed", $this->obj);
    case 92:
      EPhisocks::fail("SOCKS4 request rejected becasue SOCKS server cannot connect".
                      " to identd on the client or the given user-id is wrong", $this->obj);
    case 93:
      EPhisocks::fail("SOCKS4 request rejected because the client program and identd".
                      " report different user-ids", $this->obj);
    default:
      EPhisocks::fail("wrong SOCKS4 response code [$code]", $this->obj);
    }
  }
}

class Phisocks5 extends PhisocksProtocol {
  function connect() {
    $this->auth();

    list($target, $isIP, $port) = $this->obj->resolveTarget();

    $s = "\5\1\0".
         ($isIP ? "\1".pack('N', $target) : "\3".chr(strlen($target)).$target).
         pack('n', $port);

    $this->obj->write($s);

    extract(unpack('Cversion/Ccode/Creserved/CaddressType', $this->obj->read(4)));

    // RSV is unchecked (must be 0x00).

    if ($version !== 5) {
      EPhisocks::fail("wrong SOCKS5 response version [$version]", $this->obj);
    }

    switch ($code) {
    case 0:
      break;
    case 1:
      EPhisocks::fail("SOCKS5 general server failure", $this->obj);
    case 2:
      EPhisocks::fail("SOCKS5 connection not allowed by ruleset", $this->obj);
    case 3:
      EPhisocks::fail("SOCKS5 reported unreachable network", $this->obj);
    case 4:
      EPhisocks::fail("SOCKS5 reported unreachable host", $this->obj);
    case 5:
      EPhisocks::fail("SOCKS5 reported refused connection", $this->obj);
    case 6:
      EPhisocks::fail("SOCKS5 reported expired TTL", $this->obj);
    case 7:
      EPhisocks::fail("SOCKS5 reported unsupported command", $this->obj);
    case 8:
      EPhisocks::fail("SOCKS5 reported unsupported address type", $this->obj);
    default:
      EPhisocks::fail("wrong SOCKS5 response code [$code]", $this->obj);
    }

    switch ($addressType) {
    case 1:
      $destIP = $this->obj->read(4);
      break;
    case 3:
      $length = $this->obj->read(1);
      $destHost = $this->obj->read($length);
      break;
    case 4:
      $destIP = $this->obj->read(16);
      break;
    default:
      EPhisocks::fail("wrong SOCKS5 response address type [$addressType]");
    }

    $destPort = $this->obj->read(2);
  }

  protected function auth() {
    $map = array();

    foreach ($this->obj->auth() as $auth) {
      $map[chr($auth->code)] = $auth;
      if (count($map) >= 0xFF) { break; }
    }

    $s = "\5".chr(count($map)).join(array_keys($map));
    $this->obj->write($s);

    extract(unpack('Cversion/Cmethod', $this->obj->read(2)));

    if ($version !== 5) {
      EPhisocks::fail("wrong SOCKS5 auth response version [$version]", $this->obj);
    } elseif ($method === 0xFF or !($auth = &$map[chr($method)])) {
      EPhisocks::fail("no suitable SOCKS5 auth methods available", $this->obj);
    }

    $auth->auth($this->obj);
  }
}

abstract class PhisocksAuth {
  public $code;

  abstract function auth(Phisocks $obj);
}

class PhisocksNoAuth extends PhisocksAuth {
  public $code = 0;

  function auth(Phisocks $obj) { }
}

class PhisocksBasicAuth extends PhisocksAuth {
  public $code = 2;

  public $login;      //= str 0-255 chars long
  public $password;   //= str 0-255 chars long

  function __construct($login, $password) {
    $this->login = $login;
    $this->password = $password;
  }

  function auth(Phisocks $obj) {
    if (255 < $llen = strlen($this->login) or 255 < $plen = strlen($this->password)) {
      EPhisocks::fail("SOCKS5 basic auth login [$this->login] and password".
                      " [$this->password] each must be at most 255 characters long", $obj);
    }

    $s = "\1".chr($llen).$this->login.chr($plen).$this->password;
    $obj->write($s);

    extract(unpack('Cversion/Ccode', $obj->read(2)));

    // VER value doesn't seem to be specified in the RFC.
    if ($version !== 1) {
      EPhisocks::fail("wrong SOCKS5 basic auth response version [$version]", $this->obj);
    } elseif ($code !== 0) {
      EPhisocks::fail("SOCKS5 basic auth credentials rejected with code #$code", $this->obj);
    }
  }
}
