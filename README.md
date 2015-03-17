# Phisocks
SOCKS4/4a/5/5h client implementation for PHP 5.2+

Standalone using native PHP sockets.

Supports basic authentication and **CONNECT** command.

Supports TCP and IPv4 only.

Switch between 4(5) and 4a(5h) by adjusting `$remoteDNS`.

Consult source code for detailed configuration info.

* SOCKS 4 spec:   http://www.openssh.com/txt/socks4.protocol
* SOCKS 4a spec:  http://www.openssh.com/txt/socks4a.protocol
* SOCKS 5 spec:   https://www.ietf.org/rfc/rfc1928.txt
* SOCKS 5h is (per cURL definition) SOCKS 5 with remote DNS resolution
* SOCKS 5 Username/Password auth spec:  https://tools.ietf.org/html/rfc1929

## Usage example

```PHP
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
```
