Test-suite that checks the certificate-based wolfssl and botan engines

### How to run?
Make sure to first install Python:
- sudo apt update
- sudo apt install python3.6
- sudo apt-get -y install python3-pip
- pip3 install html-testRunner (unittest test runner that save test results in Html files)
- Change directory to "misc" folder and run:
  1. "pip3 install cryptography-3.3.1-cp36-cp36m-linux_x86_64.whl"
  2. "pip3 install -e ./pyOpenSSL-20.0.1 --no-deps"

In order to run it:
- for wolfssl engine: ./main.py <full/path/to/libwolfssl_tls_api_wrapper.so>
- for botan engine: ./main.py <full/path/to/libbotan_tls_api_wrapper.so>

The result will be printed in the console and an HTML report will be created in "reports" folder.

###### NOTICE:
In order to use this test environment in another project, one has to take the folder and add it in the new project.
The "tls_${ENGINE}" in misc/cwrapper/CMakeLists.txt should be changed to the relevant lib.
Finally, you should call the CMakeLists (The one in the current folder) as part of the new project.

### What is tested?

#### test_backend.py test:
It runs HTTPS server, and in each test it tries to establish TLS connection with different client declared.
Each test handles a new server.
Eventually server will be created according to a Cartesian product of the following parameters:
tls version:    tlsv1.1, tlsv1.2, tlsv1.3
cipher suite:   cipher suite to config the server
ec_curve:       Which EC point to config the server
alpn server:    client alpn protocol
alpn client:    server alpn protocol

In each test, the client tries to create a tls connection when the server is configured differently each time.
Checking whether the connection should be successful or not depends on the TLS library settings.

##### Server Configuration:
<table>
  <tr>
    <th>TLS version</th>
    <th>Cipher Suites</th>
    <th>Elliptic Curve Points</th>
    <th>server ALPN</th>
    <th>client ALPN</th>
  </tr>
  <tr>
    <td>TLS Version 1.1</td>
    <td>-</td>
    <td>-</td>
    <td>-</td>
    <td>-</td>
  </tr>
  <tr>
    <td>TLS version 1.2</td>
    <td>Supported/Unsupported</td>
    <td>Supported / Unsupported</td>
    <td>Suitable / Unsuitable X <br>Valid / Invalid</td>
    <td>Suitable / Unsuitable X <br>Valid / Invalid</td>
  </tr>
  <tr>
    <td>TLS version 1.3</td>
    <td>Supported / Unsupported</td>
    <td>Supported / Unsupported</td>
    <td>Suitable / Unsuitable X <br>Valid / Invalid</td>
    <td>Suitable / Unsuitable X <br>Valid / Invalid</td>
  </tr>
</table>

##### Examples:
run test:
TLS version: TLSv1.2<br>
server cipher suite: ECDHE-ECDSA-AES128-SHA256<br>
ec point: sect163k1<br>
client protocol: h2<br>
server protocol: h2 http/1.1<br>
Expected: False - Because the ec point is not supported by the library.

#### test_cipher_suites_use_cases.py test:
It runs HTTPS server, and in each test it tries to establish TLS connection with different client & server configuration.
Eventually server will be created in each test with another cipher suite, 
and the client will be declared with cipher suite use case list.
So overall every client cipher suites use case checks with every cipher suite (from the total supported cipher suites).