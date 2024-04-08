import threading
import socket
from globals import *
from OpenSSL import SSL, crypto
from socketserver import TCPServer, BaseRequestHandler


class EchoTCPRequestHandler(BaseRequestHandler):
    """
    This class handles requests for our SSL TCP server.
    It is instantiated once per connection to the server.
    """

    def handle(self):
        """
        Handles the request from the client.
        doing echo - return back what client sent.
        """

        while True:
            try:
                data = self.request.recv(1024)

                if not data:
                    break

                self.request.sendall(data)
            except (SSL.ZeroReturnError, SSL.Error):
                break

class TLSServer(TCPServer):
    """
    This class represents simple TLS server.
    """

    allow_reuse_address = True

    def __init__(self, ip, port, tls_protocol, server_cert_file_path, server_private_key_file_path):
        """
        Constructor.

        :param ip: Server's IP
        :param port: Server's port
        :param tls_protocol: TLS protocol version which the server will use
        :param server_cert_file_path: Server's certificate
        :param server_private_key_file_path: Server's private key
        """

        self._server_thread = threading.Thread(target=self.serve_forever)

        self._tls_version = tls_protocol
        self._ssl_ctx = SSL.Context(self._tls_version.value)

        self.server_cert_path = server_cert_file_path

        self._ssl_ctx.use_certificate_chain_file(server_cert_file_path)
        self._ssl_ctx.use_privatekey_file(server_private_key_file_path)
        self._ssl_ctx.check_privatekey()

        self._ocsp_stapling_file_path = None
        self._ssl_ctx.set_ocsp_server_callback(self._get_ocsp_status)

        self._alpn_protocol = None
        self._ssl_ctx.set_alpn_select_callback(self._choose_alpn_protocol)

        super().__init__((ip, port), EchoTCPRequestHandler, bind_and_activate=False)

    def shutdown_request(self, request):
        """
        Override original method to handle client socket shutdown request.
        """

        try:
            request.sock_shutdown(socket.SHUT_WR)
        except OSError:
            pass

        self.close_request(request)

    def shutdown(self):
        """
        Override super's shutdown method
        """

        if self._server_thread.is_alive():
            super().shutdown()
            self._server_thread.join()

        self.server_close()

    def run(self):
        """
        Bind the server, activate it and execute it in separate daemon thread.
        """

        self.server_bind()

        self.socket = SSL.Connection(self._ssl_ctx, self.socket)

        self.server_activate()

        # Executing server in daemon thread.
        self._server_thread.daemon = True
        self._server_thread.start()

    def get_name(self):
        """
        Gets subject's CN (common-name) according to the x509 certificate.

        :return: subject's common name string.
        """

        cert_subject = self.socket.get_certificate().get_subject()

        return cert_subject.commonName

    def get_server_certificate_path(self):
        """
        Gets server's x509 certificate path.

        :return: server's x509 certificate path.
        """

        return self.server_cert_path

    def get_signature_algorithm_type(self):
        """
        Gets certificate signature algorithm type

        :return: the algorithm type. SignatureAlgorithmType type RSA or ECDSA
        """

        algo = self.socket.get_certificate().get_signature_algorithm().decode()

        if algo == 'sha256WithRSAEncryption':
            return SignatureAlgorithmType.RSA

        elif algo == 'ecdsa-with-SHA256':
            return SignatureAlgorithmType.ECDSA

        return None

    def set_ciphers_list(self, cipher):
        """
        Sets server's cipher suites to be used.

        :param cipher: a cipher suites string in openssl format.
        """

        if self._tls_version == TLSProtocolVersionType.TLS_1_3:
            self._ssl_ctx.set_ciphersuites(cipher)
        else:
            self._ssl_ctx.set_cipher_list(cipher)

    def load_dh_params(self, dh_file):
        """
        Load the key generation parameters for Diffie-Hellman (DH) key exchange.

        :param file: the path to a file containing DH parameters in PEM format.
        """

        self._ssl_ctx.load_tmp_dh(dh_file)

    def set_ecdh_curve(self, ec_point_name):
        """
        Set the curve name for Elliptic Curve-based Diffie-Hellman (ECDH) key exchange.

        :param ec_point_type:  an enum ECPointType describing a well-known elliptic curve.
        """

        curve = crypto.get_elliptic_curve(ec_point_name.value)
        self._ssl_ctx.set_tmp_ecdh(curve)

    def set_ocsp_stapling(self, ocsp_response_file_path):
        """
        Sets OCSP stapling.

        :param ocsp_response_file_path: Path to DER file which contains the OCSP Response to staple.
                                        If None the server won't send OCSP stapling.
        """

        self._ocsp_stapling_file_path = ocsp_response_file_path

    def set_alpn_protocol(self, protocols):
        """
        Sets server's supported ALPN protocols.

        :param protocols: List of ALPN protocols enum that the server should support.
                            use 'None' to disable ALPN extension in server.
        :return:
        """

        if protocols != None:
            self._alpn_protocol = [item.value for item in protocols]
        else:
            self._alpn_protocol = None

    def _get_ocsp_status(self, connection, data):
        """
        Callback function that provide OCSP data to be stapled to the TLS handshake.

        :param connection: Server's connection, socket.
        :param data: Optional arbitrary data that provided in the callback register function.
        :return: A bytestring that contains the OCSP data to staple to the handshake.
                 If no OCSP data is available for this connection, return the empty bytestring.
        """

        content = bytes()

        if self._ocsp_stapling_file_path != None:
            ocsp_response_file = open(self._ocsp_stapling_file_path, "rb")
            content = ocsp_response_file.read()
            ocsp_response_file.close()

        return content

    def _choose_alpn_protocol(self, connection, offered_protocols_list):
        """
        Callback function that will be called when a client offers ALPN protocols.

        :param connection: Server's connection, socket.
        :param offered_protocols_list: List of offered protocols from client as bytestrings,
        :return: bytestrings from offered_protocols_list to indicate the chosen protocol,
                 the empty, "", bytestring to terminate the TLS connection,
                 or the NO_OVERLAPPING_PROTOCOLS to indicate that no offered protocol was selected,
                 but that the connection should not be aborted.
        """

        # According to RFC7301 -
        # Servers that receive a ClientHello containing the "application_layer_protocol_negotiation"
        # extension MAY return a suitable protocol selection response to the client.
        # In our case, if ALPN extension disabled by None in _alpn_protocol - dont response with ALPN extension.
        if self._alpn_protocol == None:
            return SSL.NO_OVERLAPPING_PROTOCOLS

        for protocol in offered_protocols_list:
            if protocol.decode() in self._alpn_protocol:
                return protocol

        # According to RFC7301 -
        # In the event that the server supports no protocols that the client advertises, then the server SHALL respond
        # with a fatal "no_application_protocol" alert.
        return "".encode()
