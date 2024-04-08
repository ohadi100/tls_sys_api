import unittest
from globals import *
from utils.vkms import *
from utils.tls_api import *
from servers.tls_server import *

_SERVER_IP = "127.0.0.1"
_SERVER_PORT = 5000
_DH_PARAM_FILE = "dhparams.pem"

class CertificateBasedBaseTestCases(unittest.TestCase):
    """
    Certificate based base test cases class.
    Implements common setup and teardown methods for test fixtures.
    """

    def setUp(self):
        """
        Setup the test environment for basic Backend certificate based test cases
        """

        # Declare the server member here to be able to shutdown the server in test's teardown method.
        self._tls_server = None

        self._server_ip = _SERVER_IP
        self._server_port = _SERVER_PORT
        self._dh_param_file = _DH_PARAM_FILE

        # Initialize TLS lib API
        self.assertTrue(TLSApi.init_tls_lib(), "Failed to initialize TLS Lib API")

        self._tls_client = TLSApi()

    def setUpServer(self, tls_protocol, tls_authentication_type):
        """
        Setup the HTTPS server
        """
        root_ca = SERVER_ROOT_CA_BY_SIG_TYPE_DICT[tls_authentication_type]
        client_cert = CLIENT_CERTS_BY_SIG_TYPE_DICT[tls_authentication_type]
        server_cert = SERVER_CERTS_BY_SIG_TYPE_DICT[tls_authentication_type]
        server_private_key = SERVER_PRIVATE_BY_SIG_TYPE_DICT[tls_authentication_type]
        client_private_key = CLIENT_PRIVATE_BY_SIG_TYPE_DICT[tls_authentication_type]
        server_ocsp_status = SERVER_OCSP_STAPLING_BY_SIG_TYPE_DICT[tls_authentication_type]

        # Setup and run TLS server
        self._tls_server = TLSServer(self._server_ip, self._server_port, tls_protocol, server_cert, server_private_key)
        self._tls_server.set_ocsp_stapling(server_ocsp_status)
        self._tls_server.run()

        # Create "VKMS" and prepare it with root CA and clients keys
        self._vkms = VKMS()
        self._vkms.load_root_ca(root_ca)
        self._vkms.load_client_cert(client_cert, client_private_key)

    def shutDownServer(self):
        if self._tls_server != None:
            self._tls_server.shutdown()

    def tearDown(self):
        """
        Clean the test environment
        """

        self._tls_client.free()
        self.shutDownServer()
        self.assertTrue(TLSApi.cleanup_tls_lib(), "Failed to cleanup TLSApi")

    def _config_server_and_do_tls_lib_handshake(self, host_name, cipher, client_cipher_suites_use_case):
        """
        Config server's SSL context with parameters and call TLSLibApi for handshake

        :param host_name: Host's name according to the parameter in the certificate
        :param cipher: Which cipher suite to config the server
        :param client_cipher_suites_use_case: Cipher suites use case for configuration TLS client cipher suites

        :return: True if handshake succeeded otherwise False
        """

        self._tls_server.set_ciphers_list(cipher.value)
        self._tls_server.load_dh_params(self._dh_param_file)

        host_name = self._tls_server.get_name()

        result =  self._tls_client.create_tls_client(self._server_ip, self._server_port, host_name, DEFAULT_CERT_STORE_ID,
                                                     DEFAULT_CLIENT_CERT_STORE_ID, client_cipher_suites_use_case=client_cipher_suites_use_case) and \
                  self._tls_client.connect() and \
                  self._tls_client.shutdown()

        return result