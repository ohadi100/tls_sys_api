import os
from CertificateBasedBaseTestCases import *

_ROOT_CA_CERTIFICATE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "root_ca.pem")
_VALID_CERT_CHAIN_SERVER_PRIVATE_KEY_PATH = os.path.join(MISC_KEYS_OCSP_KEYS_DIR_PATH, "valid_cert_chain_ee.key")
_VALID_CERT_CHAIN_SERVER_CERTIFICATE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "valid_cert_chain.pem")

class CertificateBasedBaseTestCasesHashPinning(CertificateBasedBaseTestCases):
    """
    Certificate based with hash pinning base test cases class.
    """

    def setUpServerWithCertChain(self, tls_protocol):
        """
        Setup the HTTPS server
        """
        tls_authentication_type = SignatureAlgorithmType.RSA

        root_ca = _ROOT_CA_CERTIFICATE_PATH
        client_cert = CLIENT_CERTS_BY_SIG_TYPE_DICT[tls_authentication_type]
        server_cert = _VALID_CERT_CHAIN_SERVER_CERTIFICATE_PATH
        server_private_key = _VALID_CERT_CHAIN_SERVER_PRIVATE_KEY_PATH
        client_private_key = CLIENT_PRIVATE_BY_SIG_TYPE_DICT[tls_authentication_type]

        self._server_hash_pinning = self._calculate_public_key_hash_pinning(server_cert)

        # Setup and run TLS server
        self._tls_server = TLSServer(self._server_ip, self._server_port, tls_protocol, server_cert, server_private_key)
        self._tls_server.run()

        # Create "VKMS" and prepare it with root CA and clients keys
        self._vkms = VKMS()
        self._vkms.load_root_ca(root_ca)
        self._vkms.load_client_cert(client_cert, client_private_key)

    def _calculate_public_key_hash_pinning(self, cert_path):

        """
        Create certificate public key hash pinning
        follows https://datatracker.ietf.org/doc/html/rfc7469

        :param cert_path: certificate path in PEM to create hash pinning from it

        :return: hash pinning in hex
        """

        # commend calculates base64(sha256(SubjectPublicKeyInfo)) value and convert it to hexadecimal
        command = "openssl x509 -in " + cert_path + " -pubkey -noout | openssl pkey -pubin -outform der" \
                                                    " | openssl dgst -sha256 -binary | openssl enc -base64" \
                                                    " | xxd -ps -c 200 | tr -d '\n'"

        hash_pinning = os.popen(command).read()

        nibble_size = 2
        return hash_pinning[:(len(hash_pinning)-nibble_size)] #remove unnecessary last byte


    def _config_server_and_do_tls_lib_handshake_with_hash_pinning(self, hash_pinning):
        """
        Config server's SSL context with parameters, calculate hash pinning parameter
        and call TLSLibApi for handshake

        :param hash_pinning: server's certificate public key hash pinning follows https://datatracker.ietf.org/doc/html/rfc7469

        :return: True if handshake succeeded otherwise False
        """

        self._tls_server.load_dh_params(self._dh_param_file)

        host_name = self._tls_server.get_name()

        result =  self._tls_client.create_tls_client(self._server_ip, self._server_port, host_name, DEFAULT_CERT_STORE_ID,
                                                     DEFAULT_CLIENT_CERT_STORE_ID, client_cipher_suites_use_case = CipherSuitesUseCaseType.CSUSLegacy ,
                                                     hash_pinnings = hash_pinning) and \
                  self._tls_client.connect() and \
                  self._tls_client.shutdown()

        return result

class HashPinningTests(CertificateBasedBaseTestCasesHashPinning):
    """TLS Certificate based test cases"""
    def _run_tests_valid_hash(self, tls_protocol_type):
        """
        Setup the Server environment, call the client to make handshake
        with server's public key certificate hash pinning and check
        the connection established successfully

        :param tls_protocol_type: TLS protocol version

        :return: True if test was successfully passed otherwise, False.
        """

        # Setup HTTPS server with specific TLS protocol
        super().setUpServerWithCertChain(tls_protocol_type)

        expected = True
        actual = self._config_server_and_do_tls_lib_handshake_with_hash_pinning(self._server_hash_pinning)

        self.assertEqual(expected,actual,
                        "\n handshake has failed not as expected,\n tls_protocol_type: {a}\n". \
                        format(a=tls_protocol_type.name))

        # Shutdown the server for the next iteration
        super().shutDownServer()

    def _run_tests_invalid_hash(self, tls_protocol_type):
        """
        Setup the Server environment, call the client to make handshake
        with server's public key certificate hash pinning and check
        the connection established successfully

        :param tls_protocol_type: TLS protocol version

        :return: True if test was successfully passed otherwise, False.
        """

        # Setup HTTPS server with specific TLS protocol
        super().setUpServerWithCertChain(tls_protocol_type)
        dummy_hash_pinning = "5a6f7062634b55bb3352724ebb2b55304b59797a755a68734671526c58695435564f66425a7033624f486f3d"

        expected = False
        actual = self._config_server_and_do_tls_lib_handshake_with_hash_pinning(dummy_hash_pinning)

        self.assertEqual(expected,actual,
                         "\n handshake has failed not as expected,\n tls_protocol_type: {a}\n". \
                         format(a=tls_protocol_type.name))

        # Shutdown the server for the next iteration
        super().shutDownServer()

    def test_hash_pinning_valid_hash(self):

        """TLS version 1.2 hash pinning test"""

        self._run_tests_valid_hash(TLSProtocolVersionType.TLS_1_2)
        self._run_tests_valid_hash(TLSProtocolVersionType.TLS_1_3)

    def test_hash_pinning_wrong_hash(self):

        """TLS version 1.3 hash pinning test"""

        self._run_tests_invalid_hash(TLSProtocolVersionType.TLS_1_2)
        self._run_tests_invalid_hash(TLSProtocolVersionType.TLS_1_3)