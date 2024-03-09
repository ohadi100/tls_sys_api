import itertools
from CertificateBasedBaseTestCases import *

class CertificateBasedWithAlpnBaseTestCases(CertificateBasedBaseTestCases):
    """
    Certificate based with ALPN base test cases class.
    """

    def _config_server_and_do_tls_lib_handshake_with_alpn(self, cipher, ec_curve, client_alpn_protocol, server_alpn_protocols):
        """
        Config server's SSL context with parameters and call TLSLibApi for handshake

        :param cipher: Which cipher suite to config the server
        :param ec_curve: Which EC point to config the server
        :param client_alpn_protocol: Client's ALPN protocol
        :param server_alpn_protocols: Server's supported ALPN protocols

        :return: True if handshake succeeded otherwise False
        """

        self._tls_server.set_ciphers_list(cipher.value)
        self._tls_server.load_dh_params(self._dh_param_file)
        self._tls_server.set_ecdh_curve(ec_curve)
        self._tls_server.set_alpn_protocol(server_alpn_protocols)

        host_name = self._tls_server.get_name()

        result = self._tls_client.create_tls_client(self._server_ip, self._server_port, host_name, DEFAULT_CERT_STORE_ID,
                                                    DEFAULT_CLIENT_CERT_STORE_ID, alpn_protocol=client_alpn_protocol.value) and \
                 self._tls_client.connect() and \
                 self._tls_client.shutdown()

        return result

class CartesianTests(CertificateBasedWithAlpnBaseTestCases):
    """TLS Certificate based test cases"""

    def _expected_result(self, tls_protocol_type, tls_auth_type, test_cipher_suite, test_ec_point, test_client_alpn, \
                         test_server_alpns, valid_cipher_suites, invalid_ec_points):
        """
        Calculate the expected result according to the parameters.

        :param tls_protocol_type: TLS protocol version
        :param tls_auth_type: Server's PK authentication type
        :param test_cipher_suite: Which cipher suite server & client configured
        :param test_ec_point: Which EC point type server & client configured
        :param test_client_alpn: Client's ALPN protocol type
        :param test_server_alpns: Server's ALPN protocols list
        :param valid_cipher_suites: List of valid cipher suites according to the test fixture
        :param invalid_ec_points: List of invalid EC points according to the test fixture

        :return: the expected result - True or False.
        """

        if tls_protocol_type is TLSProtocolVersionType.TLS_1_1:
            return False

        if (len(valid_cipher_suites) == 0) or (test_cipher_suite not in valid_cipher_suites):
            return False

        if tls_protocol_type is TLSProtocolVersionType.TLS_1_2:
            if tls_auth_type.name not in test_cipher_suite.name:
                return False

        if test_ec_point in invalid_ec_points:
            if tls_protocol_type is TLSProtocolVersionType.TLS_1_2:
                if "EC" in test_cipher_suite.name:
                    return False
            else:
                return False

        if test_client_alpn != self._tls_client.get_negotiated_protocol():
            return False

        return True

    def _run_cartesian_tests(self, tls_protocol_type, test_cipher_suites, test_ec_points, test_client_alpn,
                             valid_cipher_suites, invalid_ec_points, invalid_alpn):
        """
        Setup the HTTPS environment, call the client to make handshake, calculate the expected result
        and compare it to the actual result from the client.

        For each parameters in the cartesian of TLS version X [Authentication types       X
                                                               EC curves                  X
                                                               ALPN protocols for client  X
                                                               ALPN protocols for server  X
                                                               Cipher suites],
        :param tls_protocol_type: TLS protocol version
        :param test_cipher_suites: List of valid cipher suites to configure server
        :param test_ec_points: List of valid EC points to configure server and client
        :param test_client_alpn: List of valid ALPN protocols to the client
        :param valid_cipher_suites: List of valid cipher suites according to the test fixture.
        :param invalid_ec_points: List of invalid EC points according to the test fixture.
        :param invalid_alpn: List of invalid ALPN protocols according to the test fixture.

        :return: True if cartesian tests were successfully passed otherwise, False.
        """

        test_auth_types = [*SignatureAlgorithmType]
        server_supported_alpns = [item for item in [*ALPNProtocolType] if item not in invalid_alpn]

        for suite in itertools.product(test_auth_types, test_cipher_suites, test_ec_points, test_client_alpn):

            # In TLS 1.2 if cipher suite name does not contain auth type (ecdsa or rsa),
            #then the connection should be failed anyway, so this test case is unnecessary
            if tls_protocol_type is TLSProtocolVersionType.TLS_1_2:
                if suite[0].name not in suite[1].name:
                    continue

            # Setup HTTPS server with specific HTTPS server and auth type
            super().setUpServer(tls_protocol_type, suite[0])

            actual_res = self._config_server_and_do_tls_lib_handshake_with_alpn(suite[1], suite[2], suite[3], server_supported_alpns)
            expected_res = self._expected_result(tls_protocol_type, suite[0], suite[1], suite[2], suite[3], server_supported_alpns, \
                                                 valid_cipher_suites, invalid_ec_points)

            self.assertEqual(actual_res, expected_res,
                             "\n actual result: {a},\n expected result: {b},\n host name: {c},\n tls protocol: {d}," \
                             "\n cipher suite: {e},\n ec point: {f},\n client ALPN: {g},\n server ALPN list: {h},\n ". \
                             format(a=actual_res, b=expected_res, c=self._tls_server.get_name(), d=tls_protocol_type, \
                                    e=suite[1], f=suite[2], g=suite[3], h=server_supported_alpns))

            # Shutdown the server for the next iteration
            super().shutDownServer()

    def test_tlsv1_2_cartesian_parameters(self):
        """TLS version 1.2 cartesian parameters test, when the client's cipher suite is CSUSDefault use case in TLS cert engine"""

        #tests cipher suites in TLS  1.2 that TLS cert engine supports in CSUSDefault use case +
        #some of cipher suites in TLS 1.2 that TLS cert engine does not support in CSUSDefault use case.
        TEST_CIPHER_SUITES = TLS12defaultCipherSuites + TLS12notDefaultCipherSuites
        TEST_EC_POINTS = [*ECPointType]
        TEST_ALPN = [*ALPNProtocolType]

        VALID_CIPHER_SUITES = TLS12defaultCipherSuites
        INVALID_EC_POINTS = [ECPointType.SECT163K1]
        INVALID_TEST_ALPN = [ALPNProtocolType.SPDY1]

        self._run_cartesian_tests(TLSProtocolVersionType.TLS_1_2, \
                                  TEST_CIPHER_SUITES, TEST_EC_POINTS, TEST_ALPN, \
                                  VALID_CIPHER_SUITES, INVALID_EC_POINTS, INVALID_TEST_ALPN)

    @unittest.skipIf("botan" in TLS_LIB_PATH, "Skip test - Botan TLS cert engine doesn't support tls v1.3")
    def test_tlsv1_3_cartesian_parameters(self):
        """TLS version 1.3 cartesian parameters test, when the client's cipher suite is CSUSDefault use case in TLS cert engine"""

        TEST_CIPHER_SUITES = [*TLS13CipherSuiteType]#tests all use cases cipher suites that TLS cert engine supports in TLS1.3
        TEST_EC_POINTS = [*ECPointType]
        TEST_ALPN = [*ALPNProtocolType]

        VALID_CIPHER_SUITES = TLS13defaultCipherSuites
        INVALID_EC_POINTS = [ECPointType.SECT163K1]
        INVALID_TEST_ALPN = [ALPNProtocolType.SPDY1]

        self._run_cartesian_tests(TLSProtocolVersionType.TLS_1_3, \
                                  TEST_CIPHER_SUITES, TEST_EC_POINTS, TEST_ALPN, \
                                  VALID_CIPHER_SUITES, INVALID_EC_POINTS, INVALID_TEST_ALPN)
