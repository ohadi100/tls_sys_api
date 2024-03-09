from CertificateBasedBaseTestCases import *
import itertools

class CipherSuitesUseCaseTests(CertificateBasedBaseTestCases):
    """TLS Certificate based test cases"""

    def _expected_result(self, tls_protocol_type, tls_auth_type, test_cipher_suite, \
                         valid_cipher_suites):
        """
        Calculate the expected result according to the parameters.

        :param tls_protocol_type: TLS protocol version
        :param tls_auth_type: Server's PK authentication type
        :param test_cipher_suite: Which cipher suite server configured
        :param valid_cipher_suites: List of valid cipher suites according to the test fixture

        :return: the expected result - True or False.
        """

        if tls_protocol_type is TLSProtocolVersionType.TLS_1_1:
            return False

        if (len(valid_cipher_suites) == 0) or (test_cipher_suite not in valid_cipher_suites):
            return False

        if tls_protocol_type is TLSProtocolVersionType.TLS_1_2:
            if tls_auth_type.name not in test_cipher_suite.name:
                return False

        return True

    def _run_tests(self, tls_protocol_type, client_cipher_suites_use_case, test_cipher_suites, valid_cipher_suites):
        """
        Setup the Server environment, call the client to make handshake, calculate the expected result
        and compare it to the actual result from the client.

        For each parameters in the cartesian of TLS version X [Authentication types       X
                                                               Cipher suites],
        :param tls_protocol_type: TLS protocol version
        :param client_cipher_suites_use_case: Cipher suites use case for configuration TLS client cipher suites
        :param test_cipher_suites: List of valid cipher suites to configure server
        :param valid_cipher_suites: List of valid cipher suites according to the test fixture.

        :return: True if tests were successfully passed otherwise, False.
        """

        test_auth_types = [*SignatureAlgorithmType]

        for suite in itertools.product(test_auth_types, test_cipher_suites):

            # In TLS 1.2 if cipher suite name does not contain auth type (ecdsa or rsa),
            #then the connection should be failed anyway, so this test case is unnecessary
            if tls_protocol_type is TLSProtocolVersionType.TLS_1_2:
                if suite[0].name not in suite[1].name:
                    continue

            # Setup HTTPS server with specific HTTPS server and auth type
            super().setUpServer(tls_protocol_type, suite[0])
            actual_res = self._config_server_and_do_tls_lib_handshake(suite[0], suite[1], client_cipher_suites_use_case)
            expected_res = self._expected_result(tls_protocol_type, suite[0], suite[1], valid_cipher_suites)

            self.assertEqual(actual_res, expected_res,
                             "\n handshake result: {a},\n auth type: {b},\n tls_protocol: {c},\n cipher_suite: {d},\n "
                             "client_cipher_suites_use_case: {e}\n". \
                             format(a=actual_res, b=suite[0].name, c=tls_protocol_type, d=suite[1].name, \
                                    e=client_cipher_suites_use_case.name))

            # Shutdown the server for the next iteration
            super().shutDownServer()

    def test_tlsv1_1(self):
        """TLS version 1.1 test, when the client's cipher suite is CSUSDefault use case in TLS cert engine.
        The connection should be failed because TLS cert engine does not support TLS 1.1"""

        TEST_CIPHER_SUITES = [*TLS11CipherSuitesType]

        VALID_CIPHER_SUITES = [] #empty list because TLS cert engine does not support TLS 1.1

        self._run_tests(TLSProtocolVersionType.TLS_1_1, \
                        CipherSuitesUseCaseType.CSUSDefault, \
                        TEST_CIPHER_SUITES, VALID_CIPHER_SUITES)

    def test_tlsv1_2_cipher_suites_use_cases(self):
        """TLS version 1.2 cipher suites use cases test"""

        #tests all use cases cipher suites that TLS cert engine supports in TLS1.2
        TEST_CIPHER_SUITES = [*TLS12CipherSuiteType]

        #run every time with another cipher suites use case list
        for use_case in CipherSuitesUseCaseType:
            VALID_CIPHER_SUITES = TLS12CIPHER_SUITES_LIST_BY_USE_CASE_DICT[use_case]
            self._run_tests(TLSProtocolVersionType.TLS_1_2, use_case, \
                            TEST_CIPHER_SUITES, VALID_CIPHER_SUITES)

    @unittest.skipIf("botan" in TLS_LIB_PATH, "Skip test - Botan TLS cert engine doesn't support tls v1.3")
    def test_tlsv1_3_cipher_suites_use_cases(self):
        """TLS version 1.3 cipher suites use cases test"""

        #tests all use cases cipher suites that TLS cert engine supports in TLS1.3
        TEST_CIPHER_SUITES = [*TLS13CipherSuiteType]

        #run every time with another cipher suites use case list
        for use_case in CipherSuitesUseCaseType:
            VALID_CIPHER_SUITES = TLS13CIPHER_SUITES_LIST_BY_USE_CASE_DICT[use_case]
            self._run_tests(TLSProtocolVersionType.TLS_1_3, use_case, \
                            TEST_CIPHER_SUITES, VALID_CIPHER_SUITES)
