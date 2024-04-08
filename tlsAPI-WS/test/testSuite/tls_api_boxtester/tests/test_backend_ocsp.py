import os
import unittest
from globals import *
from utils.vkms import *
from utils.tls_api import *
from servers.tls_server import *
from servers.ocsp_responder import *

_SERVER_IP = "127.0.0.1"
_SERVER_PORT = 5000
_OCSP_RESPONDER_PORT = 8888

_OCSP_DB_FILE_PATH = os.path.join(MISC_KEYS_OCSP_DIR_PATH, "db.txt")
_OCSP_CERTIFICATE_FILE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "ocsp.pem")
_OCSP_PRIVATE_KEY_FILE_PATH = os.path.join(MISC_KEYS_OCSP_KEYS_DIR_PATH, "ocsp.key")
_OCSP_CA_CERTIFICATES_FILE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "ocsp_ca_certificates.pem")

_ROOT_CA_CERTIFICATE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "root_ca.pem")
_VALID_CLIENT_PRIVATE_KEY_PATH = os.path.join(MISC_KEYS_OCSP_KEYS_DIR_PATH, "client.key")
_VALID_CLIENT_CERTIFICATE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "client.pem")
_VALID_SERVER_PRIVATE_KEY_PATH = os.path.join(MISC_KEYS_OCSP_KEYS_DIR_PATH, "valid_server.key")
_VALID_SERVER_CERTIFICATE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "valid_server.pem")
_VALID_SERVER_OCSP_STAPLING_PATH = os.path.join(MISC_KEYS_OCSP_RESPONSES_DIR_PATH, "valid_server.der")
_REVOKED_SERVER_PRIVATE_KEY_PATH = os.path.join(MISC_KEYS_OCSP_KEYS_DIR_PATH, "revoked_server.key")
_REVOKED_SERVER_CERTIFICATE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "revoked_server.pem")
_REVOKED_SERVER_OCSP_STAPLING_PATH = os.path.join(MISC_KEYS_OCSP_RESPONSES_DIR_PATH, "revoked_server.der")
_NO_AUTHINFO_SERVER_CERTIFICATE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "no_authInfo_server.pem")
_NO_AUTHINFO_SERVER_PRIVATE_KEY_PATH = os.path.join(MISC_KEYS_OCSP_KEYS_DIR_PATH, "no_authInfo_server.key")
_NO_AUTHINFO_ROOT_CA_CERTIFICATE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "root_ca.pem")
_AUTHINFO_ROOT_CA_CERTIFICATE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "root_ca_withAuthInfo.pem")
_ROOT_CA_PRIVATE_KEY_PATH = os.path.join(MISC_KEYS_OCSP_KEYS_DIR_PATH, "root_ca.key")
_VALID_CERT_CHAIN_SERVER_PRIVATE_KEY_PATH = os.path.join(MISC_KEYS_OCSP_KEYS_DIR_PATH, "valid_cert_chain_ee.key")
_VALID_CERT_CHAIN_SERVER_CERTIFICATE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "valid_cert_chain.pem")
_VALID_CERT_CHAIN_SERVER_OCSP_STAPLING_PATH = os.path.join(MISC_KEYS_OCSP_RESPONSES_DIR_PATH, "valid_cert_chain.der")
_EXPIRED_CERTIFICATE_PATH = os.path.join(MISC_KEYS_OCSP_CERTS_DIR_PATH, "expired_server.pem")
_EXPIRED_CERTIFICATE_PRIVATE_KEY_PATH = os.path.join(MISC_KEYS_OCSP_KEYS_DIR_PATH, "expired_server.key")


class OCSPBackendTests(unittest.TestCase):
    """
    This class tests the OCSP handling in the TLSLibApi client with dummy TLS server as backend.
    """

    def setUp(self):
        """
        Setup the test environment
        """

        # Setup TLS server with valid certificate
        self._valid_tls_server = TLSServer(_SERVER_IP, _SERVER_PORT, TLSProtocolVersionType.TLS_1_2,
                                           _VALID_SERVER_CERTIFICATE_PATH, _VALID_SERVER_PRIVATE_KEY_PATH)

        # Setup TLS server with revoked certificate
        self._revoked_tls_server = TLSServer(_SERVER_IP, _SERVER_PORT, TLSProtocolVersionType.TLS_1_2,
                                             _REVOKED_SERVER_CERTIFICATE_PATH, _REVOKED_SERVER_PRIVATE_KEY_PATH)

        # Setup TLS server without authorityInfoAccess x509 extension certificate
        self._no_authInfo_tls_server = TLSServer(_SERVER_IP, _SERVER_PORT, TLSProtocolVersionType.TLS_1_2,
                                                 _NO_AUTHINFO_SERVER_CERTIFICATE_PATH, _NO_AUTHINFO_SERVER_PRIVATE_KEY_PATH)

        self._valid_cert_chain_tls_server = TLSServer(_SERVER_IP, _SERVER_PORT, TLSProtocolVersionType.TLS_1_2,
                                                _VALID_CERT_CHAIN_SERVER_CERTIFICATE_PATH, _VALID_CERT_CHAIN_SERVER_PRIVATE_KEY_PATH)
        
        self._valid_cert_chain_tls_rootCA_no_authinfo = TLSServer(_SERVER_IP, _SERVER_PORT, TLSProtocolVersionType.TLS_1_2,
                                                            _NO_AUTHINFO_ROOT_CA_CERTIFICATE_PATH, _ROOT_CA_PRIVATE_KEY_PATH)
        
        self._valid_cert_chain_tls_rootCA_authinfo = TLSServer(_SERVER_IP, _SERVER_PORT, TLSProtocolVersionType.TLS_1_2,
                                                               _AUTHINFO_ROOT_CA_CERTIFICATE_PATH, _ROOT_CA_PRIVATE_KEY_PATH)
        
        self._expired_cert_tls_server = TLSServer(_SERVER_IP, _SERVER_PORT, TLSProtocolVersionType.TLS_1_2,
                                                _EXPIRED_CERTIFICATE_PATH, _EXPIRED_CERTIFICATE_PRIVATE_KEY_PATH)
        
        # Create and start OCSP responder server
        self._ocsp_responder = OCSPResponder(_OCSP_RESPONDER_PORT, _OCSP_DB_FILE_PATH, _OCSP_CERTIFICATE_FILE_PATH, \
                                             _OCSP_PRIVATE_KEY_FILE_PATH, _OCSP_CA_CERTIFICATES_FILE_PATH)
        self._ocsp_responder.start()

        # Initialize TLS lib API
        self.assertTrue(TLSApi.init_tls_lib(), "Failed to initialize TLS Lib API")

        # Create "VKMS" and prepare it with root CA and clients keys
        self._vkms = VKMS()
        self._vkms.load_root_ca(_ROOT_CA_CERTIFICATE_PATH)
        self._vkms.load_client_cert(_VALID_CLIENT_CERTIFICATE_PATH, _VALID_CLIENT_PRIVATE_KEY_PATH)

    def tearDown(self):
        """
        Clean the test environment
        """

        self._valid_tls_server.shutdown()
        self._revoked_tls_server.shutdown()
        self._no_authInfo_tls_server.shutdown()
        self._valid_cert_chain_tls_server.shutdown()
        self._valid_cert_chain_tls_rootCA_no_authinfo.shutdown()
        self._valid_cert_chain_tls_rootCA_authinfo.shutdown()
        self._expired_cert_tls_server.shutdown()

        self._ocsp_responder.stop()
        self.assertTrue(TLSApi.cleanup_tls_lib(), "Failed to cleanup TLSApi")
        TLSApi.clear_ocsp_cache()

    def _setup_client_session_and_close(self, host_name, use_hard_fail_fallback_mechanism=True):
        """
        Setup client socket and session with the TLS server and close it immediately.

        :param host_name: TLS's server CN according to the certificate.
        :param use_hard_fail_fallback_mechanism: Flag that indicates the usage of hard fail fallback mechanism.

        :return: True if successfully done otherwise False
        """

        tls_client = TLSApi()

        cipher_suite_use_case = CipherSuitesUseCaseType.CSUSDefault if use_hard_fail_fallback_mechanism \
            else CipherSuitesUseCaseType.CSUSLegacy

        # TOOD: the shutdown method doesnt work. need to debug the TLSLibAPI and see why.
        #       to make it possible to shutdown the socket we free the object in the end.
        result = tls_client.create_tls_client(_SERVER_IP, _SERVER_PORT, host_name, DEFAULT_CERT_STORE_ID, \
                                              DEFAULT_CLIENT_CERT_STORE_ID, client_cipher_suites_use_case=cipher_suite_use_case) and \
                 tls_client.connect() and \
                 tls_client.shutdown()

        tls_client.free()

        return result

    def test_soft_fail_fallback_mechanism_with_valid_server_certificate(self):
        """Test Soft-Fail OCSP Fallback mechanism with valid server certificate"""

        # Run valid TLS Server
        self._valid_tls_server.run()

        #------------------------PHASE 1------------------------

        # Enable server's OCSP stapling
        self._valid_tls_server.set_ocsp_stapling(_VALID_SERVER_OCSP_STAPLING_PATH)

        # Create TLS client, connect to server and shutdown
        self.assertTrue(self._setup_client_session_and_close(self._valid_tls_server.get_name(), \
                                                             use_hard_fail_fallback_mechanism=False))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

        #------------------------PHASE 2------------------------

        # Disable server's OCSP stapling
        self._valid_tls_server.set_ocsp_stapling(None)

        # Create TLS client, connect to server and shutdown
        self.assertTrue(self._setup_client_session_and_close(self._valid_tls_server.get_name(), \
                                                             use_hard_fail_fallback_mechanism=False))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

    def test_soft_fail_fallback_mechanism_with_revoked_server_certificate(self):
        """Test Soft-Fail OCSP Fallback mechanism with revoked server certificate"""

        # Run revoked TLS Server
        self._revoked_tls_server.run()

        #------------------------PHASE 1------------------------

        # Enable server's OCSP stapling
        self._revoked_tls_server.set_ocsp_stapling(_REVOKED_SERVER_OCSP_STAPLING_PATH)

        # Create TLS client, connect to server and shutdown
        self.assertFalse(self._setup_client_session_and_close(self._revoked_tls_server.get_name(), \
                                                              use_hard_fail_fallback_mechanism=False))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

        #------------------------PHASE 2------------------------

        # Disable server's OCSP stapling
        self._revoked_tls_server.set_ocsp_stapling(None)

        # Create TLS client, connect to server and shutdown
        # In Legacy mode, only OCSP stapling is enabled. The client session will not connect to the OCSP responder service.
        self.assertTrue(self._setup_client_session_and_close(self._revoked_tls_server.get_name(), \
                                                             use_hard_fail_fallback_mechanism=False))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

    def test_hard_fail_fallback_mechanism_with_valid_server_certificate(self):
        """Test Hard-Fail OCSP Fallback mechanism with valid server certificate"""

        # Run valid TLS Server
        self._valid_tls_server.run()

        #------------------------PHASE 1------------------------

        # Enable server's OCSP stapling
        self._valid_tls_server.set_ocsp_stapling(_VALID_SERVER_OCSP_STAPLING_PATH)

        # Create TLS client, connect to server and shutdown
        self.assertTrue(self._setup_client_session_and_close(self._valid_tls_server.get_name()))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

        #------------------------PHASE 2------------------------

        # Disable server's OCSP stapling
        self._valid_tls_server.set_ocsp_stapling(None)

        # Create TLS client, connect to server and shutdown
        self.assertTrue(self._setup_client_session_and_close(self._valid_tls_server.get_name()))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 1)

    def test_hard_fail_fallback_mechanism_with_revoked_server_certificate(self):
        """Test Hard-Fail OCSP Fallback mechanism with revoked server certificate"""

        # Run revoked TLS Server
        self._revoked_tls_server.run()

        #------------------------PHASE 1------------------------

        # Enable server's OCSP stapling
        self._revoked_tls_server.set_ocsp_stapling(_REVOKED_SERVER_OCSP_STAPLING_PATH)

        # Create TLS client, connect to server and shutdown
        # If the revoke status is already stapled, no need to communicate with the OCSP server.
        self.assertFalse(self._setup_client_session_and_close(self._revoked_tls_server.get_name()))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

        #------------------------PHASE 2------------------------

        # Disable server's OCSP stapling
        self._revoked_tls_server.set_ocsp_stapling(None)

        # Create TLS client, connect to server and shutdown
        # The revoked status will be received from the OCSP server (using OpenSSL ocsp command) when the client session will comunicate with the OCSP server.
        self.assertFalse(self._setup_client_session_and_close(self._revoked_tls_server.get_name()))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

    def test_hard_fail_fallback_mechanism_with_valid_server_certificate_response_from_cache(self):
        """Test Hard-Fail OCSP Fallback mechanism with valid server certificate"""

        # Run valid TLS Server
        self._valid_tls_server.run()

        # Disable server's OCSP stapling
        self._valid_tls_server.set_ocsp_stapling(None)

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0, "Cache size should be 0 at the beginning")
        self.assertEqual(TLSApi.get_number_of_reads_from_ocsp_cache(), 0, "number of reads from cache should b 0 at the beginning")

        #------------------------PHASE 1------------------------

        # Create TLS client, connect to server and shutdown
        self.assertTrue(self._setup_client_session_and_close(self._valid_tls_server.get_name()))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 1, "response should have been added to cache")
        self.assertEqual(TLSApi.get_number_of_reads_from_ocsp_cache(), 0, "first connection should have request response from server")

        #------------------------PHASE 2------------------------
        # The cache has the OCSP resopnse stored from PHASE 1.
        # Create TLS client, connect to server and shutdown
        self.assertTrue(self._setup_client_session_and_close(self._valid_tls_server.get_name()))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 1, "OCSP cache should only have one entry")
        self.assertEqual(TLSApi.get_number_of_reads_from_ocsp_cache(), 1, "second connection should've read the response from cache")

        #------------------------PHASE 3------------------------  
        # set next OCSP response from cache to be invalid - triggering removal from cache
        TLSApi.set_next_ocsp_response_to_be_invalid()

        self.assertFalse(self._setup_client_session_and_close(self._valid_tls_server.get_name()))
        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0, "OCSP cache entry should have been erased")
        self.assertEqual(TLSApi.get_number_of_reads_from_ocsp_cache(), 2, "third connection also found in cache")

    def test_no_authinfo_certificate_server(self):
        """Test certificate server (no authInfo v3 extension)"""

        # Run TLS Server without authInfo extension in certificate
        self._no_authInfo_tls_server.run()

        # Create TLS client with hard-fail mechanism.
        # It should fail in the postVerification because the leaf does not have auth info extension.
        self.assertFalse(self._setup_client_session_and_close(self._no_authInfo_tls_server.get_name()))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

        # Create TLS client with soft-fail mechanism.
        self.assertTrue(self._setup_client_session_and_close(self._no_authInfo_tls_server.get_name(),
                                                             use_hard_fail_fallback_mechanism=False))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

    def test_no_authinfo_withRootCA_server(self):
        """Test certificate server (no authInfo v3 extension)"""

        # Run TLS Server without authInfo extension in root CA certificate
        self._valid_cert_chain_tls_rootCA_no_authinfo.run()

        # Create TLS client with hard-fail mechanism.
        self.assertTrue(self._setup_client_session_and_close(self._valid_cert_chain_tls_rootCA_no_authinfo.get_name()))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

        # Create TLS client with soft-fail mechanism.
        self.assertTrue(self._setup_client_session_and_close(self._valid_cert_chain_tls_rootCA_no_authinfo.get_name(),
                                                             use_hard_fail_fallback_mechanism=False))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

    def test_authinfo_withRootCA_server(self):
        """Test certificate server (authInfo v3 extension)"""

        # Run TLS Server with authInfo extension in root CA certificate
        self._valid_cert_chain_tls_rootCA_authinfo.run()

        # Create TLS client with hard-fail mechanism.
        # The auth info extension check is skipped, but this extention should not be part of the rootCA, so the verification fails.
        self.assertFalse(self._setup_client_session_and_close(self._valid_cert_chain_tls_rootCA_authinfo.get_name()))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

        # Create TLS client with soft-fail mechanism.
        self.assertTrue(self._setup_client_session_and_close(self._valid_cert_chain_tls_rootCA_authinfo.get_name(),
                                                             use_hard_fail_fallback_mechanism=False))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

    def test_hard_fail_fallback_mechanism_with_valid_server_certificate_chain(self):
        """Test OCSP mechanism with a valid certificate chain including End-Entity and intermediate CA"""

        # Run valid TLS server with certificate chain (ee, intermediate CA)
        self._valid_cert_chain_tls_server.run()

        # Disable server's OCSP stapling
        self._valid_cert_chain_tls_server.set_ocsp_stapling(None)

        # Create TLS client with hard-fail mechanism
        self.assertTrue(self._setup_client_session_and_close(self._valid_cert_chain_tls_server.get_name()))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 2, "responses for both certificates in chain") 
        self.assertEqual(TLSApi.get_number_of_reads_from_ocsp_cache(), 0)

        # Enable server's OCSP stapling
        self._valid_cert_chain_tls_server.set_ocsp_stapling(_VALID_CERT_CHAIN_SERVER_OCSP_STAPLING_PATH)

        # Create TLS client with hard-fail mechanism.
        self.assertTrue(self._setup_client_session_and_close(self._valid_cert_chain_tls_server.get_name()))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 2)
        self.assertEqual(TLSApi.get_number_of_reads_from_ocsp_cache(), 1, "response for second cert in chain will should be taken from cache")

    def test_soft_fail_fallback_mechanism_with_valid_server_certificate_chain(self):
        """Test OCSP mechanism with a valid certificate chain including End-Entity and intermediate CA"""

        # Run valid TLS server with certificate chain (ee, intermediate CA)
        self._valid_cert_chain_tls_server.run()

        # Disable server's OCSP stapling
        self._valid_cert_chain_tls_server.set_ocsp_stapling(None)

        # Create TLS client with soft-fail mechanism
        self.assertTrue(self._setup_client_session_and_close(self._valid_cert_chain_tls_server.get_name(),
                                                             use_hard_fail_fallback_mechanism=False))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

        # Enable server's OCSP stapling
        self._valid_cert_chain_tls_server.set_ocsp_stapling(_VALID_CERT_CHAIN_SERVER_OCSP_STAPLING_PATH)

        # Create TLS client with soft-fail mechanism.
        self.assertTrue(self._setup_client_session_and_close(self._valid_cert_chain_tls_server.get_name(),
                                                             use_hard_fail_fallback_mechanism=False))

        self.assertEqual(TLSApi.get_ocsp_cache_size(), 0)

    def test_ocsp_stapling_and_certificate_mismatch(self):
        """Test mismatch between OCSP stapling and server's certificate in ServerHello"""

        # Run revoked TLS Server
        self._revoked_tls_server.run()

        # Enable server's OCSP stapling with valid status
        self._revoked_tls_server.set_ocsp_stapling(_VALID_SERVER_OCSP_STAPLING_PATH)

        # Create TLS client with hard-fail mechanism.
        self.assertFalse(self._setup_client_session_and_close(self._revoked_tls_server.get_name()))

        # Create TLS client with soft-fail mechanism.
        self.assertFalse(self._setup_client_session_and_close(self._revoked_tls_server.get_name(),
                                                              use_hard_fail_fallback_mechanism=False))
    
    def test_with_expired_server_certificate(self):
        """Test OCSP soft-fail/hard-fail mechanism with an expired certificate"""
        # In this test we provide an expired certificate to the server.
        # We expect the TLS client to abort the TLS connection regardless of the OCSP mode (hard fail or soft fail).
        # In this test we don't really care about the OCSP resopnse from the OCSP server. We only want to check that
        # the client will terminate the TLS connection when the certificate is expired in any mode (soft-fail and hard-fail).

        # Run TLS Server with expired certificate
        self._expired_cert_tls_server.run()

        #------------------------HARD FAIL------------------------

        self.assertFalse(self._setup_client_session_and_close(self._expired_cert_tls_server.get_name()))

        #------------------------SOFT FAIL------------------------
 
        self.assertFalse(self._setup_client_session_and_close(self._expired_cert_tls_server.get_name(),
                                                              use_hard_fail_fallback_mechanism=False))