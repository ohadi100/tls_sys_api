import ctypes
from globals import *


class TLSApi(object):
    """
    This class handles the access to the TLS LIB wrapper in C.
    """

    # Handler to shared object
    _TLS_LIB_C_API = None

    @staticmethod
    def init_tls_lib():
        """
        Static method that initialize the TLS lib.
        must call it before constructor!

        :return: True if successfully initialized the lib otherwise False.
        """

        # Load .so lib into python and create instance for it
        TLSApi._TLS_LIB_C_API = ctypes.CDLL(TLS_LIB_PATH)

        return bool(TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_InitTLSLib())

    @staticmethod
    def cleanup_tls_lib():
        """
        Static method that delete the TLS lib.

        :return: True if successfully deleted the lib otherwise False.
        """

        return bool(TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_CleanupTLSLib())

    def __init__(self):
        """
        Constructor.
        """

        self._tls_lib_inst = TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_CreateWrapperInstance()

        assert self._tls_lib_inst != 0, "TLSLibApi instance is NULL"

    def create_tls_client(self, ip, port, host_name, cert_store_id, client_certificate_set_id, \
                          alpn_protocol=None, client_cipher_suites_use_case = CipherSuitesUseCaseType.CSUSDefault, hash_pinnings = ""):
        """
        Creates TLS client.

        :param ip: Server's IP address.
        :param port: Server's port.
        :param host_name: Server's host name.
        :param cert_store_id: Server's root certificate ID in VKMS.
        :param client_certificate_set_id: Client's certificate ID in VKMS.
        :param alpn_protocol: OPTIONAL. ALPN protocol type to offer the server.
        :param client_cipher_suites_use_case: Client's cipher suite use case.
        :param hash_pinnings: .server's certificate public key hash pinning follows https://datatracker.ietf.org/doc/html/rfc7469

        :return: True if successfully done, otherwise False.
        """

        if (alpn_protocol != None):
            return bool(TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_CreateAlpnTlsClient(self._tls_lib_inst, alpn_protocol.encode(), client_cipher_suites_use_case.value , ip.encode(), \
                                                                                    port, host_name.encode(), cert_store_id.encode(),client_certificate_set_id.encode(), \
                                                                                    hash_pinnings.encode()) )

        return bool(TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_CreateTlsClient(self._tls_lib_inst, client_cipher_suites_use_case.value , ip.encode(), port, \
                                                                    host_name.encode(), cert_store_id.encode(), \
                                                                    client_certificate_set_id.encode() , hash_pinnings.encode()) )

    def connect(self):
        """
        Open session with peer.

        :return: True if successfully done, otherwise False.
        """
        return bool(TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_Connect(self._tls_lib_inst))

    def send(self, data):
        """
        Sends data to peer.

        :param data: data from bytearray type.

        :return: True if successfully done, otherwise False.
        """

        assert isinstance(data, bytearray), "data should be bytearray type"

        c_bytes_buffer_type = (ctypes.c_uint8 * len(data)).from_buffer(data)

        return bool(TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_Send(self._tls_lib_inst, c_bytes_buffer_type, len(data)))

    def get_negotiated_protocol(self):
        """
        Gets the negotiated ALPN protocol from client.

        :return: enumeration type from ALPNProtocolType.
        """

        # This dictionary translates the integer value from TLS LIB to test environment enum.
        TLS_API_ALPN_DICT = { 0 : None,
                              1 : ALPNProtocolType.HTTP1_1,
                              2 : ALPNProtocolType.H2 }

        protocol = TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_GetUsedProtocol(self._tls_lib_inst)

        return TLS_API_ALPN_DICT[protocol]


    def shutdown(self):
        """
        Shutdown client socket.

        :return: True if successfully done, otherwise False.
        """

        return bool(TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_Shutdown(self._tls_lib_inst))

    def free(self):
        """
        Free wrapper's instance.
        """

        TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_DeleteWrapperInstance(self._tls_lib_inst)

    @staticmethod
    def clear_ocsp_cache():
        """
        Clears OCSP handler responses cache
        """

        TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_ClearOCSPCache()

    @staticmethod
    def get_ocsp_cache_size():
        """
        Return size of OCSP cache
        """

        return TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_GetOCSPCacheSize()

    @staticmethod
    def get_number_of_reads_from_ocsp_cache():
        """
        get number of reads from OCSP cache
        """

        return TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_GetOCSPNumberOfReadsFromCache()

    @staticmethod
    def set_next_ocsp_response_to_be_invalid():
        """
        set the next OCSP response from handler to be an invalid one
        """

        TLSApi._TLS_LIB_C_API.TLSLibApiCWrapper_SetNextOCSPResponseInvalid()