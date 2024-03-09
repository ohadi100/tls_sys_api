import os
from enum import Enum
from OpenSSL import SSL

# Define a global variable that will have the path to the tested TLS API library
TLS_LIB_PATH = None

# Misc directory path
MISC_DIR_PATH = os.path.join(os.getcwd(), "misc")

# Misc subdirectories & files path
MISC_KEYS_DIR_PATH = os.path.join(MISC_DIR_PATH, "keys")

MISC_KEYS_ECDSA_DIR_PATH = os.path.join(MISC_KEYS_DIR_PATH, "ecdsa")
MISC_KEYS_ECDSA_SERVER_DIR_PATH = os.path.join(MISC_KEYS_ECDSA_DIR_PATH, "server")
MISC_KEYS_ECDSA_CLIENT_DIR_PATH = os.path.join(MISC_KEYS_ECDSA_DIR_PATH, "client")

MISC_KEYS_RSA_DIR_PATH = os.path.join(MISC_KEYS_DIR_PATH, "rsa")
MISC_KEYS_RSA_SERVER_DIR_PATH = os.path.join(MISC_KEYS_RSA_DIR_PATH, "server")
MISC_KEYS_RSA_CLIENT_DIR_PATH = os.path.join(MISC_KEYS_RSA_DIR_PATH, "client")

MISC_KEYS_OCSP_DIR_PATH = os.path.join(MISC_KEYS_DIR_PATH, "ocsp")
MISC_KEYS_OCSP_KEYS_DIR_PATH = os.path.join(MISC_KEYS_OCSP_DIR_PATH, "keys")
MISC_KEYS_OCSP_CERTS_DIR_PATH = os.path.join(MISC_KEYS_OCSP_DIR_PATH, "certs")
MISC_KEYS_OCSP_RESPONSES_DIR_PATH = os.path.join(MISC_KEYS_OCSP_DIR_PATH, "responses")

# Enum which defines the OCSP fallback mechanism type
class CertificateRevocationCheckType(Enum):
    SOFT_FAIL = 0
    HARD_FAIL = 1

# Enum which defines the TLS protocol version
class TLSProtocolVersionType(Enum):
    TLS_1_1 = SSL.TLSv1_1_METHOD
    TLS_1_2 = SSL.TLSv1_2_METHOD
    TLS_1_3 = SSL.TLS_METHOD

# Enum which defines TLS authentication algorithm type
class SignatureAlgorithmType(Enum):
    ECDSA = 0
    RSA = 1

# Enum which defines ALPN protocol type
class ALPNProtocolType(Enum):
    H2 = "h2"
    SPDY1 = "spdy/1"
    HTTP1_1 = "http/1.1"

# Enum which defines EC point type
class ECPointType(Enum):
    SECP384R1 = "secp384r1"
    SECP521R1 = "secp521r1"
    SECT163K1 = "sect163k1"
    PRIME256V1 = "prime256v1"

# Enum which defines the cipher suites for TLS version 1.1. TLS cert engine doesn't support TLS 1.1.
class TLS11CipherSuitesType(Enum):
    ALL = "ALL"

# Enum which defines the cipher suites for TLS version 1.2 that the TLS cert engine supports (in all use cases)
class TLS12CipherSuiteType(Enum):
    DHE_RSA_AES256_GCM_SHA384 = "DHE-RSA-AES256-GCM-SHA384"
    DHE_RSA_AES128_GCM_SHA256 = "DHE-RSA-AES128-GCM-SHA256"
    ECDHE_RSA_AES256_GCM_SHA384 = "ECDHE-RSA-AES256-GCM-SHA384"
    ECDHE_RSA_AES128_GCM_SHA256 = "ECDHE-RSA-AES128-GCM-SHA256"
    ECDHE_ECDSA_CHACHA20_POLY1305 = "ECDHE-ECDSA-CHACHA20-POLY1305"
    ECDHE_ECDSA_AES256_GCM_SHA384 = "ECDHE-ECDSA-AES256-GCM-SHA384"
    ECDHE_ECDSA_AES128_GCM_SHA256 = "ECDHE-ECDSA-AES128-GCM-SHA256"
    #iana additions
    DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = "DHE-RSA-CHACHA20-POLY1305"
    ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = "ECDHE-RSA-CHACHA20-POLY1305"
    #legacy additions
    ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = "ECDHE-ECDSA-AES128-SHA256"
    ECDHE_ECDSA_WITH_AES_128_CBC_SHA = "ECDHE-ECDSA-AES128-SHA"
    ECDHE_ECDSA_WITH_AES_256_CBC_SHA = "ECDHE-ECDSA-AES256-SHA"
    ECDHE_RSA_WITH_AES_128_CBC_SHA256 = "ECDHE-RSA-AES128-SHA256"
    ECDHE_RSA_WITH_AES_128_CBC_SHA = "ECDHE-RSA-AES128-SHA"
    ECDHE_RSA_WITH_AES_256_CBC_SHA = "ECDHE-RSA-AES256-SHA"
    DHE_RSA_WITH_AES_128_CBC_SHA256 = "DHE-RSA-AES128-SHA256"
    DHE_RSA_WITH_AES_256_CBC_SHA256 = "DHE-RSA-AES256-SHA256"
    RSA_WITH_AES_128_GCM_SHA256 = "AES128-GCM-SHA256"
    RSA_WITH_AES_256_GCM_SHA384 = "AES256-GCM-SHA384"
    RSA_WITH_AES_128_CBC_SHA256 = "AES128-SHA256"
    RSA_WITH_AES_256_CBC_SHA256 = "AES256-SHA256"
    RSA_WITH_AES_128_CBC_SHA = "AES128-SHA"
    RSA_WITH_AES_256_CBC_SHA = "AES256-SHA"
    RSA_WITH_3DES_EDE_CBC_SHA = "DES-CBC3-SHA"

# Enum which defines the cipher suites for TLS version 1.3 that the TLS cert engine supports (in all use cases)
class TLS13CipherSuiteType(Enum):
    TLS13_AES128_GCM_SHA256 = "TLS_AES_128_GCM_SHA256"
    TLS13_AES256_GCM_SHA384 = "TLS_AES_256_GCM_SHA384"
    TLS13_CHACHA20_POLY1305_SHA256 = "TLS_CHACHA20_POLY1305_SHA256"
    TLS13_AES128_CCM_SHA256 = "TLS_AES_128_CCM_SHA256"
    TLS13_AES128_CCM8_SHA256 = "TLS_AES_128_CCM_8_SHA256"


# Enum which defines the TLS 1.3 unsupported cipher suites in the TLS cert engine.
class TLS13UnsupportedCipherSuiteType(Enum):
    TLS13_AES128_CCM_SHA256 = "TLS_AES_128_CCM_SHA256"
    TLS13_AES128_CCM8_SHA256 = "TLS_AES_128_CCM_8_SHA256"

# Enum which defines cipher suites Use Case type
class CipherSuitesUseCaseType(Enum):
    CSUSDefault = 0
    CSUSLegacy = 1
    CSUSLongtermSecure = 2
    CSUSIanaRecommended = 3
    CSUSDefaultWithSoftFail = 4

#Ciphers suites lists by CipherSuitesUseCaseType:

#Some of cipher suites list for TLS version 1.2 that the TLS cert engine does not support in CSUSDefault use case.
TLS12notDefaultCipherSuites = [TLS12CipherSuiteType.DHE_RSA_WITH_CHACHA20_POLY1305_SHA256]

#cipher suites list for TLS version 1.2 that the TLS cert engine supports in CSUSDefault use case.
TLS12defaultCipherSuites = [TLS12CipherSuiteType.DHE_RSA_AES256_GCM_SHA384, TLS12CipherSuiteType.DHE_RSA_AES128_GCM_SHA256,\
                            TLS12CipherSuiteType.ECDHE_RSA_AES256_GCM_SHA384, TLS12CipherSuiteType.ECDHE_RSA_AES128_GCM_SHA256,\
                            TLS12CipherSuiteType.ECDHE_ECDSA_CHACHA20_POLY1305, TLS12CipherSuiteType.ECDHE_ECDSA_AES256_GCM_SHA384,\
                            TLS12CipherSuiteType.ECDHE_ECDSA_AES128_GCM_SHA256]

#cipher suites list for TLS version 1.3 that the TLS cert engine supports in CSUSDefault use case.
TLS13defaultCipherSuites = [TLS13CipherSuiteType.TLS13_AES128_GCM_SHA256,
                            TLS13CipherSuiteType.TLS13_AES256_GCM_SHA384,
                            TLS13CipherSuiteType.TLS13_CHACHA20_POLY1305_SHA256]

#cipher suites list for TLS version 1.2 that the TLS cert engine supports in CSUSIanaRecommended use case.
TLS12IanaRecommendedCipherSuites = TLS12defaultCipherSuites + [TLS12CipherSuiteType.DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,\
                                                               TLS12CipherSuiteType.ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256]

#cipher suites list for TLS version 1.3 that the TLS cert engine supports in CSUSIanaRecommended use case.
TLS13IanaRecommendedCipherSuites = TLS13defaultCipherSuites + [TLS13CipherSuiteType.TLS13_AES128_CCM_SHA256]

#cipher suites list for TLS version 1.2 that the TLS cert engine supports in CSUSLegacy use case.
TLS12legacyCipherSuites = TLS12IanaRecommendedCipherSuites +\
                          [TLS12CipherSuiteType.ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS12CipherSuiteType.ECDHE_ECDSA_WITH_AES_128_CBC_SHA, \
                           TLS12CipherSuiteType.ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS12CipherSuiteType.ECDHE_RSA_WITH_AES_128_CBC_SHA256,\
                           TLS12CipherSuiteType.ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS12CipherSuiteType.ECDHE_RSA_WITH_AES_256_CBC_SHA,\
                           TLS12CipherSuiteType.DHE_RSA_WITH_AES_128_CBC_SHA256, TLS12CipherSuiteType.DHE_RSA_WITH_AES_256_CBC_SHA256,\
                           TLS12CipherSuiteType.RSA_WITH_AES_128_GCM_SHA256, TLS12CipherSuiteType.RSA_WITH_AES_256_GCM_SHA384,\
                           TLS12CipherSuiteType.RSA_WITH_AES_128_CBC_SHA256,TLS12CipherSuiteType.RSA_WITH_AES_256_CBC_SHA256,\
                           TLS12CipherSuiteType.RSA_WITH_AES_128_CBC_SHA,TLS12CipherSuiteType.RSA_WITH_AES_256_CBC_SHA,\
                           TLS12CipherSuiteType.RSA_WITH_3DES_EDE_CBC_SHA]

#cipher suites list for TLS version 1.3 that the TLS cert engine supports in CSUSLegacy use case.
TLS13legacyCipherSuites = TLS13IanaRecommendedCipherSuites + [TLS13CipherSuiteType.TLS13_AES128_CCM_SHA256]

#cipher suites list for TLS version 1.2 that the TLS cert engine supports in CSUSLongtermSecure use case.
TLS12LongtermSecureCipherSuites = [TLS12CipherSuiteType.ECDHE_ECDSA_CHACHA20_POLY1305, TLS12CipherSuiteType.ECDHE_ECDSA_AES256_GCM_SHA384,
                                   TLS12CipherSuiteType.ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS12CipherSuiteType.ECDHE_RSA_AES256_GCM_SHA384,
                                   TLS12CipherSuiteType.DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS12CipherSuiteType.DHE_RSA_AES256_GCM_SHA384]

#cipher suites list for TLS version 1.3 that the TLS cert engine supports in CSUSLongtermSecure use case.
TLS13LongtermSecureCipherSuites = [TLS13CipherSuiteType.TLS13_AES256_GCM_SHA384, TLS13CipherSuiteType.TLS13_CHACHA20_POLY1305_SHA256]

TLS12CIPHER_SUITES_LIST_BY_USE_CASE_DICT = { CipherSuitesUseCaseType.CSUSDefault : TLS12defaultCipherSuites,
                                             CipherSuitesUseCaseType.CSUSLongtermSecure : TLS12LongtermSecureCipherSuites,
                                             CipherSuitesUseCaseType.CSUSIanaRecommended : TLS12IanaRecommendedCipherSuites,
                                             CipherSuitesUseCaseType.CSUSLegacy : TLS12legacyCipherSuites,
                                             CipherSuitesUseCaseType.CSUSDefaultWithSoftFail : TLS12defaultCipherSuites}

TLS13CIPHER_SUITES_LIST_BY_USE_CASE_DICT = { CipherSuitesUseCaseType.CSUSDefault : TLS13defaultCipherSuites,
                                             CipherSuitesUseCaseType.CSUSLongtermSecure : TLS13LongtermSecureCipherSuites,
                                             CipherSuitesUseCaseType.CSUSIanaRecommended : TLS13IanaRecommendedCipherSuites,
                                             CipherSuitesUseCaseType.CSUSLegacy : TLS13legacyCipherSuites,
                                             CipherSuitesUseCaseType.CSUSDefaultWithSoftFail : TLS13defaultCipherSuites}

#path variables
_ECDSA_SERVER_ROOT_CA_FILE_PATH = os.path.join(MISC_KEYS_ECDSA_SERVER_DIR_PATH, "root_ca.pem")
_ECDSA_SERVER_CERTIFICATE_FILE_PATH = os.path.join(MISC_KEYS_ECDSA_SERVER_DIR_PATH, "cert.pem")
_ECDSA_SERVER_PRIVATE_KEY_FILE_PATH = os.path.join(MISC_KEYS_ECDSA_SERVER_DIR_PATH, "private.pem")
_ECDSA_SERVER_OCSP_STAPLING_FILE_PATH = os.path.join(MISC_KEYS_ECDSA_SERVER_DIR_PATH, "ocsp_stapling.der")

_RSA_SERVER_ROOT_CA_FILE_PATH = os.path.join(MISC_KEYS_RSA_SERVER_DIR_PATH, "root_ca.pem")
_RSA_SERVER_CERTIFICATE_FILE_PATH = os.path.join(MISC_KEYS_RSA_SERVER_DIR_PATH, "cert.pem")
_RSA_SERVER_PRIVATE_KEY_FILE_PATH = os.path.join(MISC_KEYS_RSA_SERVER_DIR_PATH, "private.pem")
_RSA_SERVER_OCSP_STAPLING_FILE_PATH = os.path.join(MISC_KEYS_RSA_SERVER_DIR_PATH, "ocsp_stapling.der")

_ECDSA_CLIENT_CERTIFICATE_FILE_PATH = os.path.join(MISC_KEYS_ECDSA_CLIENT_DIR_PATH, "cert.pem")
_ECDSA_CLIENT_PRIVATE_KEY_FILE_PATH = os.path.join(MISC_KEYS_ECDSA_CLIENT_DIR_PATH, "private.key")

_RSA_CLIENT_CERTIFICATE_FILE_PATH = os.path.join(MISC_KEYS_RSA_CLIENT_DIR_PATH, "cert.pem")
_RSA_CLIENT_PRIVATE_KEY_FILE_PATH = os.path.join(MISC_KEYS_RSA_CLIENT_DIR_PATH, "private.key")

SERVER_ROOT_CA_BY_SIG_TYPE_DICT = { SignatureAlgorithmType.ECDSA : _ECDSA_SERVER_ROOT_CA_FILE_PATH,
                                     SignatureAlgorithmType.RSA   : _RSA_SERVER_ROOT_CA_FILE_PATH }

SERVER_CERTS_BY_SIG_TYPE_DICT = { SignatureAlgorithmType.ECDSA : _ECDSA_SERVER_CERTIFICATE_FILE_PATH,
                                   SignatureAlgorithmType.RSA   : _RSA_SERVER_CERTIFICATE_FILE_PATH }

SERVER_PRIVATE_BY_SIG_TYPE_DICT = { SignatureAlgorithmType.ECDSA : _ECDSA_SERVER_PRIVATE_KEY_FILE_PATH,
                                     SignatureAlgorithmType.RSA   : _RSA_SERVER_PRIVATE_KEY_FILE_PATH }

SERVER_OCSP_STAPLING_BY_SIG_TYPE_DICT = { SignatureAlgorithmType.ECDSA : _ECDSA_SERVER_OCSP_STAPLING_FILE_PATH,
                                          SignatureAlgorithmType.RSA : _RSA_SERVER_OCSP_STAPLING_FILE_PATH}

CLIENT_CERTS_BY_SIG_TYPE_DICT = { SignatureAlgorithmType.ECDSA : _ECDSA_CLIENT_CERTIFICATE_FILE_PATH,
                                   SignatureAlgorithmType.RSA   : _RSA_CLIENT_CERTIFICATE_FILE_PATH }

CLIENT_PRIVATE_BY_SIG_TYPE_DICT = { SignatureAlgorithmType.ECDSA : _ECDSA_CLIENT_PRIVATE_KEY_FILE_PATH,
                                     SignatureAlgorithmType.RSA   : _RSA_CLIENT_PRIVATE_KEY_FILE_PATH }