import os
import shutil
from globals import *
from pathlib import Path

DEFAULT_CERT_STORE_ID = "ROOT_CA"
DEFAULT_CLIENT_CERT_STORE_ID = "MOS"

_VKMS_PATH = "/tmp/MockTeeStorage"
_VKMS_TRUST_STORE_PATH = os.path.join(_VKMS_PATH, "TrustStore")
_VKMS_CLIENT_STORE_PATH = os.path.join(_VKMS_PATH, "ClientCertStore")


class VKMS(object):
    """
    This class responsible to manage the VKMS module for the tested client
    """

    def __init__(self):
        """
        Constructor.
        """

        Path(_VKMS_TRUST_STORE_PATH).mkdir(parents=True, exist_ok=True)
        Path(_VKMS_CLIENT_STORE_PATH).mkdir(parents=True, exist_ok=True)

    def load_root_ca(self, cert_file_path, cert_store_id=DEFAULT_CERT_STORE_ID):
        """
        Loads ROOT CA certificate to client

        :param cert_file_path: Path to root ca certificate file
        :param cert_id: Certificate store ID. by default "ROOT_CA"
        """

        vkms_root_ca_path = os.path.join(_VKMS_TRUST_STORE_PATH, cert_store_id + "_TS.pem")

        shutil.copy2(cert_file_path, vkms_root_ca_path)

    def load_client_cert(self, cert_file_path, private_key_file, cert_store_id=DEFAULT_CLIENT_CERT_STORE_ID):
        """
        Loads client's certificate and private key

        :param cert_file_path: Path to client's certificate file
        :param private_key_file: Path to client's private key
        :param cert_store_id: Certificate store ID. by default "MOS"
        """

        vkms_cert_client_path = os.path.join(_VKMS_CLIENT_STORE_PATH, cert_store_id + "_CERT.pem")
        vkms_key_client_path = os.path.join(_VKMS_CLIENT_STORE_PATH, cert_store_id + "_KEY.pem")

        shutil.copy2(cert_file_path, vkms_cert_client_path)
        shutil.copy2(private_key_file, vkms_key_client_path)
