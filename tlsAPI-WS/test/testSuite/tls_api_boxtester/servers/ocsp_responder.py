import subprocess
from globals import *

class OCSPResponder(object):
    """
    Simple OCSP Responder server using 'openssl ocsp' command for tests ONLY
    """

    def __init__(self, port, db_path, certificate, private, ca_certificates):
        """
        Constructor.

        :param port: Server's port.
        :param db_path: Text file that contains the valid and revoked server. generated as part of the openssl ca cmd.
        :param certificate: The certificate to sign OCSP responses with.
        :param private: The private key to sign OCSP responses with.
        :param ca_certificates: The supported CA certificates.
        """

        self._port = port
        self._db_path = db_path
        self._certificate = certificate
        self._private = private
        self._ca_certificates = ca_certificates
        self._openssl_ocsp_pid = None

    def start(self):
        """
        Bind and activate the server to address 'localhost':port
        Server's IP is 127.0.0.1 by default.
        """

        args = "-index {} -port {} -rsigner {} -rkey {} -CA {}". \
            format(self._db_path, self._port, self._certificate, self._private, self._ca_certificates)

        self._openssl_ocsp_pid = subprocess.Popen(["openssl", "ocsp"] + args.split(), \
                                                  stdout=subprocess.DEVNULL, \
                                                  stderr=subprocess.DEVNULL)

    def stop(self):
        """
        Stop and terminate the server.
        """

        self._openssl_ocsp_pid.terminate()
