"""AsaDVSNI"""
import logging
import time

from certbot import errors
from certbot.plugins import common

from certbot_asa import asa

logger = logging.getLogger(__name__)


class AsaDvsni(common.TLSSNI01):
    """Class performs DVSNI challenges within the Asa configurator.

    :ivar configurator: AsaAuthenticator object
    :type configurator: :class:`~configurator.AsaAuthenticator`

    :ivar list achalls: Annotated tls-sni-01
        (`.KeyAuthorizationAnnotatedChallenge`) challenges.

    :param list indices: Meant to hold indices of challenges in a
        larger array. AsaDvsni is capable of solving many challenges
        at once which causes an indexing issue within AsaAuthenticator
        who must return all responses in order.  Imagine AsaAuthenticator
        maintaining state about where all of the http-01 Challenges,
        Dvsni Challenges belong in the response array.  This is an optional
        utility.

    :param str challenge_conf: location of the challenge config file

    """

#    def install_cert(self, asa, p12):
#        return

    def check_for_dup_certs(self):
        import OpenSSL.crypto
        certs = []
        for achall in self.achalls:
            c = open(self.get_cert_path(achall), 'rt').read()
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, c)
            i = ['SN', cert.get_serial_number()]
            for a in cert.get_issuer().get_components():
                i += list(a)
            certs.append(tuple(i))
        if len(certs) == len(set(certs)):
            return False
        return True

    def perform(self, asa):
        """Perform a DVSNI challenge using Cisco ASA.

        :returns: list of :class:`certbot.acme.challenges.DVSNIResponse`
        :rtype: list

        """
        from pprint import pprint as pp
        import base64
        import OpenSSL.crypto
        import time
        import string
        import random

        print "Dup certs? "+str(self.check_for_dup_certs())

        if not self.achalls:
            return []

        check_for_dup_certs

        # Basename for challenge response trustpoints on ASA boxes.
        TpBaseName = "acme_challenge_"+str(int(time.time()))+"_"

        # Create challenge certs
        responses = [self._setup_challenge_cert(x) for x in self.achalls]
#        pp(["responses: ",responses])

        s = string.ascii_letters + string.digits
        i = 0
        for achall in self.achalls:
#            P12PassPhrase = ''.join(random.choice(s) for i in range (10))
            P12PassPhrase = 'foo'
            c=open(self.get_cert_path(achall), 'rt').read()
            k=open(self.get_key_path(achall), 'rt').read()
            cert=OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, c)
            key=OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, k)
            p12=OpenSSL.crypto.PKCS12()
            p12.set_certificate(cert)
            p12.set_privatekey(key)
            b64string=base64.encodestring(p12.export(passphrase=P12PassPhrase))
#            print "crypto ca import "+TpBaseName+str(i)+" pkcs12 "+P12PassPhrase
#            print b64string
            pp(["I have a P12 challenge response structure for: ",achall.response(achall.account_key).z_domain])
            for a in asa:
                a.ImportP12(TpBaseName+str(i), b64string, P12PassPhrase)
                a.SetSniSelector(achall.response(achall.account_key).z_domain, TpBaseName+str(i))
            i += 1
#            print(b64string)
#        time.sleep(100)
        return responses

