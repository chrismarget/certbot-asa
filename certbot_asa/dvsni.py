"""AsaDVSNI"""
import logging
import time
import OpenSSL.crypto

from certbot import errors
from certbot.plugins import common

from certbot_asa import asa
from certbot_asa import pki

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

    def cleanup(self, asa):
        import hashlib
        """Delete DVSNI challenge certificates/keys from ASA"""
        print "begin dvsni.cleanup"
        for achall in self.achalls:
            z_domain_hash = hashlib.md5(achall.response(achall.account_key).z_domain)
            trustpoint_name = "acme_challenge_"+z_domain_hash.hexdigest()
            for a in asa:
                a.remove_trustpoint(trustpoint_name)
        print "end dvsni.cleanup"

    def perform(self, asa):
        """Perform a DVSNI challenge using Cisco ASA.

        :returns: list of :class:`certbot.acme.challenges.DVSNIResponse`
        :rtype: list

        """
        import base64
        import hashlib
        import OpenSSL.crypto
        import time

        if not self.achalls:
            return []

        # Basename for challenge response trustpoints on ASA boxes.
        TpBaseName = "acme_challenge_"+str(int(time.time()))+"_"

        # Create challenge certs
        responses = [self._setup_challenge_cert(x) for x in self.achalls]

        for achall in self.achalls:
            p12 = pki.make_p12(self.get_cert_path(achall), self.get_key_path(achall))
            z_domain_hash = hashlib.md5(achall.response(achall.account_key).z_domain)
            b64string = base64.encodestring(p12.export(passphrase = z_domain_hash.hexdigest()))
            trustpoint_name = "acme_challenge_"+z_domain_hash.hexdigest()
            for a in asa:
                a.import_p12(trustpoint_name, b64string, z_domain_hash.hexdigest())
                a.Activate_SNI(achall.response(achall.account_key).z_domain, trustpoint_name)
        return responses
