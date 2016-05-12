"""Cisco ASA Device Stuff"""

from certbot import errors
from certbot.plugins import common

from pprint import pprint as pp

#logger = logging.getLogger(__name__)


class RestAsa(common.TLSSNI01):
    """Class talks to ASA via REST API"""

    def __init__(self, host, user, passwd, selfsigned):
        self.host = host
        self.user = user
        self.passwd = passwd
        self.selfsigned = selfsigned

#    :ivar configurator: AsaAuthenticator object
#    :type configurator: :class:`~configurator.AsaAuthenticator`
#
#    :ivar list achalls: Annotated tls-sni-01
#        (`.KeyAuthorizationAnnotatedChallenge`) challenges.
#
#    :param list indices: Meant to hold indices of challenges in a
#        larger array. ExternalDvsni is capable of solving many challenges
#        at once which causes an indexing issue within AsaAuthenticator
#        who must return all responses in order.  Imagine AsaAuthenticator
#        maintaining state about where all of the http-01 Challenges,
#        Dvsni Challenges belong in the response array.  This is an optional
#        utility.
#
#    :param str challenge_conf: location of the challenge config file
#
#    """

    def livetest(self):
        """Test TCP connect to REST API port 443"""
        import socket
	s = socket.socket()
	try:
		s.connect((self.host, 443))
		s.close()
		return True
	except socket.error, e:
		s.close()
		return False

    def ImportP12(self, trustpoint, P12String, PassPhrase):
        """Install P12 package on an ASA"""
        from pprint import pprint as pp
        import base64
        import json
        import urllib2
        import ssl
        print "importing certificate to "+self.host+" trustpoint "+trustpoint+" with password "+PassPhrase+" and selfsigned:"+str(self.selfsigned)


        headers = {'Content-Type': 'application/json'}
        api_path = "/api/certificate/identity"
        url = "https://"+self.host+api_path
        print 'url = "'+url+'"'

        post_data = {}
        post_data["certPass"] = PassPhrase
        post_data["kind"] = "object#IdentityCertificate"
        post_data["certText"] = ["-----BEGIN PKCS12-----"]+P12String.splitlines()+["-----END PKCS12-----"]
        post_data["name"] = trustpoint
        pp(post_data)

        req = urllib2.Request(url, json.dumps(post_data), headers)
        base64string = base64.encodestring('%s:%s' % (self.user, self.passwd)).replace('\n', '')
        req.add_header("Authorization", "Basic %s" % base64string)   

        f = None
        if self.selfsigned:
            print "selfsigned okay"
            try:
                f = urllib2.urlopen(req, context=ssl._create_unverified_context(), timeout=30)
                status_code = f.getcode()
                print "Unverified Status code is "+str(status_code)
            except ssl.CertificateError, err:
                print "SSL error"
                if f: f.close()
                return [False, err]
            except Exception as err:
                print "other error"
                pp(err.reason)
                if f: f.close()
                return [False, err]
        else:
            print "doing ssl validation"
            try:
                f = urllib2.urlopen(req, context=ssl.create_default_context(), timeout=30)
                status_code = f.getcode()
                print "Verified Status code is "+str(status_code)
            except Exception as err:
                if f: f.close()
                return [False, err]
        return

    def cleanup(self, trustpoint):
        import base64
        import json
        import urllib2
        import ssl
        headers = {'Content-Type': 'application/json'}
        api_path = "/api"
#        url = "https://"+self.host+api_path
        url = "https://test-asa/apa"
        f = None

        post_data = [
          {     
            "resourceUri": "/api/certificate/identity/"+trustpoint,
            "method": "Delete"
          },
          {     
            "resourceUri": "/api/certificate/keypair/"+trustpoint,
            "method": "Delete"
          }
        ]
        req = urllib2.Request(url, json.dumps(post_data), headers)
        base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
        req.add_header("Authorization", "Basic %s" % base64string)   
        try:
            f  = urllib2.urlopen(req)
            status_code = f.getcode()
        except Exception as err:
                if f: f.close()
                return [False, err]
        finally:
            if f:  f.close()
        return

    def SetSniSelector(self, z_domain, trustpoint):
        """Test ASA credentials"""
        import base64
        import json
        import urllib2
        import ssl

        headers = {'Content-Type': 'application/json'}
        api_path = "/api/cli"
        url = "https://" + self.host + api_path
        f = None
        command = "ssl trust-point "+trustpoint+" domain "+z_domain
        post_data = { "commands": [ command ] }
        req = urllib2.Request(url, json.dumps(post_data), headers)
        base64string = base64.encodestring('%s:%s' % (self.user, self.passwd)).replace('\n', '')
        req.add_header("Authorization", "Basic %s" % base64string)
        print "ssl trust-point "+trustpoint+" domain "+z_domain
        if self.selfsigned:
            try:
                f = urllib2.urlopen(req, context=ssl._create_unverified_context(), timeout=30)
                status_code = f.getcode()
            except ssl.CertificateError, err:
                if f: f.close()
                return [False, err]
            except Exception as err:
                if f: f.close()
                return [False, err]
        else:
            try:
                f = urllib2.urlopen(req, context=ssl.create_default_context(), timeout=30)
                status_code = f.getcode()
            except Exception as err:
                if f: f.close()
                return [False, err]
        return [status_code]

    def authtest(self):
        """Test ASA credentials"""
        import base64
        import json
        import urllib2
        import ssl

        headers = {'Content-Type': 'application/json'}
        api_path = "/api/cli"
        url = "https://" + self.host + api_path
        f = None
        post_data = { "commands": [ "show version" ] }
        req = urllib2.Request(url, json.dumps(post_data), headers)
        base64string = base64.encodestring('%s:%s' % (self.user, self.passwd)).replace('\n', '')
        req.add_header("Authorization", "Basic %s" % base64string)
        if self.selfsigned:
            try:
                f = urllib2.urlopen(req, context=ssl._create_unverified_context(), timeout=30)
                status_code = f.getcode()
            except ssl.CertificateError, err:
                if f: f.close()
                return [False, err]
            except Exception as err:
                if f: f.close()
                return [False, err]
        else:
            try:
                f = urllib2.urlopen(req, context=ssl.create_default_context(), timeout=30)
                status_code = f.getcode()
            except Exception as err:
                if f: f.close()
                return [False, err]
        return [status_code]

#    def perform(self):
#        """Perform a DVSNI challenge using an external script.
#
#        :returns: list of :class:`certbot.acme.challenges.DVSNIResponse`
#        :rtype: list
#
#        """
#        if not self.achalls:
#            return []
#
#        # Create challenge certs
#        responses = [self._setup_challenge_cert(x) for x in self.achalls]
#        import time
#        import pprint
#        pp = pprint.PrettyPrinter(indent=4)
#        pp.pprint(responses)
#
#        for achall in self.achalls:
##             pp.pprint(dir(achall))
#             pp.pprint(achall.chall.encode("token"))
#             pp.pprint(achall.domain)
#             pp.pprint(achall.response(achall.account_key).z_domain)
#             pp.pprint(self.get_cert_path(achall))
#             pp.pprint(self.get_key_path(achall))
#             print 'crypto ca import challenge_'+str(int(time.time()))+'_'+achall.domain+' pkcs12 xyz'
#             print 'sudo openssl pkcs12 -export -in '+self.get_cert_path(achall)+' -inkey '+self.get_key_path(achall)+' -passout pass:foo | base64'
##            ret = self.configurator.call_handler("perform",
##                domain = achall.domain,
##                z_domain = achall.response(achall.account_key).z_domain,
##                cert_path = self.get_cert_path(achall),
##                key_path = self.get_key_path(achall),
##                port = str(self.configurator.config.tls_sni_01_port)
##            )
#
##            if ret in (None, NotImplemented):
##                raise errors.PluginError("perform handler failed")
#
#        import time
#        time.sleep (100)
#        return responses
#
