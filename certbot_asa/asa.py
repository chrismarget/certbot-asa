"""Cisco ASA Device Stuff"""

from certbot import errors
from certbot.plugins import common
import requests
import logging

requests.packages.urllib3.disable_warnings()
logging.getLogger("requests").setLevel(logging.WARNING)

class RestAsa(common.TLSSNI01):
    """Class talks to ASA via REST API"""

    def __init__(self, host, user, passwd, noverify, castore):
        self.host = host
        self.user = user
        self.passwd = passwd
        self.noverify = noverify
        self.verify = castore
        if noverify == True:
            self.verify = False

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

    def remove_trustpoint(self, trustpoint):
        """Remove P12 package from ASA"""
        import base64
        import json
        import urllib2
        import ssl
        print "removing from "+self.host+" trustpoint "+trustpoint+" with noverify: "+str(self.noverify)

        headers = {'Content-Type': 'application/json'}
        api_path = "/api/certificate/identity/"+trustpoint
        url = "https://"+self.host+api_path

        req = urllib2.Request(url, None, headers)
        base64string = base64.encodestring('%s:%s' % (self.user, self.passwd)).replace('\n', '')
        req.add_header("Authorization", "Basic %s" % base64string)   
        req.get_method = lambda: 'DELETE'

        f = None
        if self.noverify:
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
        return

    def remove_keypair(self, keypair_name):
        """Remove crypto keypair from ASA"""
        import base64
        import json
        import urllib2
        import ssl
        print "removing from "+self.host+" keypair "+keypair_name+" with noverify: "+str(self.noverify)

        headers = {'Content-Type': 'application/json'}
        api_path = "/api/certificate/keypair/"+keypair_name
        url = "https://"+self.host+api_path

        req = urllib2.Request(url, None, headers)
        base64string = base64.encodestring('%s:%s' % (self.user, self.passwd)).replace('\n', '')
        req.add_header("Authorization", "Basic %s" % base64string)   
        req.get_method = lambda: 'DELETE'

        f = None
        if self.noverify:
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
        return


    def get_cert_json(self, trustpoint):
        """Returns cert details from the specified trustpoint"""
        apiPath = '/api/certificate/details/'
        apiUrl = 'https://'+self.host+apiPath+trustpoint
        i = requests.get(apiUrl, auth=(self.user, self.passwd), verify=self.verify)
        return i.json()


    def writemem(self):
        """Saves configuration"""
        print ("begin writemem")
        apiPath = '/api/commands/writemem'
        apiUrl = 'https://'+self.host+apiPath
        headers = {'Content-Type': 'application/json'}
        r = requests.post(apiUrl, headers=headers, data={}, auth=(self.user, self.passwd), verify=self.verify)


    def list_trustpoints(self, certtype=None):
        """Returns list of trustpoints of the specified type, or all trustpoints"""
        requests.packages.urllib3.disable_warnings()
        trustpoints = []
        if certtype == "identity" or certtype == None:
            apiPath = '/api/certificate/identity'
            apiUrl = 'https://'+self.host+apiPath
            i = requests.get(apiUrl, auth=(self.user, self.passwd), verify=self.verify)
            for x in range(len(i.json()['items'])):
                trustpoints.append(i.json()['items'][x]['objectId'])
        if certtype == "ca" or certtype == None:
            apiPath = '/api/certificate/ca'
            apiUrl = 'https://'+self.host+apiPath
            c = requests.get(apiUrl, auth=(self.user, self.passwd), verify=self.verify)
            for x in range(len(c.json()['items'])):
                trustpoints.append(c.json()['items'][x]['trustpointName'])
        return trustpoints

    def import_ca_cert(self, trustpoint, PEMstring):
        """Install PEM-encoded CA cert on an ASA"""
        import json
        import requests
        requests.packages.urllib3.disable_warnings()
        apiPath = '/api/certificate/ca'
        apiUrl = 'https://'+self.host+apiPath
        headers = {'Content-Type': 'application/json'}
        auth = (self.user, self.passwd)
        verify = self.verify
        post_data = {}
        post_data["kind"] = "object#CACertificate"
        post_data["certText"] = PEMstring.splitlines()
        post_data["trustpointName"] = trustpoint
        data = json.dumps(post_data)
        r = requests.post(apiUrl, headers=headers, data=data, auth=auth, verify=verify)

#{
#  "kind": "object#CACertificate",
#  "certText": [
#    "MIIEGDCCAwCgAwIBAgIBATANBgkqhkiG9w0BAQUFADBlMQswCQYDVQQGEwJTRTEU",
#    "MBIGA1UEChMLQWRkVHJ1c3QgQUIxHTAbBgNVBAsTFEFkZFRydXN0IFRUUCBOZXR3",
#    "b3JrMSEwHwYDVQQDExhBZGRUcnVzdCBDbGFzcyAxIENBIFJvb3QwHhcNMDAwNTMw",
#    "MTAzODMxWhcNMjAwNTMwMTAzODMxWjBlMQswCQYDVQQGEwJTRTEUMBIGA1UEChML",
#    "QWRkVHJ1c3QgQUIxHTAbBgNVBAsTFEFkZFRydXN0IFRUUCBOZXR3b3JrMSEwHwYD",
#    "VQQDExhBZGRUcnVzdCBDbGFzcyAxIENBIFJvb3QwggEiMA0GCSqGSIb3DQEBAQUA",
#    "A4IBDwAwggEKAoIBAQCWltQhSWDia+hBBwzexODcEyPNwTXH+9ZOEQpnXvUGW2ul",
#    "CDtbKRY654eyNAbFvAWlA3yCyykQruGIgb3WntP+LVbBFc7jJp0VLhD7Bo8wBN6n",
#    "tGO0/7Gcrjyvd7ZWxbWroulpOj0OM3kyP3CCkplhbY0wCI9xP6ZIVxn4JdxLZlyl",
#    "dI+Yrsj5wAYi56xz36Uu+1LcsRVlIPo1Zmne3yzxbrww2ywkEtvrNTVokMsAsJch",
#    "PXQhI2U0K7t4WaPW4XY5mqRJjox0r26kmqPZm9I4XJuiGMx1I4S+6+JNM3GOGvDC",
#    "+Mcdoq0Dlyz4zyXG9rgkMbFjXZJ/Y/AlyVMuH79NAgMBAAGjgdIwgc8wHQYDVR0O",
#    "BBYEFJWxtPCUtr3H2tERCSG+wa9J/RB7MAsGA1UdDwQEAwIBBjAPBgNVHRMBAf8E",
#    "BTADAQH/MIGPBgNVHSMEgYcwgYSAFJWxtPCUtr3H2tERCSG+wa9J/RB7oWmkZzBl",
#    "MQswCQYDVQQGEwJTRTEUMBIGA1UEChMLQWRkVHJ1c3QgQUIxHTAbBgNVBAsTFEFk",
#    "ZFRydXN0IFRUUCBOZXR3b3JrMSEwHwYDVQQDExhBZGRUcnVzdCBDbGFzcyAxIENB",
#    "IFJvb3SCAQEwDQYJKoZIhvcNAQEFBQADggEBACxtZBsfzQ3duQH6lmM0MkhHma6X",
#    "7f1yFqZzR1r0693p9db7RcwpiURdv0Y5PejuvE1Uhh4dbOMXJ0PhiVYrqW9yTkkz",
#    "43J8KiOavD7/KCrto/8cI7pDVwlnTUtiBi34/2ydYB7YHEt9tTEv2dB8Xfjea4MY",
#    "eDdXL+gzB2ffHsdrKpV2ro9Xo/D0UrSpUwjP4E/TelOL/bscVjby/rK25Xa71SJl",
#    "pz/+0WatC7xrmYbvP33zGDLKe8bjq2RGlfgmadlVg3sslgf/WSxEo8bl6ancoWOA",
#    "WiFeIc9TVPC6b4nbqKqVz4vjccweGyBECMB6tkD9xOQ14R0WHNC8K47Wcdk="
#  ],
#  "trustpointName": "certificate6"
#}


    def import_p12(self, trustpoint, P12String, PassPhrase):
        """Install P12 package on an ASA"""
        import base64
        import json
        import urllib2
        import ssl
        print "importing certificate to "+self.host+" trustpoint "+trustpoint+" with noverify: "+str(self.noverify)

        headers = {'Content-Type': 'application/json'}
        api_path = "/api/certificate/identity"
        url = "https://"+self.host+api_path

        post_data = {}
        post_data["certPass"] = PassPhrase
        post_data["kind"] = "object#IdentityCertificate"
        post_data["certText"] = ["-----BEGIN PKCS12-----"]+P12String.splitlines()+["-----END PKCS12-----"]
        post_data["name"] = trustpoint

        req = urllib2.Request(url, json.dumps(post_data), headers)
        base64string = base64.encodestring('%s:%s' % (self.user, self.passwd)).replace('\n', '')
        req.add_header("Authorization", "Basic %s" % base64string)   

        f = None
        if self.noverify:
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
        return


    def Activate_SNI(self, z_domain, trustpoint):
        """Activate SNI challenge certificate"""
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
        if self.noverify:
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
        if self.noverify:
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
