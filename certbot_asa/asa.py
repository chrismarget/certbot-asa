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


    def get_trustpoint_keypair(self, trustpoint):
        if trustpoint not in self.list_trustpoints(certtype='identity'):
            return False
        headers = {'Content-Type': 'application/json'}
        apiPath = "/api/certificate/identity/"+trustpoint
        apiUrl = "https://"+self.host+apiPath
        r = requests.get(apiUrl, headers=headers, auth=(self.user, self.passwd), verify=self.verify)
        try: 
            keyPair = r.json()['keyPair']
        except: 
            return False
        return keyPair

    def remove_trustpoint(self, trustpoint):
        print "removing from "+self.host+" trustpoint "+trustpoint+" with noverify: "+str(self.noverify)
        apiPath = "/api/certificate/identity/"+trustpoint
        apiUrl = "https://"+self.host+apiPath
        keyPair = self.get_trustpoint_keypair(trustpoint)
        if trustpoint in self.list_trustpoints(certtype='identity') and keyPair != '<Default-RSA-Key>':
            r = requests.delete(apiUrl, auth=(self.user, self.passwd), verify=self.verify)
            self.remove_keypair(keyPair)
        else:
            r = requests.delete(apiUrl, auth=(self.user, self.passwd), verify=self.verify)

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


    def cert_expired(self, trustpoint):
        import datetime
        validityEndDate = self.get_cert_json(trustpoint)['validityEndDate']
        expires = datetime.datetime.strptime(validityEndDate, '%H:%M:%S %Z %b %d %Y')
        now = datetime.datetime.now()
        if now > expires:
            return True
        return False


#    def purge_expired_certs(self, certtype=None, regex=None):
#        return


    def writemem(self):
        """Saves configuration"""
        print ("begin writemem")
        apiPath = '/api/commands/writemem'
        apiUrl = 'https://'+self.host+apiPath
        headers = {'Content-Type': 'application/json'}
        r = requests.post(apiUrl, headers=headers, data={}, auth=(self.user, self.passwd), verify=self.verify)
        if r.status_code == 200:
            return True
        return False


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
        if r.status_code == 200:
            return True
        return False


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
