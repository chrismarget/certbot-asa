"""PKI stuff"""
import OpenSSL.crypto
import pem

def make_p12(cert_file, key_file):
    print "begin pki.make_p12()"
    """Convert cert/key files to OpenSSL p12 object"""
    c = open(cert_file, 'rt').read()
    k = open(key_file, 'rt').read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, c)
    key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, k)
    p12 = OpenSSL.crypto.PKCS12()
    p12.set_certificate(cert)
    p12.set_privatekey(key)
    print "end pki.make_p12()"
    return p12

class certs_from_pemfile():
    import OpenSSL.crypto
    import pem
    def __init__(self, pemfile):
        self.certs = pem.parse_file(pemfile)
        for i in range(len(self.certs)):
            self.certs[i] = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, str(self.certs[i]))

    def __len__(self):
        return self.len()

    def len(self):
        return len(self.certs)

    def prune_root(self):
        for i in list(reversed(range(len(self.certs)))):
            print self.certs[i].get_issuer()
            print self.certs[i].get_subject()
            print
            if self.certs[i].get_issuer() == self.certs[i].get_subject():
                self.certs.pop(i)
                return True
        return False

    def get_cert(self,i):
        return self.certs[i]

    def get_all_certs(self):
        return self.certs

    def get_cert(self,i):
        return self.certs[i]


    def prune_not_ca(self):
        from pyasn1.codec.ber import decoder as d
        for i in list(reversed(range(len(self.certs)))):
            for e in range(self.certs[i].get_extension_count()):
                if self.certs[i].get_extension(e).get_short_name() == 'basicConstraints':
                    data = d.decode(self.certs[i].get_extension(e).get_data())[0]
                    ca = False
                    if data:
                        ca = data.getComponentByPosition(0).hasValue()
                    if not ca:
                        print "pruning "+str(self.certs[i].get_subject())
                        self.certs.pop(i)
                        return True
        return False
