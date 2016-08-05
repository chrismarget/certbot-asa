"""PKI stuff"""
import OpenSSL.crypto

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
