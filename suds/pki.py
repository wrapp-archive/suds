from M2Crypto import *
import string

class X509IssuerSerialKeypairReference:
    def __init__(self, issuer, serial):
        self.issuer = self.normalize_serial(issuer)
        self.serial = serial
    
    def getIssuer(self):
        return self.issuer
    
    def getSerial(self):
        return self.serial
    
    def __hash__(self):
        return 17 * self.issuer.__hash__() + 23 * self.serial.__hash__()
    
    def __eq__(self, other):
        return self.issuer == other.getIssuer() and self.serial == other.getSerial()

    def normalize_serial(self, issuer):
        return ','.join(map(string.lstrip, issuer.split(',')))

class X509FingerprintKeypairReference:
    def __init__(self, fingerprint, algorithm):
        self.fingerprint = fingerprint
        self.algorithm = algorithm
    
    def getFingerprint(self):
        return self.fingerprint
    
    def getAlgorithm(self):
        return self.algorithm
    
    def __hash__(self):
        return 17 * self.fingerprint.__hash__() + 23 * self.algorithm.__hash__()
    
    def __eq__(self, other):
        return self.fingerprint == other.getFingerprint() and self.algorithm == other.getAlgorithm()

class X509PemFileCertificate:
    def __init__(self, pem_file_name):
        self.x509_cert = X509.load_cert(pem_file_name, X509.FORMAT_PEM)
        self.x509_issuer_serial = self.build_x509_issuer_serial(self.x509_cert)
        self.md5fingerprint = X509FingerprintKeypairReference(self.x509_cert.get_fingerprint('md5'), 'md5')
        self.sha1fingerprint = X509FingerprintKeypairReference(self.x509_cert.get_fingerprint('sha1'), 'sha1')

    def getX509IssuerSerial(self):
        return self.x509_issuer_serial

    def getMD5Fingerprint(self):
        return self.md5fingerprint
    
    def getSHA1Fingerprint(self):
        return self.sha1fingerprint
    
    def getIssuer(self):
        return self.x509_issuer_serial.getIssuer()
    
    def getSerial(self):
        return self.x509_issuer_serial.getSerial()
    
    def getRsaPublicKey(self):
        return self.x509_cert.get_pubkey().get_rsa()
        
    def getEvpPublicKey(self):
        return self.x509_cert.get_pubkey()
    
    def getReferences(self):
        return [self.x509_issuer_serial, self.md5fingerprint, self.sha1fingerprint]
    
    def build_x509_issuer_serial(self, x509_cert):
        x509_cert_issuer = x509_cert.get_issuer()
        issuer_name_list = []
        x509_cert_issuer.CN and issuer_name_list.append("CN=%s" % x509_cert_issuer.CN)
        x509_cert_issuer.OU and issuer_name_list.append("OU=%s" % x509_cert_issuer.OU)
        x509_cert_issuer.O and issuer_name_list.append("O=%s" % x509_cert_issuer.O)
        x509_cert_issuer.L and issuer_name_list.append("L=%s" % x509_cert_issuer.L)
        x509_cert_issuer.ST and issuer_name_list.append("ST=%s" % x509_cert_issuer.ST)
        x509_cert_issuer.C and issuer_name_list.append("C=%s" % x509_cert_issuer.C)
        return X509IssuerSerialKeypairReference(','.join(issuer_name_list), x509_cert.get_serial_number())

class RsaPemFilePrivateKey:
    def __init__(self, pem_file_name):
        self.key = EVP.load_key(pem_file_name)
        self.rsakey = RSA.load_key(pem_file_name)
    
    def getEvpPrivateKey(self):
        return self.key
    
    def getRsaPrivateKey(self):
        return self.rsakey

class Keystore:
    def __init__(self):
        self.keystore = dict()
    
    def addKey(self, key, reference):
        self.keystore[reference] = key
    
    def addCertificate(self, cert):
        for reference in cert.getReferences():
            self.keystore[reference] = cert
    
    def lookup(self, reference):
        return self.keystore[reference]
