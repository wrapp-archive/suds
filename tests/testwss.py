#!/usr/bin/env python

from suds.client import Client
from suds.sax.element import Element
from suds.sax.attribute import Attribute
from suds.wsse.xmlsec import *
from suds.wsse import *
from suds.transport.https import HttpsClientCertAuthenticated
from suds.wsse.pki import *
#from suds.wspolicy import *

def addNone():
    client = Client('http://localhost:8080/SecureCalculatorApp/CalculatorWSService?wsdl')

    #client.set_options(nosend=True)
    #client.set_options(retxml=True)
    
    print client.service.add(2, 2)

def addUsernamePassword():
    client = Client('https://localhost:8181/SecureCalculatorApp/CalculatorWSService?wsdl')
    
    client.options.wsse.tokens[0].username = 'wsitUser'
    client.options.wsse.tokens[0].password = 'changeit'
    
    print client.service.add(3, 3)

def addSslCert():
    client = Client('https://localhost:8181/SecureCalculatorApp/CalculatorWSService?wsdl')

    client.options.transport.keyfile = 'clientkey-nopass.pem'
    client.options.transport.certfile = 'clientcert.pem'

    #client.set_options(nosend=True)
    #client.set_options(retxml=True)
    
    print client.service.add(4, 4)

def addSignedSoapBody():
    client = Client('https://localhost:8181/SecureCalculatorApp/CalculatorWSService?wsdl')

    client.options.wsse.signatures[0].key = RsaPemFilePrivateKey('clientkey-nopass.pem')
    client.options.wsse.signatures[0].cert = X509PemFileCertificate('clientcert.pem')
    #client.options.wsse.signatures[0].digest = DIGEST_SHA256
    #client.options.wsse.signatures[0].signedparts = [lambda env: env.getChild('Header').getChild('Security').getChild('Timestamp')]

    #client.set_options(nosend=True)
    #client.set_options(retxml=True)
    
    print client.service.add(5, 5)

def addUsernamePasswordWithSymmetricKey():
    client = Client('http://localhost:8080/SecureCalculatorApp/CalculatorWSService?wsdl')
    
    client.options.wsse.tokens[0].username = 'wsitUser'
    client.options.wsse.tokens[0].password = 'changeit'
    client.options.wsse.signatures[0].key = RsaPemFilePrivateKey('gfkey-nopass.pem')
    client.options.wsse.signatures[0].cert = X509PemFileCertificate('gfcert.pem')
    client.options.wsse.keys[0].cert = X509PemFileCertificate('gfcert.pem')
    client.options.wsse.keystore = Keystore()
    client.options.wsse.keystore.addCertificate(X509PemFileCertificate('gfcert.pem'))
    
    #client.set_options(nosend=True)
    #client.set_options(prettyxml=True)
    #client.set_options(retxml=True)
    
    print client.service.add(10, 10)

def addSignedAndEncryptedBody():
    client = Client('http://localhost:8080/SecureCalculatorApp/CalculatorWSService?wsdl')

    client.options.wsse.signatures[0].key = RsaPemFilePrivateKey('clientkey-nopass.pem')
    client.options.wsse.signatures[0].cert = X509PemFileCertificate('clientcert.pem')
    client.options.wsse.keys[0].cert = X509PemFileCertificate('servercert.pem')
    client.options.wsse.keystore = Keystore()
    client.options.wsse.keystore.addKey(RsaPemFilePrivateKey('clientkey-nopass.pem'), X509PemFileCertificate('clientcert.pem'))
    #client.options.wsse.keystore.addKey(RsaPemFilePrivateKey('clientkey-nopass.pem'), X509FingerprintKeypairReference('C8A7D4805821C94AE6AA2751C2C42D1C854FC1A0'))
    client.options.wsse.keystore.addCertificate(X509PemFileCertificate('servercert.pem'))

    #client.set_options(nosend=True)
    #client.set_options(prettyxml=True)
    #client.set_options(retxml=True)
    
    print client.service.add(6, 6)

def addWcfSignedAndEncryptedBody():
    client = Client('http://localhost:8080/SecureCalculatorApp/CalculatorWSService?wsdl')
    #client = Client('http://localhost:8000/ServiceModelSamples/service?wsdl')

    client.options.wsse.signatures[0].key = RsaPemFilePrivateKey('gfkey-nopass.pem')
    client.options.wsse.signatures[0].cert = X509PemFileCertificate('gfcert.pem')
    client.options.wsse.signatures[1].key = RsaPemFilePrivateKey('clientkey-nopass.pem')
    client.options.wsse.signatures[1].cert = X509PemFileCertificate('clientcert.pem')
    client.options.wsse.keys[0].cert = X509PemFileCertificate('gfcert.pem')
    client.options.wsse.keystore = Keystore()
    client.options.wsse.keystore.addKey(RsaPemFilePrivateKey('clientkey-nopass.pem'), X509PemFileCertificate('clientcert.pem'))
    #client.options.wsse.keystore.addKey(RsaPemFilePrivateKey('clientkey-nopass.pem'), X509FingerprintKeypairReference('C8A7D4805821C94AE6AA2751C2C42D1C854FC1A0'))
    client.options.wsse.keystore.addCertificate(X509PemFileCertificate('gfcert.pem'))

    #client.set_options(nosend=True)
    #client.set_options(prettyxml=True)
    #client.set_options(retxml=True)
    
    print client.service.add(6, 6)

def addSignedAndEncryptedBodyAndSignature():
    client = Client('http://localhost:8080/SecureCalculatorApp/CalculatorWSService?wsdl')

    security = Security()
    #security.keystore.addKey(RsaPemFilePrivateKey('clientkey-nopass.pem'), X509IssuerSerialKeypairReference('CN=fakeca.com,O=Fake CA,L=Tucson,ST=Arizona,C=US', 2))
    security.keystore.addKey(RsaPemFilePrivateKey('clientkey-nopass.pem'), ('CN=fakeca.com,O=Fake CA,L=Tucson,ST=Arizona,C=US', 2))
    security.keystore.addCertificate(X509PemFileCertificate('servercert.pem'))
    signature = Signature(RsaPemFilePrivateKey('clientkey-nopass.pem'), X509PemFileCertificate('clientcert.pem'))
    signature.signed_parts.append(lambda env: env.getChild('Body'))
    signature.signed_parts.append(lambda env: env.getChild('Header').getChild('Action'))
    signature.signed_parts.append(lambda env: env.getChild('Header').getChild('MessageID'))
    signature.signed_parts.append(lambda env: env.getChild('Header').getChild('Security').getChild('Timestamp'))
    #signature.digest = DIGEST_SHA256
    security.signatures.append(signature)

    key = Key(X509PemFileCertificate('servercert.pem'))
    key.encrypted_parts.append(lambda env: (env.getChild('Body'), 'Content'))
    key.encrypted_parts.append(lambda env: (env.getChild('Header').getChild('Security').getChild('Signature'), 'Element'))
    #key.blockEncryption = BLOCK_ENCRYPTION_AES256_CBC
    #key.keyTransport = KEY_TRANSPORT_RSA_OAEP
    security.keys.append(key)

    client.set_options(wsse=security)
    
    #client.set_options(soapheaders=[Element("foobar")])
    #client.set_options(nosend=True)
    #client.set_options(retxml=True)
    
    print client.service.add(7, 7)

def addMultiplySignedAndMultiplyEncryptedBody():
    client = Client('http://localhost:8080/SecureCalculatorApp/CalculatorWSService?wsdl')

    security = Security()
    security.keystore.addKey(RsaPemFilePrivateKey('clientkey-nopass.pem'), X509IssuerSerialKeypairReference('CN=fakeca.com,O=Fake CA,L=Tucson,ST=Arizona,C=US', 2))
    security.keystore.addCertificate(X509PemFileCertificate('servercert.pem'))

    signature = Signature(RsaPemFilePrivateKey('clientkey-nopass.pem'), X509PemFileCertificate('clientcert.pem'))
    signature.signed_parts.append(lambda env: env.getChild('Body'))
    signature.signed_parts.append(lambda env: env.getChild('Header').getChild('Action'))
    signature.signed_parts.append(lambda env: env.getChild('Header').getChild('MessageID'))
    signature.digest = DIGEST_SHA1
    security.signatures.append(signature)

    signature = Signature(RsaPemFilePrivateKey('clientkey-nopass.pem'), X509PemFileCertificate('clientcert.pem'))
    signature.signed_parts.append(lambda env: env.getChild('Body'))
    signature.digest = DIGEST_SHA1
    security.signatures.append(signature)

    key = Key(X509PemFileCertificate('servercert.pem'))
    key.encrypted_parts.append(lambda env: (env.getChild('Body'), 'Content'))
    key.blockEncryption = BLOCK_ENCRYPTION_AES192_CBC
    key.keyTransport = KEY_TRANSPORT_RSA_OAEP
    security.keys.append(key)

    #key = Key(X509PemFileCertificate('servercert.pem'))
    #key.encrypted_parts.append(lambda env: (env.getChild('Header').getChild('foobar'), 'Element'))
    #key.blockEncryption = BLOCK_ENCRYPTION_AES128_CBC
    #key.keyTransport = KEY_TRANSPORT_RSA_OAEP
    #security.keys.append(key)

    client.set_options(wsse=security)
    
    #client.set_options(soapheaders=[Element("foobar")])
    #client.set_options(nosend=True)
    #client.set_options(retxml=True)
    
    print client.service.add(8, 8)

def addEncryptedAndSignedBody():
    client = Client('http://localhost:8080/SecureCalculatorApp/CalculatorWSService?wsdl')

    security = Security()
    security.keystore.addKey(RsaPemFilePrivateKey('clientkey-nopass.pem'), ('CN=fakeca.com,O=Fake CA,L=Tucson,ST=Arizona,C=US', 2))
    security.keystore.addCertificate(X509PemFileCertificate('servercert.pem'))

    signature = Signature(RsaPemFilePrivateKey('clientkey-nopass.pem'), X509PemFileCertificate('clientcert.pem'))
    signature.signed_parts.append(lambda env: env.getChild('Body'))
    signature.signed_parts.append(lambda env: env.getChild('Header').getChild('Action'))
    signature.signed_parts.append(lambda env: env.getChild('Header').getChild('MessageID'))
    signature.signed_parts.append(lambda env: env.getChild('Header').getChild('Security').getChild('Timestamp'))
    # Metro has a bug where some messages trigger a code path where
    # the digest algorithm is hardcoded to SHA-1.  There's an outside chance
    # this could be a SOAP standard thing, but things like encrypting the
    # signature flip the code path and make it work so I doubt it.
    #signature.digest = DIGEST_SHA256
    security.signatures.append(signature)

    key = Key(X509PemFileCertificate('servercert.pem'))
    key.encrypted_parts.append(lambda env: (env.getChild('Body'), 'Content'))
    key.blockEncryption = BLOCK_ENCRYPTION_AES256_CBC
    key.keyTransport = KEY_TRANSPORT_RSA_OAEP
    security.keys.append(key)

    security.encryptThenSign = True

    client.set_options(wsse=security)
    
    #client.set_options(nosend=True)
    #client.set_options(retxml=True)
    
    print client.service.add(9, 9)

def addWcfNone():
    client = Client('https://bwinxpecd:8001/ServiceModelSamples/service?wsdl')

    #client.set_options(nosend=True)
    #client.set_options(retxml=True)
    
    print client.service.Add(2, 2)

def addWcfUsernamePassword():
    client = Client('https://localhost:8001/ServiceModelSamples/service?wsdl')
    #client.set_options(enforcepolicy=False)
    
    security = Security()
    token = UsernameToken('ecd', '')
    security.tokens.append(token)
    client.set_options(wsse=security)

    print client.service.Add(3, 3)

def addWcfSignedSoapBody():
    client = Client('https://localhost:8001/ServiceModelSamples/service?wsdl')
    #client = Client('https://localhost:8181/SecureCalculatorApp/CalculatorWSService?wsdl')

    security = Security()
    signature = Signature(RsaPemFilePrivateKey('clientkey-nopass.pem'), X509PemFileCertificate('clientcert.pem'))
    #signature.signed_parts.append(lambda env: env.getChild('Header').getChild('To'))
    #signature.signed_parts.append(lambda env: env.getChild('Body'))
    #signature.signed_parts.append(lambda env: env.getChild('Header').getChild('Security').getChild('Timestamp'))
    #signature.digest = DIGEST_SHA1
    #signature.keyReference = KEY_REFERENCE_BINARY_SECURITY_TOKEN
    security.signatures.append(signature)
    client.set_options(wsse=security)
    
    #client.set_options(nosend=True)
    #client.set_options(retxml=True)

    print client.service.add(5, 5)

if __name__ == '__main__':
    addWcfSignedAndEncryptedBody()
