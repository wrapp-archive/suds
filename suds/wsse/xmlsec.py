# This program is free software; you can redistribute it and/or modify
# it under the terms of the (LGPL) GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of the 
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library Lesser General Public License for more details at
# ( http://www.gnu.org/licenses/lgpl.html ).
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# written by: Jeff Ortel ( jortel@redhat.com )

"""
The I{xmlsec} module provides XML Encryption and XML Digital Signature functionality.
"""

from suds.sax.element import Element
from suds.sax.parser import Parser
from pki import *
from base64 import b64encode,b64decode
from M2Crypto import *
import random
import hashlib

dsns = \
    ('ds',
     'http://www.w3.org/2000/09/xmldsig#')
wssens = \
    ('wsse', 
     'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd')
wsuns = \
    ('wsu',
     'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd')
wsencns = \
    ('wsenc',
     'http://www.w3.org/2001/04/xmlenc#')

DIGEST_SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1'
DIGEST_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256'
DIGEST_SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512'
DIGEST_RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160'

digestProperties = dict()
digestProperties[DIGEST_SHA1] = {
    'uri': DIGEST_SHA1,
    'hashlib_alg': 'sha1'}
digestProperties[DIGEST_SHA256] = {
    'uri': DIGEST_SHA256,
    'hashlib_alg': 'sha256'}
digestProperties[DIGEST_SHA512] = {
    'uri': DIGEST_SHA512,
    'hashlib_alg': 'sha512'}
digestProperties[DIGEST_RIPEMD160] = {
    'uri': DIGEST_RIPEMD160,
    'hashlib_alg': 'ripemd160'}

BLOCK_ENCRYPTION_AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
BLOCK_ENCRYPTION_AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc'
BLOCK_ENCRYPTION_AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
BLOCK_ENCRYPTION_3DES_CBC = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc'

blockEncryptionProperties = dict()
blockEncryptionProperties[BLOCK_ENCRYPTION_AES128_CBC] = {
    'uri': BLOCK_ENCRYPTION_AES128_CBC,
    'openssl_cipher': 'aes_128_cbc',
    'key_size': 16,
    'block_size': 16,
    'iv_size': 16}
blockEncryptionProperties[BLOCK_ENCRYPTION_AES192_CBC] = {
    'uri': BLOCK_ENCRYPTION_AES192_CBC,
    'openssl_cipher': 'aes_192_cbc',
    'key_size': 24,
    'block_size': 16,
    'iv_size': 16}
blockEncryptionProperties[BLOCK_ENCRYPTION_AES256_CBC] = {
    'uri': BLOCK_ENCRYPTION_AES256_CBC,
    'openssl_cipher': 'aes_256_cbc',
    'key_size': 32,
    'block_size': 16,
    'iv_size': 16}
blockEncryptionProperties[BLOCK_ENCRYPTION_3DES_CBC] =  {
    'uri': BLOCK_ENCRYPTION_3DES_CBC,
    'openssl_cipher': 'des_ede3_cbc',
    'key_size': 24,
    'block_size': 8,
    'iv_size': 8}

KEY_TRANSPORT_RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5'
KEY_TRANSPORT_RSA_OAEP = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'

keyTransportProperties = dict()
keyTransportProperties[KEY_TRANSPORT_RSA_1_5] = {
    'uri': KEY_TRANSPORT_RSA_1_5,
    'padding': RSA.pkcs1_padding}
keyTransportProperties[KEY_TRANSPORT_RSA_OAEP] = {
    'uri': KEY_TRANSPORT_RSA_OAEP,
    'padding': RSA.pkcs1_oaep_padding}

KEY_REFERENCE_ISSUER_SERIAL = 'IssuerSerial'
KEY_REFERENCE_FINGERPRINT = 'Fingerprint'
KEY_REFERENCE_BINARY_SECURITY_TOKEN = 'BinarySecurityToken'

random = random.SystemRandom()

def generate_unique_id(do_not_pass_this=[0]):
    do_not_pass_this[0] = do_not_pass_this[0] + 1
    return do_not_pass_this[0]

def build_key_info(cert, reference_type, bst_id=None):
    key_info = Element("KeyInfo", ns=dsns)
    sec_token_ref = Element("SecurityTokenReference", ns=wssens)
    if reference_type == KEY_REFERENCE_ISSUER_SERIAL:
        x509_data = Element("X509Data", ns=dsns)
        issuer_serial = Element("X509IssuerSerial", ns=dsns)
        issuer_name = Element("X509IssuerName", ns=dsns)
        issuer_name.setText(cert.getX509IssuerSerial().getIssuer())
        serial_number = Element("X509SerialNumber", ns=dsns)
        serial_number.setText(cert.getX509IssuerSerial().getSerial())
        issuer_serial.append(issuer_name)
        issuer_serial.append(serial_number)
        x509_data.append(issuer_serial)
        sec_token_ref.append(x509_data)
    elif reference_type == KEY_REFERENCE_FINGERPRINT:
        key_ident = Element("KeyIdentifier", ns=wssens)
        key_ident.set("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
        key_ident.set("ValueType", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1")
        key_ident.setText(b64encode(cert.getSHA1Fingerprint().getFingerprint().decode('hex')))
        sec_token_ref.append(key_ident)
    elif reference_type == KEY_REFERENCE_BINARY_SECURITY_TOKEN:
        reference = Element("Reference", ns=wssens)
        reference.set("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
        reference.set("URI", "#" + bst_id)
        sec_token_ref.append(reference)
    key_info.append(sec_token_ref)
    
    return key_info

def signMessage(key, ref, elements_to_digest, reference_type=KEY_REFERENCE_ISSUER_SERIAL, digest_algorithm=DIGEST_SHA1, bst_id=None):
    sig = Element("Signature", ns=dsns)

    signed_info = Element("SignedInfo", ns=dsns)
    canon_method = Element("CanonicalizationMethod", ns=dsns)
    canon_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
    sig_method = Element("SignatureMethod", ns=dsns)
    sig_method.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
    signed_info.append(canon_method)
    signed_info.append(sig_method)

    sig_value = Element("SignatureValue", ns=dsns)

    key_info = build_key_info(ref, reference_type, bst_id)
    
    sig.append(signed_info)
    sig.append(sig_value)
    sig.append(key_info)

    for element_to_digest in elements_to_digest:
        reference = Element("Reference", ns=dsns)
        transforms = Element("Transforms", ns=dsns)
        transform = Element("Transform", ns=dsns)
        transform.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
        transforms.append(transform)
        digest_method = Element("DigestMethod", ns=dsns)
        digest_method.set("Algorithm", digestProperties[digest_algorithm]['uri'])
        digest_value = Element("DigestValue", ns=dsns)
        reference.append(transforms)
        reference.append(digest_method)
        reference.append(digest_value)
        signed_info.append(reference)        

        if element_to_digest.get('wsu:Id'):
            element_id = element_to_digest.get('wsu:Id')
        else:
            element_id = "id-" + str(generate_unique_id())
            element_to_digest.set('wsu:Id', element_id)
        reference.set("URI", "#" + element_id)
        element_content = element_to_digest.canonical()
        digest_props = digestProperties[digest_algorithm]
        hash = hashlib.new(digest_props['hashlib_alg'])
        hash.update(element_content)
        digest_value.setText(b64encode(hash.digest()))

    element_to_sign = signed_info
    element_content = element_to_sign.canonical()
    priv_key = key.getEvpPrivateKey()
    priv_key.sign_init()
    priv_key.sign_update(element_content.encode("utf-8"))
    signed_digest = priv_key.sign_final()
    sig_value.setText(b64encode(signed_digest))
    
    return sig

def verifyMessage(env, keystore):
    signed_data_blocks = dict()
    
    def collectSignedDataBlock(elt):
        if not elt.get("Id", ns=wsuns):
            return
        
        signed_data_blocks[elt.get("Id", ns=wsuns)] = elt

    env.walk(collectSignedDataBlock)
    for sig_elt in env.getChild("Header").getChild("Security").getChildren("Signature", ns=dsns):
        prefix_list = []
        if sig_elt.getChild("SignedInfo", ns=dsns).getChild("CanonicalizationMethod").get("Algorithm") == "http://www.w3.org/2001/10/xml-exc-c14n#":
            prefix_list=[]
            if sig_elt.getChild("SignedInfo", ns=dsns).getChild("CanonicalizationMethod").getChild("InclusiveNamespaces") is not None:
                prefix_list = sig_elt.getChild("SignedInfo", ns=dsns).getChild("CanonicalizationMethod").getChild("InclusiveNamespaces").get("PrefixList").split(" ")
        signed_content = sig_elt.getChild("SignedInfo", ns=dsns).canonical(prefix_list)
        signature = b64decode(sig_elt.getChild("SignatureValue", ns=dsns).getText())
        sec_token_reference = sig_elt.getChild("KeyInfo").getChild("SecurityTokenReference")
        if sec_token_reference.getChild("X509Data") is not None:
            x509_issuer_serial_elt = sec_token_reference.getChild("X509Data").getChild("X509IssuerSerial")
            reference = X509IssuerSerialKeypairReference(x509_issuer_serial_elt.getChild("X509IssuerName").getText(), int(x509_issuer_serial_elt.getChild("X509SerialNumber").getText()))
            pub_key = keystore.lookup(reference).getEvpPublicKey()
        elif sec_token_reference.getChild("KeyIdentifier") is not None and sec_token_reference.getChild("KeyIdentifier").get("ValueType") == 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1':
            fingerprint = b64decode(sec_token_reference.getChild("KeyIdentifier").getText())
            reference = X509FingerprintKeypairReference(fingerprint.encode('hex'), 'sha1')
            pub_key = keystore.lookup(reference).getEvpPublicKey()
        elif sec_token_reference.getChild("KeyIdentifier") is not None and sec_token_reference.getChild("KeyIdentifier").get("ValueType") == 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier':
            ski = b64decode(sec_token_reference.getChild("KeyIdentifier").getText())
            reference = X509SubjectKeyIdentifierKeypairReference(ski.encode('hex'))
            pub_key = keystore.lookup(reference).getEvpPublicKey()
        elif sec_token_reference.getChild("Reference") is not None and sec_token_reference.getChild("Reference").get("ValueType") == 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3':
            bst_id = sec_token_reference.getChild("Reference").get("URI")
            if not bst_id[0] == "#":
                raise Exception, "Cannot handle non-local BinarySecurityToken references"
            cert_as_der = b64decode(signed_data_blocks[bst_id[1:]].getText())
            pub_key = X509.load_cert_der_string(cert_as_der).get_pubkey()
        else:
            raise Exception, 'Response contained unrecognized SecurityTokenReference'
        pub_key.reset_context(md='sha1')
        pub_key.verify_init()
        pub_key.verify_update(signed_content.encode("utf-8"))
        if pub_key.verify_final(signature) == 0:
            raise Exception, "signature failed verification"
        for signed_part in sig_elt.getChild("SignedInfo", ns=dsns).getChildren("Reference", ns=dsns):
            enclosed_digest = b64decode(signed_part.getChild("DigestValue", ns=dsns).getText())
            signed_part_id = signed_part.get("URI")

            if not signed_part_id[0] == "#":
                raise Exception, "Cannot handle non-local data references"
            prefix_list = []
            for transform in signed_part.getChild("Transforms", ns=dsns).getChildren("Transform", ns=dsns):
                if transform.get("Algorithm") == "http://www.w3.org/2001/10/xml-exc-c14n#":
                    prefix_list=[]
                    if sig_elt.getChild("SignedInfo", ns=dsns).getChild("CanonicalizationMethod").getChild("InclusiveNamespaces") is not None:
                        prefix_list = sig_elt.getChild("SignedInfo", ns=dsns).getChild("CanonicalizationMethod").getChild("InclusiveNamespaces").get("PrefixList").split(" ")
            element_digested = signed_data_blocks[signed_part_id[1:]]
            element_content = element_digested.canonical(prefix_list)
            digest_props = digestProperties[signed_part.getChild("DigestMethod").get("Algorithm")]
            hash = hashlib.new(digest_props['hashlib_alg'])
            hash.update(element_content)
            if hash.digest() <> enclosed_digest:
                raise Exception, "digest for section with id " + signed_part_id[1:] + " failed verification"

def encryptMessage(cert, elements_to_encrypt, reference_type=KEY_REFERENCE_ISSUER_SERIAL, key_transport=KEY_TRANSPORT_RSA_OAEP, block_encryption=BLOCK_ENCRYPTION_AES128_CBC):
    enc_key = Element("EncryptedKey", ns=wsencns)
    key_id = "EncKeyId-" + str(generate_unique_id())
    enc_key.set("Id", key_id)
    enc_method = Element("EncryptionMethod", ns=wsencns)
    enc_method.set("Algorithm", keyTransportProperties[key_transport]['uri'])
    key_info = build_key_info(cert, reference_type)
    
    cipher_data = Element("CipherData", ns=wsencns)
    cipher_value = Element("CipherValue", ns=wsencns)
    block_encryption_props = blockEncryptionProperties[block_encryption]
    sym_key = bytearray([random.getrandbits(8) for i in range(0, block_encryption_props['key_size'])])
    iv = bytearray([random.getrandbits(8) for i in range(0, block_encryption_props['iv_size'])])
    pub_key = cert.getRsaPublicKey()
    enc_sym_key = pub_key.public_encrypt(sym_key, keyTransportProperties[key_transport]['padding'])
    cipher_value.setText(b64encode(enc_sym_key))
    cipher_data.append(cipher_value)
    
    reference_list = Element("ReferenceList", ns=wsencns)
    
    enc_key.append(enc_method)
    enc_key.append(key_info)
    enc_key.append(cipher_data)
    enc_key.append(reference_list)

    for (element_to_encrypt, type) in elements_to_encrypt:
        reference = Element("DataReference", ns=wsencns)
        id = "EncDataId-" + str(generate_unique_id())
        reference.set("URI", '#' + id)
        reference_list.append(reference)

        element_content = element_to_encrypt.canonical()
        if type == 'Content':
            element_content = element_content[element_content.index(">") + 1:element_content.rindex("<")]
        enc_data = Element("EncryptedData", ns=wsencns)
        enc_data.set("Id", id)
        enc_data.set("Type", "http://www.w3.org/2001/04/xmlenc#" + type)
        
        block_encryption_props = blockEncryptionProperties[block_encryption]
        enc_method = Element("EncryptionMethod", ns=wsencns)
        enc_method.set("Algorithm", block_encryption_props['uri'])
        
        key_info = Element("KeyInfo", ns=dsns)
        sec_token_ref = Element("SecurityTokenReference", ns=wssens)
        wsse_reference = Element("Reference", ns=wssens)
        wsse_reference.set("URI", "#" + key_id)
        sec_token_ref.append(wsse_reference)
        key_info.append(sec_token_ref)
        
        cipher_data = Element("CipherData", ns=wsencns)
        cipher_value = Element("CipherValue", ns=wsencns)
        cipher = EVP.Cipher(alg=blockEncryptionProperties[block_encryption]['openssl_cipher'], key=sym_key, iv=iv, op=1, padding=0)
        pad_bytes = block_encryption_props['block_size'] - len(element_content) % block_encryption_props['block_size']
        element_content = element_content + ' ' * (pad_bytes - 1) + chr(pad_bytes)
        enc_content = cipher.update(element_content.encode("utf-8"))
        enc_content = enc_content + cipher.final()
        enc_content = iv + enc_content
        cipher_value.setText(b64encode(enc_content))
        cipher_data.append(cipher_value)

        enc_data.append(enc_method)
        enc_data.append(key_info)
        enc_data.append(cipher_data)
        
        if type == 'Element':
            element_to_encrypt.parent.replaceChild(element_to_encrypt, enc_data)
        elif type == 'Content':
            element_to_encrypt.setText('')
            for child in element_to_encrypt.children:
                element_to_encrypt.remove(child)
            element_to_encrypt.append(enc_data)
    
    return enc_key

def decryptMessage(env, keystore):
    enc_data_blocks = dict()
    
    def collectEncryptedDataBlock(elt):
        if not elt.match("EncryptedData", ns=wsencns):
            return
        
        enc_data_blocks[elt.get("Id")] = elt

    env.walk(collectEncryptedDataBlock)
    for key_elt in env.getChild("Header").getChild("Security").getChildren("EncryptedKey", ns=wsencns):
        key_transport_method = key_elt.getChild("EncryptionMethod").get("Algorithm")
        key_transport_props = keyTransportProperties[key_transport_method]
        enc_key = b64decode(key_elt.getChild("CipherData").getChild("CipherValue").getText())
        sec_token_reference = key_elt.getChild("KeyInfo").getChild("SecurityTokenReference")
        if sec_token_reference.getChild("X509Data") is not None:
            x509_issuer_serial_elt = sec_token_reference.getChild("X509Data").getChild("X509IssuerSerial")
            reference = X509IssuerSerialKeypairReference(x509_issuer_serial_elt.getChild("X509IssuerName").getText(), int(x509_issuer_serial_elt.getChild("X509SerialNumber").getText()))
        elif sec_token_reference.getChild("KeyIdentifier") is not None and sec_token_reference.getChild("KeyIdentifier").get("ValueType") == 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1':
            fingerprint = b64decode(sec_token_reference.getChild("KeyIdentifier").getText())
            reference = X509FingerprintKeypairReference(fingerprint.encode('hex'), 'sha1')
        elif sec_token_reference.getChild("KeyIdentifier") is not None and sec_token_reference.getChild("KeyIdentifier").get("ValueType") == 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier':
            ski = b64decode(sec_token_reference.getChild("KeyIdentifier").getText())
            reference = X509SubjectKeyIdentifierKeypairReference(ski.encode('hex'))
        else:
            raise Exception, 'Response contained unrecognized SecurityTokenReference'
        priv_key = keystore.lookup(reference).getRsaPrivateKey()
        sym_key = priv_key.private_decrypt(enc_key, key_transport_props['padding'])
        for data_block_id in [c.get("URI") for c in key_elt.getChild("ReferenceList").getChildren("DataReference")]:
            if not data_block_id[0] == "#":
                raise Exception, "Cannot handle non-local data references"
            data_block = enc_data_blocks[data_block_id[1:]]
            block_encryption_props = blockEncryptionProperties[data_block.getChild("EncryptionMethod").get("Algorithm")]
            enc_content = b64decode(data_block.getChild("CipherData").getChild("CipherValue").getText())
            iv = enc_content[:block_encryption_props['iv_size']]
            enc_content = enc_content[block_encryption_props['iv_size']:]
            cipher = EVP.Cipher(alg=block_encryption_props['openssl_cipher'], key=sym_key, iv=iv, op=0, padding=0)
            content = cipher.update(enc_content)
            content = content + cipher.final()
            content = content[:-ord(content[-1])]
            sax = Parser()
            decrypted_element = sax.parse(string=content)
            data_block.parent.replaceChild(data_block, decrypted_element.getChildren())
