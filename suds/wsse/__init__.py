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
The I{wsse} module provides WS-Security.
"""

from logging import getLogger
from suds import *
from suds.sudsobject import Object
from suds.sax.element import Element
from suds.sax.date import UTC
from datetime import datetime, timedelta
import xmlsec
from pki import Keystore
from options import *

try:
    from hashlib import md5
except ImportError:
    # Python 2.4 compatibility
    from md5 import md5


wssens = \
    ('wsse', 
     'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd')
wsse11ns = \
    ('wsse11', 
     'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd')
wsuns = \
    ('wsu',
     'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd')
envns = ('SOAP-ENV', 'http://schemas.xmlsoap.org/soap/envelope/')

def generate_unique_id(do_not_pass_this=[0]):
    do_not_pass_this[0] = do_not_pass_this[0] + 1
    return do_not_pass_this[0]

class SecurityProcessor:
    def __init__(self):
        self.symmetricKeys = dict()

    def processIncomingMessage(self, soapenv, wsse):
        if soapenv.getChild('Header').getChild('Security') is None:
            return []
        if wsse.encryptThenSign:
            xmlsec.verifyMessage(soapenv, wsse.keystore, self.symmetricKeys)
            decrypted_elements = xmlsec.decryptMessage(soapenv, wsse.keystore, self.symmetricKeys)
            self.removeEncryptedHeaders(soapenv)
        else:
            decrypted_elements = xmlsec.decryptMessage(soapenv, wsse.keystore, self.symmetricKeys)
            self.removeEncryptedHeaders(soapenv)
            xmlsec.verifyMessage(soapenv, wsse.keystore, self.symmetricKeys)

        return decrypted_elements

    def processOutgoingMessage(self, soapenv, wsse):
        soapenv.addPrefix('wsu', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd')
        soapenv.getChild('Header').insert(self.xml(wsse), 0)
        signatures = [Signature(options) for options in wsse.signatures]
        keys = [Key(options) for options in wsse.keys]
        for key in keys:
            self.symmetricKeys[key.cipherValueSha1] = key.symmetricKey.sym_key
        if len(keys) > 0:
            signatures[0].symmetricKey = keys[0].symmetricKey
            signatures[0].encKeyUri = "#" + keys[0].keyId

        if wsse.encryptThenSign:
            self.encryptMessage(soapenv, wsse, keys)
            self.signMessage(soapenv, wsse, signatures)
            self.encryptMessageSecondPass(soapenv, wsse, keys)
        else:
            self.signMessage(soapenv, wsse, signatures)
            self.encryptMessage(soapenv, wsse, keys)
    
    def removeEncryptedHeaders(self, soapenv):
        def removeEncryptedHeaders(elt):
            if not elt.match("EncryptedHeader", ns=wsse11ns):
                return
            id = elt.get("Id", ns=wsuns)
            children = elt.detachChildren()
            elt.parent.replaceChild(elt, children)
            children[0].set("Id", id)

        soapenv.walk(removeEncryptedHeaders)
        
    def signMessage(self, env, wsse, signatures):
        primary_sig = None
        security_header = env.childAtPath('Header/Security')
        insert_position = self.insertPosition(wsse)
        for sig in signatures:
            sig.primary_sig = primary_sig
            token = sig.buildTokens()
            if token is not None:
                security_header.insert(token, insert_position)
                insert_position = insert_position + 1
            security_header.insert(sig.signMessage(env, wsse.signOnlyEntireHeadersAndBody), insert_position)
            insert_position = insert_position + 1
            if primary_sig is None:
                primary_sig = sig.element

    def encryptMessage(self, env, wsse, keys):
        security_header = env.childAtPath('Header/Security')
        insert_position = self.insertPosition(wsse)
        for key in keys:
            new_headers = key.encryptMessage(env, wsse.wsse11)
            security_header.insert(new_headers, insert_position)
            insert_position = insert_position + len(new_headers)

    def encryptMessageSecondPass(self, env, wsse, keys):
        security_header = env.childAtPath('Header/Security')
        insert_position = self.insertPosition(wsse)
        for key in keys:
            new_headers = key.encryptMessage(env, wsse.wsse11, True)
            security_header.insert(new_headers, insert_position)
            insert_position = insert_position + len(new_headers)

    def insertPosition(self, wsse):
        return len(wsse.tokens) + (wsse.includeTimestamp and wsse.headerLayout != HEADER_LAYOUT_LAX_TIMESTAMP_LAST) and 1 or 0

    def xml(self, wsse):
        """
        Get xml representation of the object.
        @return: The root node.
        @rtype: L{Element}
        """
        root = Element('Security', ns=wssens)
        root.set('mustUnderstand', 'true')
        if wsse.includeTimestamp and wsse.headerLayout != HEADER_LAYOUT_LAX_TIMESTAMP_LAST:
            root.append(Timestamp().xml())
        for t in wsse.tokens:
            root.append(UsernameToken(t.username, t.password).xml())
        if wsse.includeTimestamp and wsse.headerLayout == HEADER_LAYOUT_LAX_TIMESTAMP_LAST:
            root.append(Timestamp().xml())
        return root

class Token(Object):
    """ I{Abstract} security token. """
    
    @classmethod
    def now(cls):
        return datetime.now()
    
    @classmethod
    def utc(cls):
        return datetime.utcnow()
    
    @classmethod
    def sysdate(cls):
        utc = UTC()
        return str(utc)
    
    def __init__(self):
            Object.__init__(self)


class UsernameToken(Token):
    """
    Represents a basic I{UsernameToken} WS-Secuirty token.
    @ivar username: A username.
    @type username: str
    @ivar password: A password.
    @type password: str
    @ivar nonce: A set of bytes to prevent reply attacks.
    @type nonce: str
    @ivar created: The token created.
    @type created: L{datetime}
    """

    def __init__(self, username=None, password=None):
        """
        @param username: A username.
        @type username: str
        @param password: A password.
        @type password: str
        """
        Token.__init__(self)
        self.username = username
        self.password = password
        self.nonce = None
        self.created = None
        
    def setnonce(self, text=None):
        """
        Set I{nonce} which is arbitraty set of bytes to prevent
        reply attacks.
        @param text: The nonce text value.
            Generated when I{None}.
        @type text: str
        """
        if text is None:
            s = []
            s.append(self.username)
            s.append(self.password)
            s.append(Token.sysdate())
            m = md5()
            m.update(':'.join(s))
            self.nonce = m.hexdigest()
        else:
            self.nonce = text
        
    def setcreated(self, dt=None):
        """
        Set I{created}.
        @param dt: The created date & time.
            Set as datetime.utc() when I{None}.
        @type dt: L{datetime}
        """
        if dt is None:
            self.created = Token.utc()
        else:
            self.created = dt
        
        
    def xml(self):
        """
        Get xml representation of the object.
        @return: The root node.
        @rtype: L{Element}
        """
        root = Element('UsernameToken', ns=wssens)
        u = Element('Username', ns=wssens)
        u.setText(self.username)
        root.append(u)
        p = Element('Password', ns=wssens)
        p.setText(self.password)
        root.append(p)
        if self.nonce is not None:
            n = Element('Nonce', ns=wssens)
            n.setText(self.nonce)
            root.append(n)
        if self.created is not None:
            n = Element('Created', ns=wsuns)
            n.setText(str(UTC(self.created)))
            root.append(n)
        return root


class Timestamp(Token):
    """
    Represents the I{Timestamp} WS-Secuirty token.
    @ivar created: The token created.
    @type created: L{datetime}
    @ivar expires: The token expires.
    @type expires: L{datetime}
    """

    def __init__(self, validity=90):
        """
        @param validity: The time in seconds.
        @type validity: int
        """
        Token.__init__(self)
        self.created = Token.utc()
        self.expires = self.created + timedelta(seconds=validity)
        
    def xml(self):
        root = Element("Timestamp", ns=wsuns)
        # xsd:datetime format does not have fractional seconds
        created = Element('Created', ns=wsuns)
        created.setText(str(UTC(self.created - timedelta(microseconds=self.created.microsecond))))
        expires = Element('Expires', ns=wsuns)
        expires.setText(str(UTC(self.expires - timedelta(microseconds=self.expires.microsecond))))
        root.append(created)
        root.append(expires)
        return root

class Signature(Object):
    def buildTokens(self):
        self.token = None
        self.bst_id = None
        if self.keyReference == xmlsec.KEY_REFERENCE_BINARY_SECURITY_TOKEN:
            self.token = Element("BinarySecurityToken", ns=wssens)
            self.token.setText(self.x509_issuer_serial.getCertificateText())
            self.token.set("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
            self.token.set("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
            bst_id = "BSTID-" + str(generate_unique_id())
            self.token.set("wsu:Id", bst_id)
            self.bst_id = "#" + bst_id
        elif self.keyReference == xmlsec.KEY_REFERENCE_ENCRYPTED_KEY:
            self.bst_id = self.encKeyUri
        return self.token

    def signMessage(self, env, signOnlyEntireHeadersAndBody):
        elements_to_digest = []
        
        for elements_to_digest_func in self.signed_parts:
            addl_elements = elements_to_digest_func(env, self)
            if addl_elements is None:
                continue
            if not isinstance(addl_elements, list):
                addl_elements = [addl_elements]
            for element in addl_elements:
                if element not in elements_to_digest:
                    elements_to_digest.append(element)

        if signOnlyEntireHeadersAndBody:
            self.verifyOnlyEntireHeadersAndBody(elements_to_digest)

        if self.signatureAlgorithm == SIGNATURE_RSA_SHA1:
            key = self.key
        elif self.signatureAlgorithm == SIGNATURE_HMAC_SHA1:
            key = self.symmetricKey.sym_key

        sig = xmlsec.signMessage(key, self.x509_issuer_serial, elements_to_digest, self.keyReference, self.digest, self.signatureAlgorithm, self.bst_id)
        self.element = sig
        return sig

    def verifyOnlyEntireHeadersAndBody(self, elements_to_digest):
        for element in elements_to_digest:
            if element.match('Body') or element.parent.match('Header') or element.parent.match('Security'):
                continue
            raise Exception, 'A descendant of a header or the body was signed, but only entire headers and body were permitted to be signed'

    def __init__(self, options, sym_key=None):
        Object.__init__(self)
        self.key = options.key
        self.x509_issuer_serial = options.cert
        self.signed_parts = options.signedparts
        self.digest = options.digest
        self.keyReference = options.keyreference
        self.signatureAlgorithm = options.signaturealgorithm
        self.symmetricKey = sym_key

class Key(Object):
    def buildEncryptedKey(self):
        self.keyId = "EncKeyId-" + str(generate_unique_id())
        (self.encryptedKey, self.cipherValueSha1) = buildEncryptedKey(self.keyId, self.cert, self.symmetricKey.sym_key, self.keyReference, self.blockEncryption, self.keyTransport)

    def encryptMessage(self, env, use_encrypted_header=False, second_pass=False):
        encrypted_parts = second_pass and self.second_pass_encrypted_parts or self.encrypted_parts
        elements_to_encrypt = []
        encrypted_headers = []
        
        for elements_to_encrypt_func in encrypted_parts:
            addl_elements = elements_to_encrypt_func(env)
            if addl_elements[0] is None:
                continue
            if not isinstance(addl_elements[0], list):
                addl_elements = ([addl_elements[0]], addl_elements[1])
            for element in addl_elements[0]:
                if element not in elements_to_encrypt:
                    if element[0].parent.match('Header') and use_encrypted_header:
                        enc_hdr = Element('EncryptedHeader', ns=wsse11ns)
                        element[0].parent.replaceChild(element[0], enc_hdr)
                        enc_hdr.append(element[0])
                        elements_to_encrypt.append((enc_hdr, 'Content'))
                        encrypted_headers.append(enc_hdr)
                    else:
                        elements_to_encrypt.append((element, addl_elements[1]))

        ref_list = xmlsec.encryptMessage(self.cert, self.symmetricKey, elements_to_encrypt, '#' + self.keyId, self.keyReference, self.keyTransport)

        for enc_hdr in encrypted_headers:
            enc_hdr.set('wsu:Id', enc_hdr[0].get('Id'))
            enc_hdr[0].unset('Id')
        if False:
            self.encryptedKey.append(ref_list)
            return self.encryptedKey
        else:
            return (self.encryptedKey, ref_list)
        
    def __init__(self, options):
        Object.__init__(self)
        self.cert = options.cert
        self.encrypted_parts = options.encryptedparts
        self.second_pass_encrypted_parts = options.secondpassencryptedparts
        self.blockEncryption = options.blockencryption
        self.keyTransport = options.keytransport 
        self.keyReference = options.keyreference
        self.symmetricKey = buildSymmetricKey(self.blockEncryption)
        self.buildEncryptedKey()
