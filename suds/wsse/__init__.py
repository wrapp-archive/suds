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
    def processIncomingMessage(self, soapenv, wsse):
        if soapenv.getChild('Header').getChild('Security') is None:
            return
        if wsse.encryptThenSign:
            xmlsec.verifyMessage(soapenv, wsse.keystore)
            xmlsec.decryptMessage(soapenv, wsse.keystore)
            self.removeEncryptedHeaders(soapenv)
        else:
            xmlsec.decryptMessage(soapenv, wsse.keystore)
            self.removeEncryptedHeaders(soapenv)
            xmlsec.verifyMessage(soapenv, wsse.keystore)

    def processOutgoingMessage(self, soapenv, wsse):
        soapenv.addPrefix('wsu', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd')
        soapenv.getChild('Header').insert(self.xml(wsse), 0)
        if wsse.encryptThenSign:
            self.encryptMessage(soapenv, wsse)
            self.signMessage(soapenv, wsse)
        else:
            self.signMessage(soapenv, wsse)
            self.encryptMessage(soapenv, wsse)
    
    def removeEncryptedHeaders(self, soapenv):
        def removeEncryptedHeaders(elt):
            if not elt.match("EncryptedHeader", ns=wsse11ns):
                return
            id = elt.get("Id", ns=wsuns)
            children = elt.detachChildren()
            elt.parent.replaceChild(elt, children)
            children[0].set("Id", id)

        soapenv.walk(removeEncryptedHeaders)
        
    def signMessage(self, env, wsse):
        env.getChild('Header').getChild('Security').insert(reduce(lambda x,y: x + y.signMessage(env, wsse.signOnlyEntireHeadersAndBody), wsse.signatures, []), self.insertPosition(wsse))

    def encryptMessage(self, env, wsse):
        env.getChild('Header').getChild('Security').insert([k.encryptMessage(env, wsse.wsse11) for k in wsse.keys], self.insertPosition(wsse))

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
            root.append(t.xml())
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
    def signMessage(self, env, signOnlyEntireHeadersAndBody):
        elements_to_digest = []
        
        for elements_to_digest_func in self.signed_parts:
            addl_elements = elements_to_digest_func(env)
            if addl_elements is None:
                continue
            if not isinstance(addl_elements, list):
                addl_elements = [addl_elements]
            for element in addl_elements:
                if element not in elements_to_digest:
                    elements_to_digest.append(element)

        if signOnlyEntireHeadersAndBody:
            self.verifyOnlyEntireHeadersAndBody(elements_to_digest)

        bst_id = None
        bst = None
        if self.keyReference == xmlsec.KEY_REFERENCE_BINARY_SECURITY_TOKEN:
            bst = Element("BinarySecurityToken", ns=wssens)
            bst.setText(self.x509_issuer_serial.getCertificateText())
            bst.set("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
            bst.set("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
            bst_id = "BSTID-" + str(generate_unique_id())
            bst.set("wsu:Id", bst_id)

        sig = xmlsec.signMessage(self.key, self.x509_issuer_serial, elements_to_digest, self.keyReference, self.digest, bst_id)
        if bst is not None:
            return [bst, sig]
        else:
            return [sig]

    def verifyOnlyEntireHeadersAndBody(self, elements_to_digest):
        for element in elements_to_digest:
            if element.match('Body') or element.parent.match('Header') or element.parent.match('Security'):
                continue
            raise Exception, 'A descendant of a header or the body was signed, but only entire headers and body were permitted to be signed'

    def __init__(self, key, x509_issuer_serial):
        Object.__init__(self)
        self.key = key
        self.x509_issuer_serial = x509_issuer_serial
        self.signed_parts = []
        self.digest = xmlsec.DIGEST_SHA1
        self.keyReference = xmlsec.KEY_REFERENCE_BINARY_SECURITY_TOKEN

class Key(Object):
    def encryptMessage(self, env, use_encrypted_header=False):
        elements_to_encrypt = []
        encrypted_headers = []
        
        for elements_to_encrypt_func in self.encrypted_parts:
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

        key = xmlsec.encryptMessage(self.cert, elements_to_encrypt, self.keyReference, self.keyTransport, self.blockEncryption)

        for enc_hdr in encrypted_headers:
            enc_hdr.set('wsu:Id', enc_hdr[0].get('Id'))
            enc_hdr[0].unset('Id')
        return key
        
    def __init__(self, cert):
        Object.__init__(self)
        self.cert = cert
        self.encrypted_parts = []
        self.blockEncryption = xmlsec.BLOCK_ENCRYPTION_AES128_CBC
        self.keyTransport = xmlsec.KEY_TRANSPORT_RSA_OAEP
        self.keyReference = xmlsec.KEY_REFERENCE_ISSUER_SERIAL
