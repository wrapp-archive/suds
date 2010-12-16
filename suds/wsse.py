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
from hashlib import sha1
from base64 import b64encode
from M2Crypto import *

try:
    from hashlib import md5
except ImportError:
    # Python 2.4 compatibility
    from md5 import md5


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

def build_key_info(cert):
    key_info = Element("KeyInfo", ns=dsns)
    sec_token_ref = Element("SecurityTokenReference", ns=wssens)
    x509_data = Element("X509Data", ns=dsns)
    issuer_serial = Element("X509IssuerSerial", ns=dsns)
    x509_cert = X509.load_cert(cert, X509.FORMAT_PEM)
    x509_cert_issuer = x509_cert.get_issuer()
    issuer_name = Element("X509IssuerName", ns=dsns)
    issuer_name.setText("CN=%s,O=%s,L=%s,ST=%s,C=%s" % (x509_cert_issuer.CN,
        x509_cert_issuer.O,
        x509_cert_issuer.L,
        x509_cert_issuer.ST,
        x509_cert_issuer.C))
    serial_number = Element("X509SerialNumber", ns=dsns)
    serial_number.setText(x509_cert.get_serial_number())
    issuer_serial.append(issuer_name)
    issuer_serial.append(serial_number)
    x509_data.append(issuer_serial)
    sec_token_ref.append(x509_data)
    key_info.append(sec_token_ref)
    
    return key_info

class Security(Object):
    """
    WS-Security object.
    @ivar tokens: A list of security tokens
    @type tokens: [L{Token},...]
    @ivar signatures: A list of signatures.
    @type signatures: TBD
    @ivar references: A list of references.
    @type references: TBD
    @ivar keys: A list of encryption keys.
    @type keys: TBD
    """
    
    def __init__(self):
        """ """
        Object.__init__(self)
        self.mustUnderstand = True
        self.tokens = []
        self.signatures = []
        self.references = []
        self.keys = []
        
    def signMessage(self, env):
        for s in self.signatures:
            s.signMessage(env)
        
    def xml(self):
        """
        Get xml representation of the object.
        @return: The root node.
        @rtype: L{Element}
        """
        root = Element('Security', ns=wssens)
        root.set('mustUnderstand', str(self.mustUnderstand).lower())
        for t in self.tokens:
            root.append(t.xml())
        for s in self.signatures:
		    root.append(s.xml())
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
        created = Element('Created', ns=wsuns)
        created.setText(str(UTC(self.created)))
        expires = Element('Expires', ns=wsuns)
        expires.setText(str(UTC(self.expires)))
        root.append(created)
        root.append(expires)
        return root

class Signature(Object):
    def signMessage(self, env):
        id_index = 1
        for (element_to_store_digest, element_to_digest_func) in self.digest_elements:
            element_to_digest = element_to_digest_func(env)
            element_to_digest.set('wsu:Id', 'id-' + str(id_index))
            id_index = id_index + 1
            detached_element = element_to_digest.clone(None)
            element_content = detached_element.canonical()
            hash = sha1()
            hash.update(element_content)
            element_to_store_digest.setText(b64encode(hash.digest()))
        for (element_to_store_signature, element_to_sign_func) in self.signature_elements:
            element_to_sign = element_to_sign_func(env)
            element_content = element_to_sign.clone(None).canonical()
            priv_key = EVP.load_key(self.key)
            priv_key.sign_init()
            priv_key.sign_update(element_content.encode("utf-8"))
            signed_digest = priv_key.sign_final()
            element_to_store_signature.setText(b64encode(signed_digest))
    
    def xml(self):
        self.digest_elements = []
        self.signature_elements = []
        
        root = Element("Signature", ns=dsns)

        signed_info = Element("SignedInfo", ns=dsns)
        canon_method = Element("CanonicalizationMethod", ns=dsns)
        canon_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
        sig_method = Element("SignatureMethod", ns=dsns)
        sig_method.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
        signed_info.append(canon_method)
        signed_info.append(sig_method)

        id_index = 1
        for signed_part_func in self.signed_parts:
            reference = Element("Reference", ns=dsns)
            reference.set("URI", "#id-" + str(id_index))
            id_index = id_index + 1
            transforms = Element("Transforms", ns=dsns)
            transform = Element("Transform", ns=dsns)
            transform.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
            transforms.append(transform)
            digest_method = Element("DigestMethod", ns=dsns)
            digest_method.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")
            digest_value = Element("DigestValue", ns=dsns)
            self.digest_elements.append((digest_value, signed_part_func))
            reference.append(transforms)
            reference.append(digest_method)
            reference.append(digest_value)
            signed_info.append(reference)        
        
        sig_value = Element("SignatureValue", ns=dsns)
        self.signature_elements.append((sig_value, lambda env: signed_info))

        key_info = build_key_info(self.cert)
        
        root.append(signed_info)
        root.append(sig_value)
        root.append(key_info)
        return root

    def __init__(self, key, cert):
        Object.__init__(self)
        self.digest_elements = None
        self.signature_elements = None
        self.key = key
        self.cert = cert
        self.signed_parts = []

