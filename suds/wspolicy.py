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
The I{wspolicy} module provides support for WS-Policy.
"""

from suds.sudsobject import Object, merge
from suds.wsse.xmlsec import *
from suds.wsse import *
from suds.transport.options import *
from suds.options import Options
from suds.sax.date import DateTime

def override(base_policy, override_policy):
    new_policy = Policy()
    merge(base_policy, new_policy)
    merge(override_policy, new_policy)
    return new_policy

class Policy(Object):
    def __init__(self):
        Object.__init__(self)
        self.wsseEnabled = False
        self.includeTimestamp = False
        self.addressing = False
        self.headerLayout = None
        self.onlySignEntireHeadersAndBody = False
        self.clientCertRequired = False
        self.requiredTransports = None
        self.blockEncryption = None
        self.digestAlgorithm = None
        self.keyTransport = None
        self.usernameRequired = False
        self.signatureRequired = False
        self.encryptionRequired = False
        self.encryptThenSign = False
        self.signedParts = []
        self.tokens = []
        self.signatures = []
        self.keys = []

    def addFromWsdl(self, wsdl_policy):
        baseSignedParts = self.buildParts(wsdl_policy.signed_parts)
        baseEncryptedParts = self.buildParts(wsdl_policy.encrypted_parts)
        secondPassEncryptedParts = []

        if wsdl_policy.binding:
            self.wsseEnabled = True
            if wsdl_policy.binding.getChild("IncludeTimestamp") is not None:
                self.includeTimestamp = True
            if wsdl_policy.binding.getChild("EncryptBeforeSigning") is not None:
                self.encryptThenSign = True
            if wsdl_policy.binding.getChild("EncryptSignature") is not None:
                if self.encryptThenSign:
                    secondPassEncryptedParts.append(('signature',))
                else:
                    baseEncryptedParts.append(('signature',))
            if wsdl_policy.binding.getChild("OnlySignEntireHeadersAndBody") is not None:
                self.onlySignEntireHeadersAndBody = True
            if wsdl_policy.binding.getChild("Layout") is not None:
                layout = wsdl_policy.binding.getChild("Layout").getChild("Policy")[0]
                self.headerLayout = layout.name
            if wsdl_policy.binding_type == 'TransportBinding':
                transport_token = wsdl_policy.binding.getChild("TransportToken")
                if transport_token is not None:
                    if transport_token.getChild("Policy").getChild("HttpsToken") is not None:
                        self.requiredTransports = ['https']
                        https_token = transport_token.getChild("Policy").getChild("HttpsToken")
                        client_cert_req = https_token.get("RequireClientCertificate")
                        if client_cert_req is None or client_cert_req == "false":
                            self.clientCertRequired = False
                        elif client_cert_req == "true":
                            self.clientCertRequired = True
            if wsdl_policy.binding.getChild("InitiatorToken") is not None:
                token = wsdl_policy.binding.getChild("InitiatorToken")
                if token.getChild("Policy").getChild("X509Token") is not None:
                    signature = Object()
                    signature.signedParts = self.buildParts(token.getChild("Policy").getChild("SignedParts"))
                    # This would technically be the correct behavior, but WCF specifies that thumbprint references
                    # are supported, but it can't use them for a primary signature.  Support for BinarySecurityTokens
                    # is always required, so just use them
                    #if token.getChild("Policy").getChild("X509Token").getChild("Policy").getChild("RequireThumbprintReference") is not None:
                    #    signature.keyReference = KEY_REFERENCE_FINGERPRINT
                    #elif token.getChild("Policy").getChild("X509Token").getChild("Policy").getChild("RequireIssuerSerialReference") is not None:
                    #    signature.keyReference = KEY_REFERENCE_ISSUER_SERIAL
                    #else:
                    #    signature.keyReference = KEY_REFERENCE_BINARY_SECURITY_TOKEN
                    signature.keyReference = KEY_REFERENCE_BINARY_SECURITY_TOKEN
                    self.signatures.append(signature)
            if (wsdl_policy.binding.getChild("InitiatorToken") is not None and wsdl_policy.binding.getChild("RecipientToken") is not None) or \
                wsdl_policy.binding.getChild("ProtectionToken") is not None:
                key = Object()
                token = wsdl_policy.binding.getChild("RecipientToken") or wsdl_policy.binding.getChild("ProtectionToken")
                if token.getChild("Policy").getChild("X509Token").getChild("Policy").getChild("RequireThumbprintReference") is not None:
                    key.keyReference = KEY_REFERENCE_FINGERPRINT
                elif token.getChild("Policy").getChild("X509Token").getChild("Policy").getChild("RequireIssuerSerialReference") is not None:
                    key.keyReference = KEY_REFERENCE_ISSUER_SERIAL
                else:
                    key.keyReference = KEY_REFERENCE_ISSUER_SERIAL
                key.encryptedParts = self.buildParts(token.getChild("Policy").getChild("EncryptedParts"))
                key.secondPassEncryptedParts = []
                self.keys.append(key)
            if self.blockEncryption is None:
                algorithm_suite = wsdl_policy.binding.getChild("AlgorithmSuite")
                if algorithm_suite is not None:
                    if algorithm_suite.getChild("Policy") is not None:
                        algorithm_policy_name = algorithm_suite.getChild("Policy").getChildren()[0].name
                        if "Basic128" in algorithm_policy_name:
                            self.blockEncryption = BLOCK_ENCRYPTION_AES128_CBC
                        elif "Basic192" in algorithm_policy_name:
                            self.blockEncryption = BLOCK_ENCRYPTION_AES192_CBC
                        elif "Basic256" in algorithm_policy_name:
                            self.blockEncryption = BLOCK_ENCRYPTION_AES256_CBC
                        elif "TripleDes" in algorithm_policy_name:
                            self.blockEncryption = BLOCK_ENCRYPTION_3DES_CBC
                        if "Sha256" in algorithm_policy_name:
                            self.digestAlgorithm = DIGEST_SHA256
                        else:
                            self.digestAlogrithm = DIGEST_SHA1
                        if "Rsa15" in algorithm_policy_name:
                            self.keyTransport = KEY_TRANSPORT_RSA_1_5
                        else:
                            self.keyTransport = KEY_TRANSPORT_RSA_OAEP

        for token in wsdl_policy.tokens:
            if token.getChild("Policy").getChild("UsernameToken") is not None:
                token = Object()
                self.tokens.append(token)
            elif token.getChild("Policy").getChild("X509Token") is not None:
                signature = Object()
                signature.signedParts = self.buildParts(token.getChild("Policy").getChild("SignedParts"))
                # This would technically be the correct behavior, but WCF specifies that thumbprint references
                # are supported, but it can't use them for a primary signature.  Support for BinarySecurityTokens
                # is always required, so just use them
                #if token.getChild("Policy").getChild("X509Token").getChild("Policy").getChild("RequireThumbprintReference") is not None:
                #    signature.keyReference = KEY_REFERENCE_FINGERPRINT
                #elif token.getChild("Policy").getChild("X509Token").getChild("Policy").getChild("RequireIssuerSerialReference") is not None:
                #    signature.keyReference = KEY_REFERENCE_ISSUER_SERIAL
                #else:
                #    signature.keyReference = KEY_REFERENCE_BINARY_SECURITY_TOKEN
                signature.keyReference = KEY_REFERENCE_BINARY_SECURITY_TOKEN
                self.signatures.append(signature)

        if (wsdl_policy.root.getChild("Addressing") is not None or wsdl_policy.root.getChild("UsingAddressing") is not None) and self.addressing <> True:
            if wsdl_policy.root.getChild("Addressing") is not None:
                optional = wsdl_policy.root.getChild("Addressing").get("Optional")
            else:
                optional = wsdl_policy.root.getChild("UsingAddressing").get("Optional")
                
            if optional == "false" or optional is None:
                self.addressing = True
            elif optional == "true":
                self.addressing = None # use what the user specifies

        for sig in self.signatures:
            sig.signedParts.extend(baseSignedParts)
        for key in self.keys:
            key.encryptedParts.extend(baseEncryptedParts)
            key.secondPassEncryptedParts.extend(secondPassEncryptedParts)

        if wsdl_policy.root.getChild("Wss10") is not None:
            self.wsse11 = False
        elif wsdl_policy.root.getChild("Wss11") is not None:
            self.wsse11 = True
        else:
            self.wsse11 = None

    def buildParts(self, parts_element):
        parts = []
        if parts_element is not None:
            for part in parts_element:
                if part.name == "Body":
                    parts.append(('body',))
                elif part.name == "Header":
                    parts.append(('header', part.get("Namespace"), part.get("Name")))
                else:
                    # There are other more obscure options specified in WS-SecurityPolicy, but they are not supported yet
                    pass
        return parts

    def buildOptions(self):
        options = Options()
        options.wsse.enabled = self.wsseEnabled
        if self.wsseEnabled:
            options.wsse.includeTimestamp = self.includeTimestamp
            options.wsse.encryptThenSign = self.encryptThenSign
            options.wsse.signOnlyEntireHeadersAndBody = self.onlySignEntireHeadersAndBody
            if self.wsse11 is not None:
                options.wsse.wsse11 = self.wsse11 
            if self.headerLayout is not None:
                options.wsse.headerLayout = self.headerLayout

            def create_signed_header_func(ns, name):
                return lambda env: env.getChild("Header").getChildren(name, ns=(None, ns))
                    
            def create_encrypted_header_func(ns, name):
                return lambda env: (env.getChild("Header").getChildren(name, ns=(None, ns)), 'Element')
                    
            index = 0
            for sig in self.signatures:
                if self.digestAlgorithm is not None:
                    options.wsse.signatures[index].digest = self.digestAlgorithm
                if sig.keyReference is not None:
                    options.wsse.signatures[index].keyreference = sig.keyReference

                signed_parts = []
                for part in sig.signedParts:
                    if part[0] == 'body':
                        signed_parts.append(lambda env: env.getChild("Body"))
                    elif part[0] == 'header':
                        signed_parts.append(create_signed_header_func(part[1], part[2]))
                
                options.wsse.signatures[index].signedparts = signed_parts

                index = index + 1
            if self.includeTimestamp and len(self.signatures) > 0:
                options.wsse.signatures[0].signedparts.append(lambda env: env.getChild("Header").getChild("Security").getChild("Timestamp"))

            index = 0
            for key in self.keys:
                if self.blockEncryption is not None:
                    options.wsse.keys[index].blockencryption = self.blockEncryption
                if self.keyTransport is not None:
                    options.wsse.keys[index].keytransport = self.keyTransport
                if key.keyReference is not None:
                    options.wsse.keys[index].keyreference = key.keyReference

                encrypted_parts = []
                for part in key.encryptedParts:
                    if part[0] == 'body':
                        encrypted_parts.append(lambda env: (env.getChild("Body"), "Content"))
                    elif part[0] == 'header':
                        encrypted_parts.append(create_encrypted_header_func(part[1], part[2]))
                    elif part[0] == 'signature':
                        encrypted_parts.append(lambda env: (env.getChild('Header').getChild('Security').getChild('Signature'), 'Element'))

                options.wsse.keys[index].encryptedparts = encrypted_parts

                second_pass_encrypted_parts = []
                for part in key.secondPassEncryptedParts:
                    if part[0] == 'body':
                        second_pass_encrypted_parts.append(lambda env: (env.getChild("Body"), "Content"))
                    elif part[0] == 'header':
                        second_pass_encrypted_parts.append(create_encrypted_header_func(part[1], part[2]))
                    elif part[0] == 'signature':
                        second_pass_encrypted_parts.append(lambda env: (env.getChild('Header').getChild('Security').getChild('Signature'), 'Element'))

                options.wsse.keys[index].secondpassencryptedparts = second_pass_encrypted_parts

                index = index + 1

        if self.addressing is not None:
            options.wsaddr = self.addressing
        if self.clientCertRequired:
            options.transport.protocol = PROTOCOL_HTTPS_CERT_AUTH
        return options

    def enforceMessagePreSecurity(self, env):
        pass

    def enforceMessagePostSecurity(self, env):
        timestamp = env.childAtPath('Header/Security/Timestamp')
        if self.includeTimestamp and timestamp is None:
            raise Exception, 'WSDL policy required Timestamp, but Timestamp was not present in reply'
        if timestamp.getChild('Expires') is not None:
            expiry_time = DateTime(timestamp.getChild('Expires').getText()).datetime
            if expiry_time < datetime.now():
                raise Exception, 'Message expiration time has passed'
