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

def override(base_policy, override_policy):
    new_policy = Policy()
    merge(base_policy, new_policy)
    merge(override_policy, new_policy)
    return new_policy

class Policy(Object):
    def addFromWsdl(self, wsdl_policy):
        if wsdl_policy.binding:
            self.wsseEnabled = True
            if wsdl_policy.binding.getChild("IncludeTimestamp") is not None:
                self.includeTimestamp = True
            if wsdl_policy.binding.getChild("EncryptSignature") is not None:
                self.encryptedParts.append(('signature',))
            if wsdl_policy.binding.getChild("EncryptBeforeSigning") is not None:
                self.encryptThenSign = True
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
                    self.signatureRequired = True
                    self.signedParts.extend(self.buildParts(token.getChild("Policy").getChild("SignedParts")))
            if (wsdl_policy.binding.getChild("InitiatorToken") is not None and wsdl_policy.binding.getChild("RecipientToken") is not None) or \
                wsdl_policy.binding.getChild("ProtectionToken") is not None:
                self.encryptionRequired = True
                token = wsdl_policy.binding.getChild("RecipientToken") or wsdl_policy.binding.getChild("ProtectionToken")
                self.encryptedParts.extend(self.buildParts(token.getChild("Policy").getChild("EncryptedParts")))
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
                self.usernameRequired = True
            if token.getChild("Policy").getChild("X509Token") is not None:
                self.signatureRequired = True
                self.signedParts.extend(self.buildParts(token.getChild("Policy").getChild("SignedParts")))
        if (wsdl_policy.root.getChild("Addressing") is not None or wsdl_policy.root.getChild("UsingAddressing") is not None) and self.addressing <> True:
            if wsdl_policy.root.getChild("Addressing") is not None:
                optional = wsdl_policy.root.getChild("Addressing").get("Optional")
            else:
                optional = wsdl_policy.root.getChild("UsingAddressing").get("Optional")
                
            if optional == "false" or optional is None:
                self.addressing = True
            elif optional == "true":
                self.addressing = None # use what the user specifies
        self.signedParts.extend(self.buildParts(wsdl_policy.signed_parts))
        self.encryptedParts.extend(self.buildParts(wsdl_policy.encrypted_parts))
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
        if self.addressing is not None:
            options.wsaddr = self.addressing
        if self.clientCertRequired:
            options.transport.protocol = PROTOCOL_HTTPS_CERT_AUTH
        return options

    def enforceOptions(self, options, location):
        if self.wsseEnabled:
            if not options.wsse:
                options.wsse = Security()
            wsse = options.wsse
            if self.usernameRequired and len(wsse.tokens) == 0:
                raise Exception, 'WSDL policy requires username token, but no username token was specified in Client'
            if self.signatureRequired and len(wsse.signatures) == 0:
                raise Exception, 'WSDL policy requires signed message, but no signature was specified in Client'
            if self.encryptionRequired and len(wsse.keys) == 0:
                raise Exception, 'WSDL policy requires encrypted message, but no encryption keys were specified in Client'
            if self.clientCertRequired and not isinstance(options.transport, HttpsClientCertAuthenticated):
                raise Exception, 'WSDL policy requires client certificate authentication with HTTPS, but HttpsClientCertAuthenticated transport was not specified in Client'
            wsse.includeTimestamp = self.includeTimestamp
            wsse.encryptThenSign = self.encryptThenSign
            wsse.signOnlyEntireHeadersAndBody = self.onlySignEntireHeadersAndBody
            if self.digestAlgorithm is not None:
                for sig in wsse.signatures:
                    sig.digest = self.digestAlgorithm
            if self.blockEncryption is not None:
                for key in wsse.keys:
                    key.blockEncryption = self.blockEncryption
            if self.keyTransport is not None:
                for key in wsse.keys:
                    key.keyTransport = self.keyTransport
            if self.wsse11 is not None:
                wsse.wsse11 = self.wsse11 
            if self.headerLayout is not None:
                wsse.headerLayout = self.headerLayout
            def create_signed_header_func(ns, name):
                return lambda env: env.getChild("Header").getChildren(name, ns=(None, ns))
                    
            def create_encrypted_header_func(ns, name):
                return lambda env: (env.getChild("Header").getChildren(name, ns=(None, ns)), 'Element')
                    
            for part in self.signedParts:
                if part[0] == 'body':
                    wsse.signatures[0].signed_parts.append(lambda env: env.getChild("Body"))
                elif part[0] == 'header':
                    wsse.signatures[0].signed_parts.append(create_signed_header_func(part[1], part[2]))
            for part in self.encryptedParts:
                if part[0] == 'body':
                    wsse.keys[0].encrypted_parts.append(lambda env: (env.getChild("Body"), "Content"))
                elif part[0] == 'header':
                    wsse.keys[0].encrypted_parts.append(create_encrypted_header_func(part[1], part[2]))
                elif part[0] == 'signature':
                    wsse.keys[0].encrypted_parts.append(lambda env: (env.getChild('Header').getChild('Security').getChild('Signature'), 'Element'))
            if self.signatureRequired and self.includeTimestamp:
                wsse.signatures[0].signed_parts.append(lambda env: env.getChild("Header").getChild("Security").getChild("Timestamp"))
        if self.addressing is not None:
            options.wsaddr = self.addressing
        if self.requiredTransports is not None:
            for transport_scheme in self.requiredTransports:
                if transport_scheme == location[:location.find(':')]:
                    break
                raise Exception, 'Specified transport is not allowed by WSDL policy'

    def enforceMessagePreSecurity(self, env):
        pass

    def enforceMessagePostSecurity(self, env):
        if self.includeTimestamp:
            if env.getChild('Header') is None or env.getChild('Header').getChild('Security') is None or env.getChild('Header').getChild('Security').getChild('Timestamp') is None:
                raise Exception, 'WSDL policy required Timestamp, but Timestamp was not present in reply'

        
