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

from suds.sudsobject import Object
from suds.wsse.xmlsec import *
from suds.wsse import *
from suds.transport.options import *
from suds.options import Options
from suds.sax.date import DateTime

wspns = (None, 'http://www.w3.org/ns/ws-policy')
wspns2 = (None, 'http://schemas.xmlsoap.org/ws/2004/09/policy')
spns = (None, 'http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702')

class PolicyConverter:
    def __init__(self, initiator):
        self.policy = Policy()
        self.policy.signatures.append(None)
        self.initiator = initiator
        self.baseSignedParts = []
        self.baseEncryptedParts = []
        self.secondPassEncryptedParts = []
        self.bindingType = None

    def addFromWsdl(self, wsdl_policy):
        self.wsdl_policy = wsdl_policy
        self.optional = False
        self.visitMethods = {('All', None): self.visitAll, \
                ('ExactlyOne', None): self.visitExactlyOne, \
                ('Policy', None): self.visitAll, }
        self.visit(wsdl_policy.root)

    def finishPolicy(self):
        if self.policy.signatures[0] is None:
            del self.policy.signatures[0]
        if self.bindingType <> 'TransportBinding':
            if len(self.policy.signatures) > 0:
                self.policy.signatures[0].signedParts.extend(self.baseSignedParts)
            if len(self.policy.keys) > 0:
                self.policy.keys[0].encryptedParts.extend(self.baseEncryptedParts)
                self.policy.keys[0].secondPassEncryptedParts.extend(self.secondPassEncryptedParts)

        return self.policy

    def visit(self, elt):
        optional_replaced = False
        if elt.get("Optional") == 'true':
            optional_replaced = True
            old_optional = self.optional
            self.optional = True

        try:
            elt_name = (elt.name, elt.namespace()[1])
            if elt_name in self.visitMethods:
                self.visitMethods[elt_name](elt)
            elif (elt.name, None) in self.visitMethods:
                self.visitMethods[(elt.name, None)](elt)
            else:
                self.visitOther(elt)
        finally:
            if optional_replaced:
                self.optional = old_optional

    def visitAll(self, elt):
        for child in elt.getChildren():
            self.visit(child)

    def visitExactlyOne(self, elt):
        optional_replaced = False
        for child in elt.getChildren():
            if child.name == 'All' and (child.namespace()[1] == wspns[1] or child.namespace()[1] == wspns2[1]) and len(child.getChildren()) == 0:
                optional_replaced = True
                old_optional = self.optional
                self.optional = True

        successful = False
        for child in elt.getChildren():
            try:
                # TODO policy backtracking on exception
                self.visit(child)
                successful = True
                break
            except Exception, e:
                exception = e
        
        if optional_replaced:
            self.optional = old_optional

        if not successful:
            raise exception

    def visitOther(self, elt):
        policy = self.policy
        wsdl_policy = self.wsdl_policy

        if elt.name == 'TransportBinding' or elt.name == 'SymmetricBinding' or elt.name == 'AsymmetricBinding':
            self.bindingType = elt.name
            binding = elt.getChild('Policy')

            policy.wsseEnabled = True
            if binding.getChild("IncludeTimestamp") is not None:
                policy.includeTimestamp = True
            if binding.getChild("EncryptBeforeSigning") is not None:
                policy.encryptThenSign = True
            if binding.getChild("EncryptSignature") is not None:
                if policy.encryptThenSign:
                    self.secondPassEncryptedParts.append(('signature',))
                else:
                    self.baseEncryptedParts.append(('signature',))
            if binding.getChild("OnlySignEntireHeadersAndBody") is not None:
                policy.onlySignEntireHeadersAndBody = True
            if binding.getChild("ProtectTokens") is not None:
                policy.protectTokens = True
            if binding.getChild("Layout") is not None:
                layout = binding.getChild("Layout").getChild("Policy")[0]
                policy.headerLayout = layout.name
            if elt.name == 'TransportBinding':
                transport_token = binding.getChild("TransportToken")
                if transport_token is not None:
                    if transport_token.getChild("Policy").getChild("HttpsToken") is not None:
                        https_token = transport_token.getChild("Policy").getChild("HttpsToken")
                        client_cert_req = https_token.get("RequireClientCertificate")
                        if client_cert_req is None or client_cert_req == "false":
                            policy.clientCertRequired = False
                        elif client_cert_req == "true":
                            policy.clientCertRequired = True
            if binding.getChild("InitiatorToken") is not None or binding.getChild("ProtectionToken") is not None:
                token = binding.getChild("InitiatorToken") or binding.getChild("ProtectionToken")
                if token.getChild("Policy").getChild("X509Token") is not None:
                    signature = Object()
                    signature.signedParts = self.buildParts(token.getChild("Policy").getChild("SignedParts"))
                    signature.signedParts.append(('timestamp',))
                    # This would technically be the correct behavior, but WCF specifies that thumbprint references
                    # are supported, but it can't use them for a primary signature.  Support for BinarySecurityTokens
                    # is always required, so just use them
                    #if token.getChild("Policy").getChild("X509Token").getChild("Policy").getChild("RequireThumbprintReference") is not None:
                    #    signature.keyReference = KEY_REFERENCE_FINGERPRINT
                    #elif token.getChild("Policy").getChild("X509Token").getChild("Policy").getChild("RequireIssuerSerialReference") is not None:
                    #    signature.keyReference = KEY_REFERENCE_ISSUER_SERIAL
                    #else:
                    #    signature.keyReference = KEY_REFERENCE_BINARY_SECURITY_TOKEN
                    if elt.name == 'AsymmetricBinding':
                        signature.keyReference = KEY_REFERENCE_BINARY_SECURITY_TOKEN
                        signature.signatureAlgorithm = SIGNATURE_RSA_SHA1
                    elif elt.name == 'SymmetricBinding':
                        signature.keyReference = KEY_REFERENCE_ENCRYPTED_KEY
                        signature.signatureAlgorithm = SIGNATURE_HMAC_SHA1
                    policy.signatures[0] = signature
            if (binding.getChild("InitiatorToken") is not None and binding.getChild("RecipientToken") is not None) or \
                binding.getChild("ProtectionToken") is not None:
                key = Object()
                token = binding.getChild("RecipientToken") or binding.getChild("ProtectionToken")
                if token.getChild("Policy").getChild("X509Token").getChild("Policy").getChild("RequireThumbprintReference") is not None:
                    key.keyReference = KEY_REFERENCE_FINGERPRINT
                elif token.getChild("Policy").getChild("X509Token").getChild("Policy").getChild("RequireIssuerSerialReference") is not None:
                    key.keyReference = KEY_REFERENCE_ISSUER_SERIAL
                else:
                    key.keyReference = KEY_REFERENCE_ISSUER_SERIAL
                if elt.name == 'AsymmetricBinding':
                    key.includeRefList = True
                elif elt.name == 'SymmetricBinding':
                    key.includeRefList = False
                key.encryptedParts = self.buildParts(token.getChild("Policy").getChild("EncryptedParts"))
                key.secondPassEncryptedParts = []
                policy.keys.append(key)
            if policy.blockEncryption is None:
                algorithm_suite = binding.getChild("AlgorithmSuite")
                if algorithm_suite is not None:
                    if algorithm_suite.getChild("Policy") is not None:
                        algorithm_policy_name = algorithm_suite.getChild("Policy").getChildren()[0].name
                        if "Basic128" in algorithm_policy_name:
                            policy.blockEncryption = BLOCK_ENCRYPTION_AES128_CBC
                        elif "Basic192" in algorithm_policy_name:
                            policy.blockEncryption = BLOCK_ENCRYPTION_AES192_CBC
                        elif "Basic256" in algorithm_policy_name:
                            policy.blockEncryption = BLOCK_ENCRYPTION_AES256_CBC
                        elif "TripleDes" in algorithm_policy_name:
                            policy.blockEncryption = BLOCK_ENCRYPTION_3DES_CBC
                        if "Sha256" in algorithm_policy_name:
                            policy.digestAlgorithm = DIGEST_SHA256
                        else:
                            policy.digestAlgorithm = DIGEST_SHA1
                        if "Rsa15" in algorithm_policy_name:
                            policy.keyTransport = KEY_TRANSPORT_RSA_1_5
                        else:
                            policy.keyTransport = KEY_TRANSPORT_RSA_OAEP

        if elt.name.endswith("Tokens") and self.initiator:
            type = None
            index = None
            if elt.getChild("Policy").getChild("UsernameToken") is not None:
                token = Object()
                policy.tokens.append(token)
                type = 'token'
                index = len(policy.tokens) - 1
            if 'Endorsing' in elt.name and elt.getChild("Policy").getChild("X509Token") is not None:
                signature = Object()
                signature.signedParts = self.buildParts(elt.getChild("Policy").getChild("SignedParts"))
                signature.signatureAlgorithm = SIGNATURE_RSA_SHA1
                if wsdl_policy.binding_type == 'TransportBinding':
                    signature.signedParts.append(('timestamp',))
                else:
                    signature.signedParts.append(('primary_signature',))
                    if policy.protectTokens:
                        signature.signedParts.append(('token', 'self'))
                # This would technically be the correct behavior, but WCF specifies that thumbprint references
                # are supported, but it can't use them for a primary signature.  Support for BinarySecurityTokens
                # is always required, so just use them
                #if elt.getChild("Policy").getChild("X509Token").getChild("Policy").getChild("RequireThumbprintReference") is not None:
                #    signature.keyReference = KEY_REFERENCE_FINGERPRINT
                #elif elt.getChild("Policy").getChild("X509Token").getChild("Policy").getChild("RequireIssuerSerialReference") is not None:
                #    signature.keyReference = KEY_REFERENCE_ISSUER_SERIAL
                #else:
                #    signature.keyReference = KEY_REFERENCE_BINARY_SECURITY_TOKEN
                signature.keyReference = KEY_REFERENCE_BINARY_SECURITY_TOKEN
                policy.signatures.append(signature)
                type = 'signature'
                index = len(policy.signatures) - 1
            if 'Signed' in elt.name and wsdl_policy.binding_type <> 'TransportBinding' and type is not None:
                self.baseSignedParts.append(('token', type, index))
            if 'Encrypted' in elt.name and wsdl_policy.binding_type <> 'TransportBinding' and type is not None:
                self.baseEncryptedParts.append(('token', type, index))

        if (elt.name == "Addressing" or elt.name == "UsingAddressing") and policy.addressing <> True:
            if self.optional == False:
                policy.addressing = True
            else:
                policy.addressing = None # use what the user specifies

        if elt.name == "SignedParts":
            self.baseSignedParts.extend(self.buildParts(elt))
        elif elt.name == "EncryptedParts":
            self.baseEncryptedParts.extend(self.buildParts(elt))

        if elt.name == "Wss10":
            policy.wsse11 = False
        elif elt.name == "Wss11":
            policy.wsse11 = True

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

class Policy(Object):
    def __init__(self):
        Object.__init__(self)
        self.wsseEnabled = False
        self.includeTimestamp = False
        self.addressing = False
        self.headerLayout = None
        self.protectTokens = False
        self.onlySignEntireHeadersAndBody = False
        self.clientCertRequired = False
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
	self.wsse11 = None

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
                return lambda env, sig: env.getChild("Header").getChildren(name, ns=(None, ns))
                    
            def create_encrypted_header_func(ns, name):
                return lambda env: (env.getChild("Header").getChildren(name, ns=(None, ns)), 'Element')

            def create_signed_username_token_func(index):
                return lambda env, sig: env.getChild("Header").getChild("Security").getChildren("UsernameToken")[index]

            def create_signed_binary_token_func(index):
                return lambda env, sig: env.getChild("Header").getChild("Security").getChildren("BinarySecurityToken")[index]

            def create_encrypted_username_token_func(index):
                return lambda env: (env.getChild("Header").getChild("Security").getChildren("UsernameToken")[index], 'Element')

            def create_encrypted_binary_token_func(index):
                return lambda env: (env.getChild("Header").getChild("Security").getChildren("BinarySecurityToken")[index], 'Element')

            index = 0
            for sig in self.signatures:
                if self.digestAlgorithm is not None:
                    options.wsse.signatures[index].digest = self.digestAlgorithm
                if sig.keyReference is not None:
                    options.wsse.signatures[index].keyreference = sig.keyReference
                if sig.signatureAlgorithm is not None:
                    options.wsse.signatures[index].signaturealgorithm = sig.signatureAlgorithm

                signed_parts = []
                for part in sig.signedParts:
                    if part[0] == 'body':
                        signed_parts.append(lambda env, sig: env.getChild("Body"))
                    elif part[0] == 'header':
                        signed_parts.append(create_signed_header_func(part[1], part[2]))
                    elif part[0] == 'timestamp':
                        signed_parts.append(lambda env, sig: env.childAtPath("Header/Security/Timestamp"))
                    elif part[0] == 'primary_signature':
                        signed_parts.append(lambda env, sig: sig.primary_sig)
                    elif part[0] == 'token':
                        if part[1] == 'self':
                            signed_parts.append(lambda env, sig: sig.token)
                        elif part[1] == 'token':
                            signed_parts.append(create_signed_username_token_func(part[2]))
                        elif part[1] == 'signature':
                            signed_parts.append(create_signed_binary_token_func(part[2]))
                
                options.wsse.signatures[index].signedparts = signed_parts

                index = index + 1

            index = 0
            for key in self.keys:
                if self.blockEncryption is not None:
                    options.wsse.keys[index].blockencryption = self.blockEncryption
                if self.keyTransport is not None:
                    options.wsse.keys[index].keytransport = self.keyTransport
                if key.keyReference is not None:
                    options.wsse.keys[index].keyreference = key.keyReference
                options.wsse.keys[index].includereflist = key.includeRefList

                encrypted_parts = []
                for part in key.encryptedParts:
                    if part[0] == 'body':
                        encrypted_parts.append(lambda env: (env.getChild("Body"), "Content"))
                    elif part[0] == 'header':
                        encrypted_parts.append(create_encrypted_header_func(part[1], part[2]))
                    elif part[0] == 'signature':
                        encrypted_parts.append(lambda env: (env.getChild('Header').getChild('Security').getChild('Signature'), 'Element'))
                    elif part[0] == 'token':
                        if part[1] == 'token':
                            encrypted_parts.append(create_encrypted_username_token_func(part[2]))
                        elif part[1] == 'signature':
                            encrypted_parts.append(create_encrypted_binary_token_func(part[2]))

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

    def enforceMessagePostSecurity(self, env, decrypted_elements):
        timestamp = env.childAtPath('Header/Security/Timestamp')
        if self.includeTimestamp and timestamp is None:
            raise Exception, 'WSDL policy required Timestamp, but Timestamp was not present in reply'
        if timestamp.getChild('Expires') is not None:
            expiry_time = DateTime(timestamp.getChild('Expires').getText()).datetime
            if expiry_time < datetime.now():
                raise Exception, 'Message expiration time has passed'

        id_blocks = dict()
        
        def collectSignedDataBlock(elt):
            id = elt.get("Id", ns=wsuns) or elt.get("Id")
            if id is None:
                return
            
            if id in id_blocks:
                raise Exception, 'Duplicate IDs are not allowed in secured SOAP message'
            
            id_blocks[id] = elt

        env.walk(collectSignedDataBlock)

        signed_data_blocks = set()
        for sig_elt in env.getChild("Header").getChild("Security").getChildren("Signature", ns=dsns):
            for signed_part in sig_elt.getChild("SignedInfo", ns=dsns).getChildren("Reference", ns=dsns):
                signed_part_id = signed_part.get("URI")

                if not signed_part_id[0] == "#":
                    raise Exception, "Cannot handle non-local data references"
                signed_data_blocks.add(id(id_blocks[signed_part_id[1:]]))

        policy_signed_blocks = set()
        for sig in self.signatures:
            for part in sig.signedParts:
                if part[0] == 'body':
                    policy_signed_blocks.add(id(env.getChild("Body")))
                elif part[0] == 'header':
                    for x in env.getChild("Header").getChildren(part[2], ns=(None, part[1])):
                        policy_signed_blocks.add(id(x))
                elif part[0] == 'signature':
                    policy_signed_blocks.add(id(env.getChild("Header").getChild("Security").getChild("Signature")))
        if self.includeTimestamp and len(self.signatures) > 0:
            policy_signed_blocks.add(id(env.getChild("Header").getChild("Security").getChild("Timestamp")))

        if not policy_signed_blocks <= signed_data_blocks:
            raise Exception, 'Policy specified signed parts that were not signed in the response'

        if decrypted_elements is not None:
            decrypted_element_set = set([id(x) for x in decrypted_elements])
        else:
            decrypted_element_set = set()

        policy_encrypted_blocks = set()
        for key in self.keys:
            for part in key.encryptedParts + key.secondPassEncryptedParts:
                if part[0] == 'body':
                    for child in env.getChild("Body").getChildren():
                        policy_encrypted_blocks.add(id(child))
                elif part[0] == 'header':
                    for x in env.getChild("Header").getChildren(part[2], ns=(None, part[1])):
                        policy_encrypted_blocks.add(id(x))
                elif part[0] == 'signature':
                    policy_encrypted_blocks.add(id(env.getChild("Header").getChild("Security").getChild("Signature")))

        if not policy_encrypted_blocks <= decrypted_element_set:
            raise Exception, 'Policy specified encrypted parts that were not encrypted in the response'

