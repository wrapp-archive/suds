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
The I{options} module provides options for WS-Security.
"""

from suds.properties import *
from pki import Keystore
from suds.wsse.xmlsec import *

HEADER_LAYOUT_STRICT = 'Strict'
HEADER_LAYOUT_LAX = 'Lax'
HEADER_LAYOUT_LAX_TIMESTAMP_FIRST = 'LaxTimestampFirst'
HEADER_LAYOUT_LAX_TIMESTAMP_LAST = 'LaxTimestampLast'

class Options(Skin):
    def __init__(self, **kwargs):
        domain = __name__
        definitions = [
            Definition('enabled', bool, False),
            Definition('includeTimestamp', bool, False),
            Definition('encryptThenSign', bool, False),
            Definition('signOnlyEntireHeadersAndBody', bool, False),
            Definition('headerLayout', basestring, HEADER_LAYOUT_LAX),
            Definition('wsse11', bool, False),
            Definition('keystore', Keystore, Keystore()),
            Definition('tokens', Skin, Skin(ListProperties(TokenOptions))),
            Definition('signatures', Skin, Skin(ListProperties(SignatureOptions))), 
            Definition('keys', Skin, Skin(ListProperties(KeyOptions))), 
        ]
        Skin.__init__(self, Properties(domain, definitions, kwargs))

class TokenOptions(Skin):
    def __init__(self, **kwargs):
        domain = __name__
        definitions = [
            Definition('username', basestring, None),
            Definition('password', basestring, None),
        ]
        Skin.__init__(self, Properties(domain, definitions, kwargs))

class SignatureOptions(Skin):
    def __init__(self, **kwargs):
        domain = __name__
        definitions = [
            Definition('key', (), None),
            Definition('cert', (), None),
            Definition('digest', basestring, DIGEST_SHA1),
            Definition('keyreference', basestring, KEY_REFERENCE_BINARY_SECURITY_TOKEN),
            Definition('signedparts', (list, tuple), []),
        ]
        Skin.__init__(self, Properties(domain, definitions, kwargs))

class KeyOptions(Skin):
    def __init__(self, **kwargs):
        domain = __name__
        definitions = [
            Definition('cert', (), None),
            Definition('encryptedparts', (list, tuple), []),
            Definition('secondpassencryptedparts', (list, tuple), []),
            Definition('blockencryption', basestring, BLOCK_ENCRYPTION_AES128_CBC),
            Definition('keytransport', basestring, KEY_TRANSPORT_RSA_OAEP),
            Definition('keyreference', basestring, KEY_REFERENCE_ISSUER_SERIAL),
        ]
        Skin.__init__(self, Properties(domain, definitions, kwargs))
