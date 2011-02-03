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
            Definition('signatures', (list, tuple), []),
            Definition('keys', (list, tuple), []),
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
