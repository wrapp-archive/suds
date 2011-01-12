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
Provides classes for WS-Addressing constructs 
"""

from suds.sudsobject import Object
from suds.sax.element import Element
import random

wsa = ('wsa', 'http://www.w3.org/2005/08/addressing')

random = random.SystemRandom()

class Action(Object):
    def __init__(self, method):
        Object.__init__(self)
        self.method = method

    def xml(self):
        action = Element('Action', ns=wsa)
        action.setText(self.method.soap.action)
        return action

class MessageID(Object):
    def xml(self):
        messageid = Element('MessageID', ns=wsa)
        messageid_bytes = bytearray([random.getrandbits(8) for i in range(0, 16)])
        messageid.setText("mid:" + ''.join(["%02X" % x for x in messageid_bytes]))
        return messageid

