# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import struct


class AddressType:
    GSS_C_AF_UNSPEC = 0  # Unspecified
    GSS_C_AF_LOCAL = 1  # Host local address
    GSS_C_AF_INET = 2  # DARPA Version 4 internet address (IPv4).
    GSS_C_AF_IMPLINK = 3  # ARPAnet IMP
    GSS_C_AF_PUP = 4  # pup protocols (for example, BSP)
    GSS_C_AF_CHAOS = 5  # MIT CHAOS protocol
    GSS_C_AF_NS = 6  # XEROS NS
    GSS_C_AF_NBS = 7  # nbs
    GSS_C_AF_ECMA = 8  # ECMA
    GSS_C_AF_DATAKIT = 9  # datakit protocols
    GSS_C_AF_CCITT = 10  # CCITT protocol (for example, X.25)
    GSS_C_AF_SNA = 11  # IBM SNA
    GSS_C_AF_DECnet = 12  # Digital DECnet
    GSS_C_AF_DLI = 13  # Direct data link interface
    GSS_C_AF_LAT = 14  # LAT
    GSS_C_AF_HYLINK = 15  # NSC Hyperchannel
    GSS_C_AF_APPLETALK = 16  # AppleTalk
    GSS_C_AF_BSC = 17  # BISYNC 2780/3780
    GSS_C_AF_DSS = 18  # Distributed system services
    GSS_C_AF_OSI = 19  # OSI TP4
    GSS_C_AF_X25 = 21  # X25
    GSS_C_AF_INET6 = 24  # DARPA Version 6 internet address (IPv6)
    GSS_C_AF_NULLADDR = 255  # No address specified


class GssChannelBindings:

    def __init__(self, initiator_addrtype=AddressType.GSS_C_AF_UNSPEC, initiator_address=b"",
                 acceptor_addrtype=AddressType.GSS_C_AF_UNSPEC, acceptor_address=b"", application_data=b""):
        """
        This is a common way of representing channel bindings to bind to a security context. Channel bindings are tags
        that identify the particular data channel that is used. Because these tags are specific to the originator and
        recipient applications, they offer more proof of a valid identity. Most HTTPS based authentications just set
        application data o b'tls-server-end-point:<certificate hash>'.

        :param initiator_addrtype: The address type of the initiator address.
        :param initiator_address: The address of the initiator.
        :param acceptor_addrtype: The address type of the acceptor address.
        :param acceptor_address: The address of the acceptor.
        :param application_data: Any extra application data to set on the bindings struct.
        """
        self.initiator_addrtype = initiator_addrtype
        self.initiator_address = initiator_address
        self.acceptor_addrtype = acceptor_addrtype
        self.acceptor_address = acceptor_address
        self.application_data = application_data

    def get_data(self):
        b_data = self._pack_value(self.initiator_addrtype, self.initiator_address)
        b_data += self._pack_value(self.acceptor_addrtype, self.acceptor_address)
        b_data += self._pack_value(None, self.application_data)

        return b_data

    def _pack_value(self, addr_type, b):
        return (struct.pack("<I", addr_type) if addr_type is not None else b"") + struct.pack("<I", len(b)) + b
