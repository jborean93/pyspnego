# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import enum
import io
import struct
from typing import Optional

from spnego._text import (
    text_type,
    to_bytes,
    to_text,
)


class NegotiateFlags(enum.IntFlag):
    key_56 = 0x80000000
    negotiate_key_exch = 0x40000000
    key_128 = 0x20000000
    r1 = 0x10000000
    r2 = 0x08000000
    r3 = 0x04000000
    version = 0x02000000
    r4 = 0x01000000
    target_info = 0x00800000
    non_nt_session_key = 0x00400000
    r5 = 0x00200000
    identity = 0x00100000
    extended_session_security = 0x00080000
    r6 = 0x00040000
    target_type_server = 0x00020000
    target_type_domain = 0x00010000
    always_sign = 0x00008000
    r7 = 0x00004000
    oem_workstation_supplied = 0x00002000
    oem_domain_name_supplied = 0x00001000
    anonymous = 0x00000800
    r8 = 0x00000400
    ntlm = 0x00000200
    r9 = 0x00000100
    lm_key = 0x00000080
    datagram = 0x00000040
    seal = 0x00000020
    sign = 0x00000010
    r10 = 0x00000008
    request_target = 0x00000004
    oem = 0x00000002
    unicode = 0x00000001


class Negotiate:

    def __init__(self, flags, domain_name=None, workstation=None, version=None):
        self.flags = flags  # type: NegotiateFlags
        self.domain_name = domain_name  # type: text_type
        self.workstation = workstation  # type: text_type
        self.version = version  # type: Version

    def pack(self, encoding='windows-1252'):  # type: (str) -> bytes
        b_data = io.BytesIO(b"NTLMSSP\x00\x01\x00\x00\x00")
        flags = self.flags
        payload_offset = 40

        b_domain = b""
        if self.domain_name:
            flags |= NegotiateFlags.oem_domain_name_supplied
            b_domain = to_bytes(self.domain_name, encoding=encoding)

        b_domain_field = (struct.pack("<H", len(b_domain)) * 2) + struct.pack("<I", payload_offset)
        payload_offset += len(b_domain)

        b_workstation = b""
        if self.workstation:
            flags |= NegotiateFlags.oem_workstation_supplied
            b_workstation = to_bytes(self.workstation, encoding=encoding)

        b_workstation_field = (struct.pack("<H", len(b_workstation)) * 2) + struct.pack("<I", payload_offset)
        payload_offset += len(b_workstation)

        b_version = b"\x00" * 8
        if self.version:
            flags |= NegotiateFlags.version
            b_version = self.version.pack()

        b_data.write(struct.pack("<I", int(flags)))
        b_data.write(b_domain_field)
        b_data.write(b_workstation_field)
        b_data.write(b_version)
        b_data.write(b_domain)
        b_data.write(b_workstation)

        return bytes(b_data)

    @staticmethod
    def unpack(b_data, encoding='windows-1252'):  # type: (bytes, str) -> Negotiate
        signature = b_data[:8]
        if signature != b"NTLMSSP\x00":
            raise ValueError("Invalid NTLM Negotiate signature")

        message_type = struct.unpack("<I", b_data[8:12])[0]
        if message_type != 1:
            raise ValueError("Invalid NTLM Negotiate message type %d, expecting 1" % message_type)

        flags = NegotiateFlags(struct.unpack("<I", b_data[12:16])[0])

        domain_name_len = struct.unpack("<H", b_data[16:18])[0]
        domain_name_offset = struct.unpack("<I", b_data[20:24])[0]

        workstation_len = struct.unpack("<H", b_data[24:26])[0]
        workstation_offset = struct.unpack("<I", b_data[28:32])[0]

        version = None
        if b_data[32:40] != b"\x00" * 8:
            version = Version.unpack(b_data[32:40])

        domain_name = None
        if domain_name_len:
            domain_name = to_text(b_data[domain_name_offset:domain_name_offset + domain_name_len],
                                  encoding=encoding)

        workstation = None
        if workstation_len:
            workstation = to_text(b_data[workstation_offset:workstation_offset + workstation_len],
                                  encoding=encoding)

        return Negotiate(flags, domain_name=domain_name, workstation=workstation, version=version)


class Challenge:

    def __init__(self, flags, server_challenge, target_name=None, target_info=None, version=None):
        self.flags = NegotiateFlags(flags)  # type: NegotiateFlags
        self.server_challenge = server_challenge  # type: bytes
        self.target_name = target_name  # type: Optional[text_type]
        self.target_info = target_info  # type: Optional[TargetInfo]
        self.version = version

    def pack(self, encoding='windows-1252'):  # type: (str) -> bytes
        b_data = io.BytesIO(b"NTLMSSP\x00\x02\x00\x00\x00")
        flags = int(self.flags)

        if flags & NegotiateFlags.unicode:
            encoding = 'utf-16-le'

        payload_offset = 48

        b_target_name = b""
        if self.target_name:
            flags |= NegotiateFlags.request_target
            b_target_name = to_bytes(self.target_name, encoding=encoding)

        b_target_name_fields = (struct.pack("<H", len(b_target_name)) * 2) + struct.pack("<I", payload_offset)
        payload_offset += len(b_target_name)

        b_target_info = b""
        if self.target_info:
            flags |= NegotiateFlags.target_info
            b_target_info = self.target_info.pack()

        b_target_info_fields = (struct.pack("<H", len(b_target_info)) * 2) + struct.pack("<I", payload_offset)
        payload_offset += len(b_target_info)

        b_version = b"\x00" * 8
        if self.version:
            flags |= NegotiateFlags.version
            b_version = self.version.pack()

        b_data.write(b_target_name_fields)
        b_data.write(struct.pack("<I", flags))
        b_data.write(self.server_challenge)
        b_data.write(b"\x00" * 8)
        b_data.write(b_target_info_fields)
        b_data.write(b_version)
        b_data.write(b_target_name)
        b_data.write(b_target_info)

        return bytes(b_data)


class Authentication:

    def __init__(self):
        self.flags = 0
        self.lm_challenge_response = None
        self.nt_challenge_response = None
        self.domain_name = None
        self.username = None
        self.workstation = None
        self.encrypted_random_session_key = None
        self.version = None
        self.mic = None


class TargetInfo:

    def __init__(self):
        pass

    def pack(self):
        return b""

    @staticmethod
    def unpack(b_data):
        return TargetInfo()


class Version:

    def __init__(self, major=0, minor=0, build=0, revision=0x0F):
        self.major = major
        self.minor = minor
        self.build = build
        self.revision = revision

    def __str__(self):
        return "%s.%s.%s.%s" % (self.major, self.minor, self.build, self.revision)

    def pack(self):
        return struct.pack("B", self.major) + struct.pack("B", self.minor) + struct.pack("<H", self.build) + \
               b"\x00\x00\x00" + struct.pack("B", self.revision)

    @staticmethod
    def unpack(b_data):
        major = struct.unpack("B", b_data[:1])[0]
        minor = struct.unpack("B", b_data[1:2])[0]
        build = struct.unpack("<H", b_data[2:4])[0]
        revision = struct.unpack("B", b_data[7:8])[0]

        return Version(major=major, minor=minor, build=build, revision=revision)
