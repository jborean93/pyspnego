# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

import io
import struct

from collections import (
    OrderedDict,
)

from datetime import (
    datetime,
    timedelta,
    tzinfo,
)

from spnego._compat import (
    Callable,
    Dict,
    Optional,
    Tuple,
    IntFlag,
)

from spnego._text import (
    text_type,
    to_bytes,
    to_text,
)

from spnego._version import (
    __version__ as pyspnego_version,
)


# TODO: Use _compat.IntFlag once Python 2.7 is dropped.
# Cannot use it today as Python 2.7 on some systems have sys.maxint as a signed 32 bit integer and cannot have anything
# > 0x7FFFFFFF set.
class NegotiateFlags:
    """NTLM Negotiation flags.

    Used during NTLM negotiation to negotiate the capabilities between the client and server.

    .. _NEGOTIATE:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832
    """

    key_56 = 0x80000000
    key_exch = 0x40000000
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
    target_type_share = 0x00040000  # Not documented in MS-NLMP
    target_type_server = 0x00020000
    target_type_domain = 0x00010000
    always_sign = 0x00008000
    local_call = 0x00004000  # Not documented in MS-NLMP
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
    netware = 0x00000008  # Not documented in MS-NLMP
    request_target = 0x00000004
    oem = 0x00000002
    unicode = 0x00000001

    @classmethod
    def native_labels(cls):  # type: () -> Dict[str, int]
        return {
            'NTLMSSP_NEGOTIATE_56': NegotiateFlags.key_56,
            'NTLMSSP_NEGOTIATE_KEY_EXCH': NegotiateFlags.key_exch,
            'NTLMSSP_NEGOTIATE_128': NegotiateFlags.key_128,
            'NTLMSSP_RESERVED_R1': NegotiateFlags.r1,
            'NTLMSSP_RESERVED_R2': NegotiateFlags.r2,
            'NTLMSSP_RESERVED_R3': NegotiateFlags.r3,
            'NTLMSSP_NEGOTIATE_VERSION': NegotiateFlags.version,
            'NTLMSSP_RESERVED_R4': NegotiateFlags.r4,
            'NTLMSSP_NEGOTIATE_TARGET_INFO': NegotiateFlags.target_info,
            'NTLMSSP_REQUEST_NON_NT_SESSION_KEY': NegotiateFlags.non_nt_session_key,
            'NTLMSSP_RESERVED_R5': NegotiateFlags.r5,
            'NTLMSSP_NEGOTIATE_IDENTITY': NegotiateFlags.identity,
            'NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY': NegotiateFlags.extended_session_security,
            'NTLMSSP_TARGET_TYPE_SHARE - R6': NegotiateFlags.target_type_share,
            'NTLMSSP_TARGET_TYPE_SERVER': NegotiateFlags.target_type_server,
            'NTLMSSP_TARGET_TYPE_DOMAIN': NegotiateFlags.target_type_domain,
            'NTLMSSP_NEGOTIATE_ALWAYS_SIGN': NegotiateFlags.always_sign,
            'NTLMSSP_NEGOTIATE_LOCAL_CALL - R7': NegotiateFlags.local_call,
            'NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED': NegotiateFlags.oem_workstation_supplied,
            'NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED': NegotiateFlags.oem_domain_name_supplied,
            'NTLMSSP_ANOYNMOUS': NegotiateFlags.anonymous,
            'NTLMSSP_RESERVED_R8': NegotiateFlags.r8,
            'NTLMSSP_NEGOTIATE_NTLM': NegotiateFlags.ntlm,
            'NTLMSSP_RESERVED_R9': NegotiateFlags.r9,
            'NTLMSSP_NEGOTIATE_LM_KEY': NegotiateFlags.lm_key,
            'NTLMSSP_NEGOTIATE_DATAGRAM': NegotiateFlags.datagram,
            'NTLMSSP_NEGOTIATE_SEAL': NegotiateFlags.seal,
            'NTLMSSP_NEGOTIATE_SIGN': NegotiateFlags.sign,
            'NTLMSSP_NEGOTIATE_NETWARE - R10': NegotiateFlags.netware,
            'NTLMSSP_REQUEST_TARGET': NegotiateFlags.request_target,
            'NTLMSSP_NEGOTIATE_OEM': NegotiateFlags.oem,
            'NTLMSSP_NEGOTIATE_UNICODE': NegotiateFlags.unicode,
        }


class AvId(IntFlag):
    """ID for an NTLM AV_PAIR.

    These are the IDs that can be set as the `AvId` on an `AV_PAIR`_.

    .. _AV_PAIR:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
    """
    eol = 0x0000
    nb_computer_name = 0x0001
    nb_domain_name = 0x0002
    dns_computer_name = 0x0003
    dns_domain_name = 0x0004
    dns_tree_name = 0x0005
    flags = 0x0006
    timestamp = 0x0007
    single_host = 0x0008
    target_name = 0x0009
    channel_bindings = 0x000A

    @classmethod
    def native_labels(cls):  # type: () -> Dict[str, int]
        return {
            'MSV_AV_EOL': AvId.eol,
            'MSV_AV_NB_COMPUTER_NAME': AvId.nb_computer_name,
            'MSV_AV_NB_DOMAIN_NAME': AvId.nb_domain_name,
            'MSV_AV_DNS_COMPUTER_NAME': AvId.dns_computer_name,
            'MSV_AV_DNS_DOMAIN_NAME': AvId.dns_domain_name,
            'MSV_AV_DNS_TREE_NAME': AvId.dns_tree_name,
            'MSV_AV_FLAGS': AvId.flags,
            'MSV_AV_TIMESTAMP': AvId.timestamp,
            'MSV_AV_SINGLE_HOST': AvId.single_host,
            'MSV_AV_TARGET_NAME': AvId.target_name,
            'MSV_AV_CHANNEL_BINDINGS': AvId.channel_bindings,
        }


class AvFlags(IntFlag):
    """MsvAvFlags for an AV_PAIR.

    These are the flags that can be set on the MsvAvFlags entry of an NTLM `AV_PAIR`_.

    .. _AV_PAIR:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
    """
    constrained = 0x00000001
    mic = 0x00000002
    untrusted_spn = 0x00000004

    @classmethod
    def native_labels(cls):  # type: () -> Dict[str, int]
        return {
            'AUTHENTICATION_CONSTRAINED': AvFlags.constrained,
            'MIC_PROVIDED': AvFlags.mic,
            'UNTRUSTED_SPN_SOURCE': AvFlags.untrusted_spn
        }


def _pack_payload(data, b_payload, payload_offset, pack_func=None):
    # type: (Optional[any], io.BytesIO, int, Callable[[any], bytes]) -> Tuple[bytes, int]
    if data:
        b_data = pack_func(data) if pack_func else data
    else:
        b_data = b""

    b_payload.write(b_data)
    length = len(b_data)

    b_field = (struct.pack("<H", length) * 2) + struct.pack("<I", payload_offset)
    payload_offset += length

    return b_field, payload_offset


def _unpack_payload(b_data, field_offset, unpack_func=None):  # type: (bytes, int, Callable[[bytes], any]) -> any
    field_len = struct.unpack("<H", b_data[field_offset:field_offset + 2])[0]
    if field_len:
        field_offset = struct.unpack("<I", b_data[field_offset + 4:field_offset + 8])[0]
        b_value = b_data[field_offset:field_offset + field_len]

        return unpack_func(b_value) if unpack_func else b_value


class Negotiate:
    """NTLM Negotiate Message

    This structure represents an NTLM `NEGOTIATE_MESSAGE`_ that can be serialized and deserialized to and from
    bytes.

    Args:
        flags: The `NegotiateFlags` that the client has negotiated.
        domain_name: The `DomainName` of the client authentication domain.
        workstation: The `Workstation` of the client.
        version: The `Version` of the client.

    .. _NEGOTIATE_MESSAGE:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2
    """

    def __init__(self, flags, domain_name=None, workstation=None, version=None):
        # type: (int, Optional[text_type], Optional[text_type], Optional[Version]) -> None
        self.flags = flags  # type: int
        self.domain_name = domain_name  # type: text_type
        self.workstation = workstation  # type: text_type
        self.version = version  # type: Version

    def pack(self, encoding='windows-1252'):  # type: (str) -> bytes
        """ Packs the structure to bytes. """
        b_data = io.BytesIO()
        b_payload = io.BytesIO()

        flags = self.flags
        payload_offset = 40

        if self.domain_name:
            flags |= NegotiateFlags.oem_domain_name_supplied
        b_domain_field, payload_offset = _pack_payload(self.domain_name, b_payload, payload_offset,
                                                       lambda d: to_bytes(d, encoding=encoding))

        if self.workstation:
            flags |= NegotiateFlags.oem_workstation_supplied
        b_workstation_field, payload_offset = _pack_payload(self.workstation, b_payload, payload_offset,
                                                            lambda d: to_bytes(d, encoding=encoding))

        b_version = b"\x00" * 8
        if self.version:
            flags |= NegotiateFlags.version
            b_version = self.version.pack()

        b_data.write(b"NTLMSSP\x00\x01\x00\x00\x00")
        b_data.write(struct.pack("<I", int(flags)))
        b_data.write(b_domain_field)
        b_data.write(b_workstation_field)
        b_data.write(b_version)

        return b_data.getvalue() + b_payload.getvalue()

    @staticmethod
    def unpack(b_data, encoding='windows-1252'):  # type: (bytes, str) -> Negotiate
        """ Unpacks the structure from bytes. """
        signature = b_data[:8]
        if signature != b"NTLMSSP\x00":
            raise ValueError("Invalid NTLM Negotiate signature")

        message_type = struct.unpack("<I", b_data[8:12])[0]
        if message_type != 1:
            raise ValueError("Invalid NTLM Negotiate message type %d, expecting 1" % message_type)

        flags = struct.unpack("<I", b_data[12:16])[0]

        domain = to_text(_unpack_payload(b_data, 16), encoding=encoding, nonstring='passthru')
        workstation = to_text(_unpack_payload(b_data, 24), encoding=encoding, nonstring='passthru')

        version = None
        if flags & NegotiateFlags.version:
            version = Version.unpack(b_data[32:40])

        return Negotiate(flags, domain_name=domain, workstation=workstation, version=version)


class Challenge:
    """NTLM Challenge Message

    This structure represents an NTLM `CHALLENGE_MESSAGE`_ that can be serialized and deserialized to and from
    bytes.

    Args:
        flags: The `NegotiateFlags` that the client has negotiated.
        server_challenge: The random 64-bit `ServerChallenge` nonce.
        target_name: The name of the acceptor server.
        target_info: The variable length `TargetInfo` information.
        version: The `Version` of the server.

    .. _CHALLENGE_MESSAGE:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
    """

    def __init__(self, flags, server_challenge, target_name=None, target_info=None, version=None):
        # type: (int, bytes, Optional[text_type], Optional[TargetInfo], Optional[Version]) -> None

        self.flags = flags  # type: int
        self.server_challenge = server_challenge  # type: bytes
        self.reserved = b"\x00" * 8  # type: bytes
        self.target_name = target_name  # type: Optional[text_type]
        self.target_info = target_info  # type: Optional[TargetInfo]
        self.version = version

    def pack(self, encoding='windows-1252'):  # type: (str) -> bytes
        """ Packs the structure to bytes. """
        b_data = io.BytesIO()
        b_payload = io.BytesIO()
        flags = int(self.flags)

        if flags & NegotiateFlags.unicode:
            encoding = 'utf-16-le'

        payload_offset = 56

        if self.target_name:
            flags |= NegotiateFlags.request_target
        b_target_name_fields, payload_offset = _pack_payload(self.target_name, b_payload, payload_offset,
                                                             lambda d: to_bytes(d, encoding=encoding))

        if self.target_info:
            flags |= NegotiateFlags.target_info
        b_target_info_fields, payload_offset = _pack_payload(self.target_info, b_payload, payload_offset,
                                                             lambda d: d.pack())

        b_version = b"\x00" * 8
        if self.version:
            flags |= NegotiateFlags.version
            b_version = self.version.pack()

        b_data.write(b"NTLMSSP\x00\x02\x00\x00\x00")
        b_data.write(b_target_name_fields)
        b_data.write(struct.pack("<I", flags))
        b_data.write(self.server_challenge)
        b_data.write(self.reserved)
        b_data.write(b_target_info_fields)
        b_data.write(b_version)

        return b_data.getvalue() + b_payload.getvalue()

    @staticmethod
    def unpack(b_data, encoding='windows-1252'):  # type: (bytes, str) -> Challenge
        """ Unpacks the structure from bytes. """
        signature = b_data[:8]
        if signature != b"NTLMSSP\x00":
            raise ValueError("Invalid NTLM Challenge signature")

        message_type = struct.unpack("<I", b_data[8:12])[0]
        if message_type != 2:
            raise ValueError("Invalid NTLM Challenge message type %d, expecting 2" % message_type)

        flags = struct.unpack("<I", b_data[20:24])[0]
        if flags & NegotiateFlags.unicode:
            encoding = 'utf-16-le'

        target_name = to_text(_unpack_payload(b_data, 12), encoding=encoding, nonstring='passthru')
        server_challenge = b_data[24:32]
        reserved = b_data[32:40]
        target_info = _unpack_payload(b_data, 40, lambda d: TargetInfo.unpack(d))

        version = None
        if flags & NegotiateFlags.version:
            version = Version.unpack(b_data[48:56])

        challenge = Challenge(flags, server_challenge, target_name=target_name, target_info=target_info,
                              version=version)
        challenge.reserved = reserved

        return challenge


class Authenticate:
    """NTLM Authentication Message

    This structure represents an NTLM `AUTHENTICATION_MESSAGE`_ that can be serialized and deserialized to and from
    bytes.

    Args:
        flags: The `NegotiateFlags` that the client has negotiated.
        lm_challenge_response: The `LmChallengeResponse` for the client's secret.
        nt_challenge_response: The `NtChallengeResponse` for the client's secret.
        domain_name: The `DomainName` for the client.
        username: The `UserName` for the cleint.
        workstation: The `Workstation` for the client.
        encrypted_session_key: The `EncryptedRandomSessionKey` for the set up context.
        version: The `Version` of the client.
        mic: The `MIC` for the authentication exchange.

    .. _AUTHENTICATION_MESSAGE:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce
    """

    def __init__(self, flags, lm_challenge_response, nt_challenge_response, domain_name=None, username=None,
                 workstation=None, encrypted_session_key=None, version=None, mic=None):
        # type: (int, Optional[bytes], Optional[bytes], Optional[text_type], Optional[text_type], Optional[text_type], Optional[bytes], Optional[Version], Optional[bytes]) -> None # noqa

        self.flags = flags    # type: int
        self.lm_challenge_response = lm_challenge_response  # type: Optional[bytes]
        self.nt_challenge_response = nt_challenge_response  # type: Optional[bytes]
        self.domain_name = domain_name  # type: Optional[text_type]
        self.username = username  # type: Optional[text_type]
        self.workstation = workstation  # type: Optional[text_type]
        self.encrypted_random_session_key = encrypted_session_key  # type: bytes
        self.version = version  # type: Optional[Version]
        self.mic = None  # type: Optional[bytes]
        if mic:
            self.mic = mic

    def pack(self, encoding='windows-1252'):  # type: (str) -> bytes
        """ Packs the structure to bytes. """
        b_data = io.BytesIO()
        b_payload = io.BytesIO()
        flags = int(self.flags)

        if flags & NegotiateFlags.unicode:
            encoding = 'utf-16-le'

        # While MS server accept a blank version field, other implementations aren't so kind. No need to be strict
        # about it and only add the version bytes if it's present.
        b_version = b""
        if self.version:
            flags |= NegotiateFlags.version
            b_version = self.version.pack()

        payload_offset = 64 + len(b_version) + len(self.mic or b"")

        b_lm_response_fields, payload_offset = _pack_payload(self.lm_challenge_response, b_payload, payload_offset)
        b_nt_response_fields, payload_offset = _pack_payload(self.nt_challenge_response, b_payload, payload_offset)
        b_domain_fields, payload_offset = _pack_payload(self.domain_name, b_payload, payload_offset,
                                                        lambda d: to_bytes(d, encoding=encoding))
        b_username_fields, payload_offset = _pack_payload(self.username, b_payload, payload_offset,
                                                          lambda d: to_bytes(d, encoding=encoding))
        b_workstation_fields, payload_offset = _pack_payload(self.workstation, b_payload, payload_offset,
                                                             lambda d: to_bytes(d, encoding=encoding))

        if self.encrypted_random_session_key:
            flags |= NegotiateFlags.key_exch
        b_session_key_fields, payload_offset = _pack_payload(self.encrypted_random_session_key, b_payload,
                                                             payload_offset)

        b_data.write(b"NTLMSSP\x00\x03\x00\x00\x00")
        b_data.write(b_lm_response_fields)
        b_data.write(b_nt_response_fields)
        b_data.write(b_domain_fields)
        b_data.write(b_username_fields)
        b_data.write(b_workstation_fields)
        b_data.write(b_session_key_fields)
        b_data.write(struct.pack("<I", flags))
        b_data.write(b_version)
        if self.mic:
            b_data.write(self.mic)

        return b_data.getvalue() + b_payload.getvalue()

    @staticmethod
    def unpack(b_data, encoding='windows-1252'):  # type: (bytes, str) -> Authenticate
        """ Unpacks the structure from bytes. """
        signature = b_data[:8]
        if signature != b"NTLMSSP\x00":
            raise ValueError("Invalid NTLM Authenticate signature")

        message_type = struct.unpack("<I", b_data[8:12])[0]
        if message_type != 3:
            raise ValueError("Invalid NTLM Authenticate message type %d, expecting 3" % message_type)

        flags = struct.unpack("<I", b_data[60:64])[0]
        if flags & NegotiateFlags.unicode:
            encoding = 'utf-16-le'

        lm_response = _unpack_payload(b_data, 12)
        nt_response = _unpack_payload(b_data, 20)
        domain = to_text(_unpack_payload(b_data, 28), encoding=encoding, nonstring='passthru')
        user = to_text(_unpack_payload(b_data, 36), encoding=encoding, nonstring='passthru')
        workstation = to_text(_unpack_payload(b_data, 44), encoding=encoding, nonstring='passthru')
        enc_key = _unpack_payload(b_data, 52)

        mic_offset = 64
        version = None
        if flags & NegotiateFlags.version:
            version = Version.unpack(b_data[64:72])
            mic_offset += 8

        # To detect whether a MIC was actually present we need to scan the NTLMv2 proof string for MsvAvFlags in the
        # AV_PAIRS of the token
        mic = None
        if len(nt_response) > 24:
            target_info = TargetInfo.unpack(nt_response[44:-4])
            if target_info.get(AvId.flags, 0) & AvFlags.mic:
                mic = b_data[mic_offset:mic_offset + 16]

        return Authenticate(flags, lm_response, nt_response, domain_name=domain, username=user,
                            workstation=workstation, encrypted_session_key=enc_key, version=version, mic=mic)


class FileTime(datetime):
    """Windows FILETIME structure.

    FILETIME structure representing number of 100-nanosecond intervals that have elapsed since January 1, 1601 UTC.
    This subclasses the datetime object to provide a similar interface but with the `nanosecond` attribute.

    Attrs:
        nanosecond (int): The number of nanoseconds (< 1000) in the FileTime. Note this only has a precision of up to
            100 nanoseconds.

    .. _FILETIME:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2c57429b-fdd4-488f-b5fc-9e4cf020fcdf
    """

    _EPOCH_FILETIME = 116444736000000000  # 1970-01-01 as FILETIME.

    def __new__(cls, *args, **kwargs):
        ns = 0
        if 'nanosecond' in kwargs:
            ns = kwargs.pop('nanosecond')

        dt = super(FileTime, cls).__new__(cls, *args, **kwargs)
        dt.nanosecond = ns

        return dt

    @classmethod
    def now(cls, tz=None):  # type: (tzinfo) -> FileTime
        """ Construct a FileTime from the current time and optional time zone info. """
        return FileTime.from_datetime(datetime.now(tz=tz))

    @classmethod
    def from_datetime(cls, dt, ns=0):  # type: (datetime, int) -> FileTime
        """ Creates a FileTime object from a datetime object. """
        return FileTime(year=dt.year, month=dt.month, day=dt.day, hour=dt.hour, minute=dt.minute, second=dt.second,
                        microsecond=dt.microsecond, tzinfo=dt.tzinfo, nanosecond=ns)

    def __str__(self):
        """ Displays the datetime in ISO 8601 including the 100th nanosecond internal like .NET does. """
        fraction_seconds = ""

        if self.microsecond or self.nanosecond:
            fraction_seconds = self.strftime('.%f')

            if self.nanosecond:
                fraction_seconds += str(self.nanosecond // 100)

        timezone = 'Z'
        if self.tzinfo:
            utc_offset = self.strftime('%z')
            timezone = "%s:%s" % (utc_offset[:3], utc_offset[3:])

        return self.strftime("%Y-%m-%dT%H:%M:%S{0}{1}".format(fraction_seconds, timezone))

    def pack(self):  # type: () -> bytes
        """ Packs the structure to bytes. """
        # Get the time since EPOCH in microseconds
        td = self - datetime.utcfromtimestamp(0)
        epoch_time_ms = (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6)

        # Add the EPOCH_FILETIME to the microseconds since EPOCH and finally the nanoseconds part.
        ns100 = FileTime._EPOCH_FILETIME + (epoch_time_ms * 10) + (self.nanosecond // 100)

        return struct.pack("<Q", ns100)

    @staticmethod
    def unpack(b_data):  # type: (bytes) -> FileTime
        """ Unpacks the structure from bytes. """
        filetime = struct.unpack("<Q", b_data)[0]  # 100 nanosecond intervals since 1601-01-01.

        # Create a datetime object based on the filetime microseconds
        epoch_time_ms = (filetime - FileTime._EPOCH_FILETIME) // 10
        dt = datetime(1970, 1, 1) + timedelta(microseconds=epoch_time_ms)

        # Create the FileTime object from the datetime object and add the nanoseconds.
        ns = int(filetime % 10) * 100

        return FileTime.from_datetime(dt, ns=ns)


class TargetInfo(OrderedDict):
    """A collection of AV_PAIR structures for the TargetInfo field.

    The `AV_PAIR`_ structure defines an attribute/value pair and sequences of these pairs are using in the
    :class:`Challenge` and :class:`Authenticate` messages. The value for each pair depends on the AvId specified.
    Each value can be get/set/del like a normal dictionary where the key is the AvId of the value.

    .. _AV_PAIR:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
    """

    _FIELD_TYPES = {
        'text': (AvId.nb_computer_name, AvId.nb_domain_name, AvId.dns_computer_name, AvId.dns_domain_name,
                 AvId.dns_tree_name, AvId.target_name),
        'int32': (AvId.flags,),
        'struct': (AvId.timestamp, AvId.single_host),
    }

    def __setitem__(self, key, value):
        if isinstance(value, bytes):
            if key == AvId.timestamp:
                FileTime.unpack(value)
            elif key == AvId.single_host:
                value = SingleHost.unpack(value)

        super(TargetInfo, self).__setitem__(key, value)

    def pack(self):  # type: () -> bytes
        """ Packs the structure to bytes. """
        b_data = io.BytesIO()

        for av_id, value in self.items():
            # MsvAvEOL should only be set at the end, will just ignore these entries.
            if av_id == AvId.eol:
                continue

            if av_id in self._FIELD_TYPES['text']:
                b_value = to_bytes(value, encoding='utf-16-le')
            elif av_id in self._FIELD_TYPES['int32']:
                b_value = struct.pack("<I", value)
            elif av_id in self._FIELD_TYPES['struct']:
                b_value = value.pack()
            else:
                b_value = value

            b_data.write(struct.pack("<HH", av_id, len(b_value)) + b_value)

        b_data.write(b"\x00\x00\x00\x00")  # MsvAvEOL
        return b_data.getvalue()

    @staticmethod
    def unpack(b_data):  # type: (bytes) -> TargetInfo
        """ Unpacks the structure from bytes. """
        target_info = TargetInfo()
        b_io = io.BytesIO(b_data)

        b_av_id = b_io.read(2)

        while b_av_id:
            av_id = struct.unpack("<H", b_av_id)[0]
            length = struct.unpack("<H", b_io.read(2))[0]
            b_value = b_io.read(length)

            if av_id in TargetInfo._FIELD_TYPES['text']:
                # All AV_PAIRS are UNICODE encoded.
                value = to_text(b_value, encoding='utf-16-le')

            elif av_id in TargetInfo._FIELD_TYPES['int32']:
                value = AvFlags(struct.unpack("<I", b_value)[0])

            elif av_id == AvId.timestamp:
                value = FileTime.unpack(b_value)

            elif av_id == AvId.single_host:
                value = SingleHost.unpack(b_value)

            else:
                value = b_value

            target_info[AvId(av_id)] = value
            b_av_id = b_io.read(2)

        return target_info


class SingleHost:
    """Single_Host_Data structure for NTLM TargetInfo entry.

    `Single_Host_Data`_ structure allows a client to send machine-specific information within an authentication
    exchange to services on the same machine. If the server and client platforms are different or if they are on
    different hosts, then the information MUST be ignores.

    Args:
        size: A 32-bit unsigned int that defines size of the structure.
        z4: A 32-bit integer value, currently set to 0.
        custom_data: An 8-byte platform-specific blob containing info only relevant when the client and server are on
            the same host.
        machine_id: A 32-byte random number created at computer startup to identify the calling machine.

    Attributes:
        size: See args.
        z4: See args.
        custom_data: See args.
        machine_id: See args.

    .. _Single_Host_Data:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/f221c061-cc40-4471-95da-d2ff71c85c5b
    """

    def __init__(self, size, z4, custom_data, machine_id):  # type: (int, int, bytes, bytes) -> None
        self.size = size  # type: int
        self.z4 = z4  # type: int
        self.custom_data = custom_data  # type: bytes
        self.machine_id = machine_id  # type; bytes

    def pack(self):  # type: () -> bytes
        """ Packs the structure to bytes. """
        return struct.pack("<I", self.size) + struct.pack("<I", self.z4) + self.custom_data + self.machine_id

    @staticmethod
    def unpack(b_data):  # type: (bytes) -> SingleHost
        """ Unpacks the structure from bytes. """
        size = struct.unpack("<I", b_data[:4])[0]
        z4 = struct.unpack("<I", b_data[4:8])[0]

        return SingleHost(size, z4, b_data[8:16], b_data[16:48])


class Version:
    """A structure contains the OS information.

    The `VERSION`_ structure contains operating system version information that SHOULD be ignored. This structure is
    used for debugging purposes only and its value does not affect NTLM message processing. It is populated in the NTLM
    messages only if `NTLMSSP_NEGOTIATE_VERSION` (`NegotiateFlags.version`) is negotiated.

    Args:
        major: The 8-bit unsigned int for the version major part.
        minor: The 8-bit unsigned int for the version minor part.
        build: The 16-bit unsigned int for the version build part.
        revision: An 8-bit unsigned integer that contains a value indicating the current revision of the NTLMSSP in
            use. This field SHOULD be `0x0F`.

    Attrs:
        major: See args.
        minor: See args.
        build: See args.
        reserved: A reserved field that shouldn't be set.
        revision: See args.

    .. _VERSION:
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175
    """

    def __init__(self, major=0, minor=0, build=0, revision=0x0F):  # type: (int, int, int, int) -> None
        self.major = major  # type: int
        self.minor = minor  # type: int
        self.build = build  # type: int
        self.reserved = b"\x00\x00\x00"  # type: bytes
        self.revision = revision  # type: int

    def __str__(self):
        return "%s.%s.%s.%s" % (self.major, self.minor, self.build, self.revision)

    def pack(self):  # type: () -> bytes
        """ Packs the structure to bytes. """
        return struct.pack("B", self.major) + struct.pack("B", self.minor) + struct.pack("<H", self.build) + \
            self.reserved + struct.pack("B", self.revision)

    @staticmethod
    def get_current():  # type: () -> Version
        """ Generates an NTLM Version structure based on the pyspnego package version. """
        v = [v for v in pyspnego_version.split('.', 3) if v]
        v += [0] * (3 - len(v))

        return Version(major=int(v[0]), minor=int(v[1]), build=int(v[2]))

    @staticmethod
    def unpack(b_data):  # type: (bytes) -> Version
        """ Unpacks the structure from bytes. """
        major = struct.unpack("B", b_data[:1])[0]
        minor = struct.unpack("B", b_data[1:2])[0]
        build = struct.unpack("<H", b_data[2:4])[0]
        revision = struct.unpack("B", b_data[7:8])[0]

        v = Version(major=major, minor=minor, build=build, revision=revision)
        v.reserved = b_data[4:7]

        return v
