# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from spnego._ntlm_raw.messages import NegotiateFlags

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/7fc694c9-397a-446a-bd80-4635000f2c0f
TEST_USER = "User"
TEST_USER_DOM = "Domain"
TEST_PASSWD = "Password"
TEST_SERVER_NAME = "Server"
TEST_WORKSTATION_NAME = "COMPUTER"
TEST_RANDOM_SESSION_KEY = b"\x55" * 16
TEST_TIME = b"\x00" * 8
TEST_CLIENT_CHALLENGE = b"\xAA" * 8
TEST_SERVER_CHALLENGE = b"\x01\x23\x45\x67\x89\xAB\xCD\xEF"

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/2624850f-36e9-403c-a832-1d9c7243acc2
TEST_NTLMV1_FLAGS = (
    NegotiateFlags.key_exch
    | NegotiateFlags.key_56
    | NegotiateFlags.key_128
    | NegotiateFlags.version
    | NegotiateFlags.target_type_server
    | NegotiateFlags.always_sign
    | NegotiateFlags.ntlm
    | NegotiateFlags.seal
    | NegotiateFlags.sign
    | NegotiateFlags.oem
    | NegotiateFlags.unicode
)

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/62b3a421-8a57-4778-82df-9064a282f207
TEST_NTLMV1_CLIENT_CHALLENGE_FLAGS = (
    NegotiateFlags.key_56
    | NegotiateFlags.version
    | NegotiateFlags.extended_session_security
    | NegotiateFlags.target_type_server
    | NegotiateFlags.always_sign
    | NegotiateFlags.ntlm
    | NegotiateFlags.seal
    | NegotiateFlags.sign
    | NegotiateFlags.oem
    | NegotiateFlags.unicode
)

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/125f7a94-933e-4023-a146-a449e49bf774
TEST_NTLMV2_FLAGS = (
    NegotiateFlags.key_exch
    | NegotiateFlags.key_56
    | NegotiateFlags.key_128
    | NegotiateFlags.version
    | NegotiateFlags.target_info
    | NegotiateFlags.extended_session_security
    | NegotiateFlags.target_type_server
    | NegotiateFlags.always_sign
    | NegotiateFlags.ntlm
    | NegotiateFlags.seal
    | NegotiateFlags.sign
    | NegotiateFlags.oem
    | NegotiateFlags.unicode
)
