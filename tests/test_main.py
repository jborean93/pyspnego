# -*- coding: utf-8 -*-
# Copyright: (c) 2021, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import base64
import io
import json
import os.path

import pytest

import spnego.__main__ as entrypoint
from spnego._ntlm_raw.messages import (
    Authenticate,
    AvId,
    Challenge,
    Negotiate,
    SingleHost,
    TargetInfo,
)
from spnego._spnego import NegTokenResp

from .conftest import get_data


def test_parse_with_hex(capsys):
    entrypoint.main(["--token", base64.b16encode(get_data("ntlm_negotiate")).decode().lower()])
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "NEGOTIATE_MESSAGE (1)"
    assert actual["RawData"] is not None
    assert actual["Data"] is not None


def test_parse_with_file(capsys):
    entrypoint.main(["--file", os.path.join(os.path.dirname(__file__), "data", "ntlm_negotiate")])
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "NEGOTIATE_MESSAGE (1)"
    assert actual["RawData"] is not None
    assert actual["Data"] is not None


def test_parse_with_file_missing():
    with pytest.raises(ValueError, match="Cannot find file at path"):
        entrypoint.main(["--file", "missing"])


def test_parse_from_stdin(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(get_data("ntlm_negotiate"))))
    entrypoint.main([])
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "NEGOTIATE_MESSAGE (1)"
    assert actual["RawData"] is not None
    assert actual["Data"] is not None


def test_parse_from_stdin_base16(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(base64.b16encode(get_data("ntlm_negotiate")))))
    entrypoint.main([])
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "NEGOTIATE_MESSAGE (1)"
    assert actual["RawData"] is not None
    assert actual["Data"] is not None


def test_parse_from_stdin_base64(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(base64.b64encode(get_data("ntlm_negotiate")))))
    entrypoint.main([])
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "NEGOTIATE_MESSAGE (1)"
    assert actual["RawData"] is not None
    assert actual["Data"] is not None


def test_parse_output_yaml(capsys):
    ruamel = pytest.importorskip("ruamel")
    entrypoint.main(
        [
            "--token",
            base64.b64encode(get_data("ntlm_negotiate")).decode(),
            "--format",
            "yaml",
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    with pytest.raises(ValueError):
        json.loads(actual_out.out)

    loader = ruamel.yaml.YAML(typ="safe", pure=True)
    actual = loader.load(actual_out.out)

    assert actual["MessageType"] == "NEGOTIATE_MESSAGE (1)"
    assert actual["RawData"] is not None
    assert actual["Data"] is not None


def test_parse_output_yaml_not_installed(monkeypatch):
    monkeypatch.setattr(entrypoint, "yaml", None)

    with pytest.raises(ValueError, match="Cannot output as yaml as ruamel.yaml is not installed"):
        entrypoint.main(
            [
                "--token",
                base64.b64encode(get_data("ntlm_negotiate")).decode(),
                "--format",
                "yaml",
            ]
        )


def test_parse_invalid_spnego_token(capsys):
    resp = NegTokenResp(response_token=b"invalid")
    entrypoint.main(
        [
            "--token",
            base64.b64encode(resp.pack()).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "SPNEGO NegTokenResp"
    assert actual["RawData"] is not None
    assert actual["Data"]["negState"] is None
    assert actual["Data"]["supportedMech"] is None
    assert actual["Data"]["responseToken"]["MessageType"] == "Unknown - Failed to parse see Data for more details."
    assert (
        actual["Data"]["responseToken"]["Data"]
        == "Failed to parse token: Expecting a tag number of 0 not 9 for InitialContextToken"
    )
    assert actual["Data"]["responseToken"]["RawData"] == "696E76616C6964"
    assert actual["Data"]["mechListMIC"] is None


def test_ntlm_negotiate(capsys):
    entrypoint.main(["--token", base64.b64encode(get_data("ntlm_negotiate")).decode()])
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "NEGOTIATE_MESSAGE (1)"
    assert actual["RawData"] is not None

    assert actual["Data"]["NegotiateFlags"]["raw"] == 3792208567
    assert set(actual["Data"]["NegotiateFlags"]["flags"]) == {
        "NTLMSSP_NEGOTIATE_56 (2147483648)",
        "NTLMSSP_NEGOTIATE_KEY_EXCH (1073741824)",
        "NTLMSSP_NEGOTIATE_128 (536870912)",
        "NTLMSSP_NEGOTIATE_VERSION (33554432)",
        "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (524288)",
        "NTLMSSP_NEGOTIATE_ALWAYS_SIGN (32768)",
        "NTLMSSP_NEGOTIATE_NTLM (512)",
        "NTLMSSP_NEGOTIATE_LM_KEY (128)",
        "NTLMSSP_NEGOTIATE_SEAL (32)",
        "NTLMSSP_NEGOTIATE_SIGN (16)",
        "NTLMSSP_REQUEST_TARGET (4)",
        "NTLMSSP_NEGOTIATE_OEM (2)",
        "NTLMSSP_NEGOTIATE_UNICODE (1)",
    }

    assert actual["Data"]["DomainNameFields"] == {
        "Len": 0,
        "MaxLen": 0,
        "BufferOffset": 0,
    }
    assert actual["Data"]["WorkstationFields"] == {
        "Len": 0,
        "MaxLen": 0,
        "BufferOffset": 0,
    }
    assert actual["Data"]["Version"] == {
        "Major": 10,
        "Minor": 0,
        "Build": 17763,
        "Reserved": "000000",
        "NTLMRevision": 15,
    }
    assert actual["Data"]["Payload"] == {
        "DomainName": None,
        "Workstation": None,
    }


def test_ntlm_challenge(capsys):
    entrypoint.main(["--token", base64.b64encode(get_data("ntlm_challenge")).decode()])
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "CHALLENGE_MESSAGE (2)"
    assert actual["RawData"] is not None

    assert actual["Data"]["TargetNameFields"] == {
        "Len": 12,
        "MaxLen": 12,
        "BufferOffset": 56,
    }
    assert actual["Data"]["NegotiateFlags"]["raw"] == 3800662581
    assert set(actual["Data"]["NegotiateFlags"]["flags"]) == {
        "NTLMSSP_NEGOTIATE_56 (2147483648)",
        "NTLMSSP_NEGOTIATE_KEY_EXCH (1073741824)",
        "NTLMSSP_NEGOTIATE_128 (536870912)",
        "NTLMSSP_NEGOTIATE_VERSION (33554432)",
        "NTLMSSP_NEGOTIATE_TARGET_INFO (8388608)",
        "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (524288)",
        "NTLMSSP_TARGET_TYPE_DOMAIN (65536)",
        "NTLMSSP_NEGOTIATE_ALWAYS_SIGN (32768)",
        "NTLMSSP_NEGOTIATE_NTLM (512)",
        "NTLMSSP_NEGOTIATE_SEAL (32)",
        "NTLMSSP_NEGOTIATE_SIGN (16)",
        "NTLMSSP_REQUEST_TARGET (4)",
        "NTLMSSP_NEGOTIATE_UNICODE (1)",
    }
    assert actual["Data"]["ServerChallenge"] == "E4101014CF8A90BE"
    assert actual["Data"]["Reserved"] == "0000000000000000"
    assert actual["Data"]["TargetInfoFields"] == {
        "Len": 138,
        "MaxLen": 138,
        "BufferOffset": 68,
    }
    assert actual["Data"]["Version"] == {
        "Major": 10,
        "Minor": 0,
        "Build": 14393,
        "Reserved": "000000",
        "NTLMRevision": 15,
    }
    assert actual["Data"]["Payload"]["TargetName"] == "DOMAIN"
    assert actual["Data"]["Payload"]["TargetInfo"] == [
        {"AvId": "MSV_AV_NB_DOMAIN_NAME (2)", "Value": "DOMAIN"},
        {"AvId": "MSV_AV_NB_COMPUTER_NAME (1)", "Value": "DC01"},
        {"AvId": "MSV_AV_DNS_DOMAIN_NAME (4)", "Value": "domain.local"},
        {"AvId": "MSV_AV_DNS_COMPUTER_NAME (3)", "Value": "DC01.domain.local"},
        {"AvId": "MSV_AV_DNS_TREE_NAME (5)", "Value": "domain.local"},
        {"AvId": "MSV_AV_TIMESTAMP (7)", "Value": "2020-04-30T02:46:22.4140792Z"},
        {"AvId": "MSV_AV_EOL (0)", "Value": None},
    ]


def test_ntlm_authenticate(capsys):
    entrypoint.main(["--token", base64.b64encode(get_data("ntlm_authenticate")).decode()])
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "AUTHENTICATE_MESSAGE (3)"
    assert actual["RawData"] is not None

    assert actual["Data"]["LmChallengeResponseFields"] == {
        "Len": 0,
        "MaxLen": 0,
        "BufferOffset": 72,
    }
    assert actual["Data"]["NtChallengeResponseFields"] == {
        "Len": 252,
        "MaxLen": 252,
        "BufferOffset": 72,
    }
    assert actual["Data"]["DomainNameFields"] == {
        "Len": 0,
        "MaxLen": 0,
        "BufferOffset": 0,
    }
    assert actual["Data"]["UserNameFields"] == {
        "Len": 54,
        "MaxLen": 54,
        "BufferOffset": 324,
    }
    assert actual["Data"]["WorkstationFields"] == {
        "Len": 26,
        "MaxLen": 26,
        "BufferOffset": 378,
    }
    assert actual["Data"]["EncryptedRandomSessionKeyFields"] == {
        "Len": 16,
        "MaxLen": 16,
        "BufferOffset": 404,
    }
    assert actual["Data"]["NegotiateFlags"]["raw"] == 3800662581
    assert set(actual["Data"]["NegotiateFlags"]["flags"]) == {
        "NTLMSSP_NEGOTIATE_56 (2147483648)",
        "NTLMSSP_NEGOTIATE_KEY_EXCH (1073741824)",
        "NTLMSSP_NEGOTIATE_128 (536870912)",
        "NTLMSSP_NEGOTIATE_VERSION (33554432)",
        "NTLMSSP_NEGOTIATE_TARGET_INFO (8388608)",
        "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY (524288)",
        "NTLMSSP_TARGET_TYPE_DOMAIN (65536)",
        "NTLMSSP_NEGOTIATE_ALWAYS_SIGN (32768)",
        "NTLMSSP_NEGOTIATE_NTLM (512)",
        "NTLMSSP_NEGOTIATE_SEAL (32)",
        "NTLMSSP_NEGOTIATE_SIGN (16)",
        "NTLMSSP_REQUEST_TARGET (4)",
        "NTLMSSP_NEGOTIATE_UNICODE (1)",
    }
    assert actual["Data"]["Version"] == {
        "Major": 6,
        "Minor": 2,
        "Build": 0,
        "Reserved": "000000",
        "NTLMRevision": 15,
    }
    assert actual["Data"]["MIC"] is None
    assert actual["Data"]["Payload"]["LmChallengeResponse"] is None
    assert actual["Data"]["Payload"]["NtChallengeResponse"]["ResponseType"] == "NTLMv2"
    assert actual["Data"]["Payload"]["NtChallengeResponse"]["NTProofStr"] == "C543CC0D1A0FBD9EC05E1AAB0771B124"
    assert actual["Data"]["Payload"]["NtChallengeResponse"]["ClientChallenge"] == {
        "RespType": 1,
        "HiRespType": 1,
        "Reserved1": 0,
        "Reserved2": 0,
        "TimeStamp": "2020-04-30T02:46:22.4140792Z",
        "ChallengeFromClient": "DC5A7473AC5672FC",
        "Reserved3": 0,
        "AvPairs": [
            {"AvId": "MSV_AV_NB_COMPUTER_NAME (1)", "Value": "DC01"},
            {"AvId": "MSV_AV_NB_DOMAIN_NAME (2)", "Value": "DOMAIN"},
            {"AvId": "MSV_AV_DNS_COMPUTER_NAME (3)", "Value": "DC01.domain.local"},
            {"AvId": "MSV_AV_DNS_DOMAIN_NAME (4)", "Value": "domain.local"},
            {"AvId": "MSV_AV_DNS_TREE_NAME (5)", "Value": "domain.local"},
            {"AvId": "MSV_AV_FLAGS (6)", "Value": {"raw": 0, "flags": []}},
            {"AvId": "MSV_AV_TIMESTAMP (7)", "Value": "2020-04-30T02:46:22.4140792Z"},
            {"AvId": "MSV_AV_TARGET_NAME (9)", "Value": "dc01.domain.local"},
            {"AvId": "MSV_AV_CHANNEL_BINDINGS (10)", "Value": "00000000000000000000000000000000"},
            {"AvId": "MSV_AV_EOL (0)", "Value": None},
        ],
        "Reserved4": 0,
    }
    assert actual["Data"]["Payload"]["DomainName"] is None
    assert actual["Data"]["Payload"]["UserName"] == "vagrant-domain@DOMAIN.LOCAL"
    assert actual["Data"]["Payload"]["Workstation"] == "JBOREAN-LINUX"
    assert actual["Data"]["Payload"]["EncryptedRandomSessionKey"] == "3765D5AFD13EC3A6C97C0726CE9F30C9"
    assert actual["Data"]["SessionKey"] == "Failed to derive"


def test_ntlm_authenticate_with_secret(capsys):
    entrypoint.main(
        [
            "--token",
            base64.b64encode(get_data("ntlm_authenticate")).decode(),
            "--secret",
            "VagrantPass1",
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)
    assert actual["Data"]["SessionKey"] == "4E10F9B8AA8C2A5DF0A2AD75A8ECF433"


def test_ntlm_authenticate_ntlmv1(capsys):
    data = base64.b64encode(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x03\x00\x00\x00"
        b"\x18\x00"
        b"\x18\x00"
        b"\x6C\x00\x00\x00"
        b"\x18\x00"
        b"\x18\x00"
        b"\x84\x00\x00\x00"
        b"\x0C\x00"
        b"\x0C\x00"
        b"\x48\x00\x00\x00"
        b"\x08\x00"
        b"\x08\x00"
        b"\x54\x00\x00\x00"
        b"\x10\x00"
        b"\x10\x00"
        b"\x5C\x00\x00\x00"
        b"\x10\x00"
        b"\x10\x00"
        b"\x9C\x00\x00\x00"
        b"\x35\x82\x80\xE2"
        b"\x05\x01\x28\x0A\x00\x00\x00\x0F"
        b"\x44\x00\x6F\x00\x6D\x00\x61\x00\x69\x00\x6E\x00"
        b"\x55\x00\x73\x00\x65\x00\x72\x00"
        b"\x43\x00\x4F\x00\x4D\x00\x50\x00\x55\x00\x54\x00\x45\x00\x52\x00"
        b"\x98\xDE\xF7\xB8\x7F\x88\xAA\x5D\xAF\xE2\xDF\x77\x96\x88\xA1\x72"
        b"\xDE\xF1\x1C\x7D\x5C\xCD\xEF\x13"
        b"\x67\xC4\x30\x11\xF3\x02\x98\xA2\xAD\x35\xEC\xE6\x4F\x16\x33\x1C"
        b"\x44\xBD\xBE\xD9\x27\x84\x1F\x94"
        b"\x51\x88\x22\xB1\xB3\xF3\x50\xC8\x95\x86\x82\xEC\xBB\x3E\x3C\xB7"
    ).decode()

    entrypoint.main(["--token", data])
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["Data"]["LmChallengeResponseFields"] == {
        "Len": 24,
        "MaxLen": 24,
        "BufferOffset": 108,
    }
    assert actual["Data"]["NtChallengeResponseFields"] == {
        "Len": 24,
        "MaxLen": 24,
        "BufferOffset": 132,
    }

    assert actual["Data"]["Payload"]["LmChallengeResponse"]["ResponseType"] == "LMv1"
    assert (
        actual["Data"]["Payload"]["LmChallengeResponse"]["LMProofStr"]
        == "98DEF7B87F88AA5DAFE2DF779688A172DEF11C7D5CCDEF13"
    )
    assert actual["Data"]["Payload"]["NtChallengeResponse"]["ResponseType"] == "NTLMv1"
    assert (
        actual["Data"]["Payload"]["NtChallengeResponse"]["NTProofStr"]
        == "67C43011F30298A2AD35ECE64F16331C44BDBED927841F94"
    )


def test_ntlm_authenticate_lmv2(capsys):
    data = base64.b64encode(
        b"\x4E\x54\x4C\x4D\x53\x53\x50\x00"
        b"\x03\x00\x00\x00"
        b"\x18\x00"
        b"\x18\x00"
        b"\x6C\x00\x00\x00"
        b"\x54\x00"
        b"\x54\x00"
        b"\x84\x00\x00\x00"
        b"\x0C\x00"
        b"\x0C\x00"
        b"\x48\x00\x00\x00"
        b"\x08\x00"
        b"\x08\x00"
        b"\x54\x00\x00\x00"
        b"\x10\x00"
        b"\x10\x00"
        b"\x5C\x00\x00\x00"
        b"\x10\x00"
        b"\x10\x00"
        b"\xD8\x00\x00\x00"
        b"\x35\x82\x88\xE2"
        b"\x05\x01\x28\x0A\x00\x00\x00\x0F"
        b"\x44\x00\x6F\x00\x6D\x00\x61\x00\x69\x00\x6E\x00"
        b"\x55\x00\x73\x00\x65\x00\x72\x00"
        b"\x43\x00\x4F\x00\x4D\x00\x50\x00\x55\x00\x54\x00\x45\x00\x52\x00"
        b"\x86\xC3\x50\x97\xAC\x9C\xEC\x10\x25\x54\x76\x4A\x57\xCC\xCC\x19"
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
        b"\x68\xCD\x0A\xB8\x51\xE5\x1C\x96\xAA\xBC\x92\x7B\xEB\xEF\x6A\x1C"
        b"\x01"
        b"\x01"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
        b"\x00\x00\x00\x00"
        b"\x02\x00\x0C\x00\x44\x00\x6F\x00\x6D\x00\x61\x00\x69\x00\x6E\x00"
        b"\x01\x00\x0C\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\xC5\xDA\xD2\x54\x4F\xC9\x79\x90\x94\xCE\x1C\xE9\x0B\xC9\xD0\x3E"
    ).decode()

    entrypoint.main(["--token", data])
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["Data"]["LmChallengeResponseFields"] == {
        "Len": 24,
        "MaxLen": 24,
        "BufferOffset": 108,
    }
    assert actual["Data"]["NtChallengeResponseFields"] == {
        "Len": 84,
        "MaxLen": 84,
        "BufferOffset": 132,
    }

    assert actual["Data"]["Payload"]["LmChallengeResponse"]["ResponseType"] == "LMv2"
    assert actual["Data"]["Payload"]["LmChallengeResponse"]["LMProofStr"] == "86C35097AC9CEC102554764A57CCCC19"
    assert actual["Data"]["Payload"]["LmChallengeResponse"]["ChallengeFromClient"] == "AAAAAAAAAAAAAAAA"
    assert actual["Data"]["Payload"]["NtChallengeResponse"]["ResponseType"] == "NTLMv2"
    assert actual["Data"]["Payload"]["NtChallengeResponse"]["NTProofStr"] == "68CD0AB851E51C96AABC927BEBEF6A1C"
    assert actual["Data"]["Payload"]["NtChallengeResponse"]["ClientChallenge"] == {
        "RespType": 1,
        "HiRespType": 1,
        "Reserved1": 0,
        "Reserved2": 0,
        "TimeStamp": "1601-01-01T00:00:00Z",
        "ChallengeFromClient": "AAAAAAAAAAAAAAAA",
        "Reserved3": 0,
        "AvPairs": [
            {"AvId": "MSV_AV_NB_DOMAIN_NAME (2)", "Value": "Domain"},
            {"AvId": "MSV_AV_NB_COMPUTER_NAME (1)", "Value": "Server"},
            {"AvId": "MSV_AV_EOL (0)", "Value": None},
        ],
        "Reserved4": 0,
    }


def test_nltm_session_key_no_sign_seal(capsys):
    entrypoint.main(
        [
            "--token",
            base64.b64encode(get_data("ntlm_authenticate_no_sign_seal")).decode(),
            "--secret",
            "vagrant",
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)
    assert actual["Data"]["SessionKey"] == "92D93576421343CEB1937AAD4CD78116"


def test_ntlm_without_version(capsys):
    msg = Negotiate()
    entrypoint.main(
        [
            "--token",
            base64.b64encode(msg.pack()).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["Data"]["Version"] is None


def test_ntlm_no_target_info(capsys):
    msg = Challenge()
    entrypoint.main(
        [
            "--token",
            base64.b64encode(msg.pack()).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["Data"]["Payload"]["TargetInfo"] is None


def test_ntlm_av_single_host(capsys):
    ti = TargetInfo(
        {
            AvId.single_host: SingleHost(size=4, z4=0, custom_data=b"\x01" * 8, machine_id=b"\x02" * 32),
        }
    )
    msg = Challenge(target_info=ti)
    entrypoint.main(
        [
            "--token",
            base64.b64encode(msg.pack()).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert len(actual["Data"]["Payload"]["TargetInfo"]) == 2
    assert actual["Data"]["Payload"]["TargetInfo"][0]["AvId"] == "MSV_AV_SINGLE_HOST (8)"
    assert actual["Data"]["Payload"]["TargetInfo"][0]["Value"] == {
        "Size": 4,
        "Z4": 0,
        "CustomData": "0101010101010101",
        "MachineId": "0202020202020202020202020202020202020202020202020202020202020202",
    }
    assert actual["Data"]["Payload"]["TargetInfo"][1] == {"AvId": "MSV_AV_EOL (0)", "Value": None}


def test_krb_as_rep(capsys):
    entrypoint.main(
        [
            "--token",
            base64.b64encode(get_data("krb_as_rep")).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "AS-REP (11)"
    assert actual["RawData"] is not None

    assert actual["Data"]["pvno"] == 5
    assert actual["Data"]["msg-type"] == "AS-REP (11)"
    assert actual["Data"]["padata"] == [
        {
            "padata-type": "PA-ETYPE-INFO2 (19)",
            "padata-value": [
                {
                    "etype": "AES256_CTS_HMAC_SHA1_96 (18)",
                    "salt": "444F4D41494E2E4C4F43414C76616772616E742D646F6D61696E",
                    "s2kparams": None,
                },
            ],
        },
    ]
    assert actual["Data"]["crealm"] == "DOMAIN.LOCAL"
    assert actual["Data"]["cname"] == {
        "name-type": "NT-PRINCIPAL (1)",
        "name-string": ["vagrant-domain"],
    }
    assert actual["Data"]["ticket"] == {
        "tkt-vno": 5,
        "realm": "DOMAIN.LOCAL",
        "sname": {
            "name-type": "NT-SRV-INST (2)",
            "name-string": ["krbtgt", "DOMAIN.LOCAL"],
        },
        "enc-part": {
            "etype": "AES256_CTS_HMAC_SHA1_96 (18)",
            "kvno": 2,
            "cipher": actual["Data"]["ticket"]["enc-part"]["cipher"],
        },
    }
    assert actual["Data"]["ticket"]["enc-part"]["cipher"] is not None
    assert actual["Data"]["enc-part"] == {
        "etype": "AES256_CTS_HMAC_SHA1_96 (18)",
        "kvno": 11,
        "cipher": actual["Data"]["enc-part"]["cipher"],
    }
    assert actual["Data"]["enc-part"]["cipher"] is not None


def test_krb_as_req(capsys):
    entrypoint.main(
        [
            "--token",
            base64.b64encode(get_data("krb_as_req")).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "AS-REQ (10)"
    assert actual["RawData"] is not None

    assert actual["Data"]["pvno"] == 5
    assert actual["Data"]["msg-type"] == "AS-REQ (10)"
    assert actual["Data"]["padata"] == [
        {
            "padata-type": "PA-ENC-TIMESTAMP (2)",
            "padata-value": {
                "etype": "AES256_CTS_HMAC_SHA1_96 (18)",
                "kvno": None,
                "cipher": actual["Data"]["padata"][0]["padata-value"]["cipher"],
            },
        },
        {
            "padata-type": "PA-REQ-ENC-PA-REP (149)",
            "padata-value": "",
        },
    ]
    assert actual["Data"]["padata"][0]["padata-value"]["cipher"] is not None
    assert actual["Data"]["req-body"] == {
        "kdc-options": {
            "raw": 1073741824,
            "flags": ["forwardable (1073741824)"],
        },
        "cname": {
            "name-type": "NT-PRINCIPAL (1)",
            "name-string": ["vagrant-domain"],
        },
        "realm": "DOMAIN.LOCAL",
        "sname": {
            "name-type": "NT-SRV-INST (2)",
            "name-string": ["krbtgt", "DOMAIN.LOCAL"],
        },
        "from": None,
        "till": "2020-06-14T07:04:20+00:00",
        "rtime": None,
        "nonce": 734266074,
        "etype": [
            "AES256_CTS_HMAC_SHA1_96 (18)",
            "AES128_CTS_HMAC_SHA1_96 (17)",
            "DES3_CBC_SHA1 (16)",
            "RC4_HMAC (23)",
        ],
        "addresses": None,
        "enc-authorization-data": None,
        "additional-tickets": None,
    }


def test_krb_error(capsys):
    entrypoint.main(
        [
            "--token",
            base64.b64encode(get_data("krb_error")).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "KRB-ERROR (30)"
    assert actual["RawData"] is not None

    assert actual["Data"]["pvno"] == 5
    assert actual["Data"]["msg-type"] == "KRB-ERROR (30)"
    assert actual["Data"]["ctime"] is None
    assert actual["Data"]["cusec"] is None
    assert actual["Data"]["stime"] == "2020-06-13T21:04:23+00:00"
    assert actual["Data"]["susec"] == 748591
    assert actual["Data"]["error-code"] == "KDC_ERR_PREAUTH_REQUIRED (25)"
    assert actual["Data"]["crealm"] is None
    assert actual["Data"]["cname"] is None
    assert actual["Data"]["realm"] == "DOMAIN.LOCAL"
    assert actual["Data"]["sname"] == {"name-type": "NT-SRV-INST (2)", "name-string": ["krbtgt", "DOMAIN.LOCAL"]}
    assert actual["Data"]["e-text"] is None
    assert actual["Data"]["e-data"] is not None


def test_krb_tgs_rep(capsys):
    entrypoint.main(
        [
            "--token",
            base64.b64encode(get_data("krb_tgs_rep")).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "TGS-REP (13)"
    assert actual["RawData"] is not None

    assert actual["Data"]["pvno"] == 5
    assert actual["Data"]["msg-type"] == "TGS-REP (13)"
    assert actual["Data"]["padata"] is None
    assert actual["Data"]["crealm"] == "DOMAIN.LOCAL"
    assert actual["Data"]["cname"] == {
        "name-type": "NT-PRINCIPAL (1)",
        "name-string": ["vagrant-domain"],
    }
    assert actual["Data"]["ticket"] == {
        "tkt-vno": 5,
        "realm": "DOMAIN.LOCAL",
        "sname": {
            "name-type": "NT-SRV-HST (3)",
            "name-string": ["HTTP", "server2019.domain.local"],
        },
        "enc-part": {
            "etype": "AES256_CTS_HMAC_SHA1_96 (18)",
            "kvno": 6,
            "cipher": actual["Data"]["ticket"]["enc-part"]["cipher"],
        },
    }
    assert actual["Data"]["ticket"]["enc-part"]["cipher"] is not None
    assert actual["Data"]["enc-part"] == {
        "etype": "AES256_CTS_HMAC_SHA1_96 (18)",
        "kvno": None,
        "cipher": actual["Data"]["enc-part"]["cipher"],
    }
    assert actual["Data"]["enc-part"]["cipher"] is not None


def test_krb_tgs_req(capsys):
    entrypoint.main(
        [
            "--token",
            base64.b64encode(get_data("krb_tgs_req")).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "TGS-REQ (12)"
    assert actual["RawData"] is not None

    assert actual["Data"]["pvno"] == 5
    assert actual["Data"]["msg-type"] == "TGS-REQ (12)"
    assert len(actual["Data"]["padata"]) == 1
    assert actual["Data"]["padata"][0]["padata-type"] == "PA-TGS-REQ (1)"
    assert actual["Data"]["padata"][0]["padata-value"]["pvno"] == 5
    assert actual["Data"]["padata"][0]["padata-value"]["msg-type"] == "AP-REQ (14)"
    assert actual["Data"]["padata"][0]["padata-value"]["ap-options"] == {
        "raw": 0,
        "flags": [],
    }
    assert actual["Data"]["padata"][0]["padata-value"]["ticket"] == {
        "tkt-vno": 5,
        "realm": "DOMAIN.LOCAL",
        "sname": {"name-type": "NT-SRV-INST (2)", "name-string": ["krbtgt", "DOMAIN.LOCAL"]},
        "enc-part": {
            "etype": "AES256_CTS_HMAC_SHA1_96 (18)",
            "kvno": 2,
            "cipher": actual["Data"]["padata"][0]["padata-value"]["ticket"]["enc-part"]["cipher"],
        },
    }
    assert actual["Data"]["padata"][0]["padata-value"]["ticket"]["enc-part"]["cipher"] is not None
    assert actual["Data"]["padata"][0]["padata-value"]["authenticator"] == {
        "etype": "AES256_CTS_HMAC_SHA1_96 (18)",
        "kvno": None,
        "cipher": actual["Data"]["padata"][0]["padata-value"]["authenticator"]["cipher"],
    }
    assert actual["Data"]["padata"][0]["padata-value"]["authenticator"]["cipher"] is not None

    assert actual["Data"]["req-body"]["kdc-options"] == {
        "raw": 1073807360,
        "flags": ["forwardable (1073741824)", "canonicalize (65536)"],
    }
    assert actual["Data"]["req-body"]["cname"] is None
    assert actual["Data"]["req-body"]["realm"] == "DOMAIN.LOCAL"
    assert actual["Data"]["req-body"]["sname"] == {
        "name-type": "NT-SRV-HST (3)",
        "name-string": ["HTTP", "server2019.domain.local"],
    }
    assert actual["Data"]["req-body"]["from"] is None
    assert actual["Data"]["req-body"]["till"] == "1970-01-01T00:00:00+00:00"
    assert actual["Data"]["req-body"]["rtime"] is None
    assert actual["Data"]["req-body"]["nonce"] == 333512069
    assert actual["Data"]["req-body"]["etype"] == [
        "AES256_CTS_HMAC_SHA1_96 (18)",
        "AES128_CTS_HMAC_SHA1_96 (17)",
        "DES3_CBC_SHA1 (16)",
        "RC4_HMAC (23)",
    ]
    assert actual["Data"]["req-body"]["addresses"] is None
    assert actual["Data"]["req-body"]["enc-authorization-data"] is None
    assert actual["Data"]["req-body"]["additional-tickets"] is None


def test_krb_ap_req_in_initial_context_token(capsys):
    entrypoint.main(
        [
            "--token",
            base64.b64encode(get_data("initial_context_token_krb_ap_rep")).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "SPNEGO InitialContextToken"
    assert actual["RawData"] is not None

    assert actual["Data"]["thisMech"] == "Kerberos (1.2.840.113554.1.2.2)"
    assert actual["Data"]["innerContextToken"]["MessageType"] == "AP-REP (15)"
    assert actual["Data"]["innerContextToken"]["RawData"] is not None
    assert actual["Data"]["innerContextToken"]["Data"]["pvno"] == 5
    assert actual["Data"]["innerContextToken"]["Data"]["msg-type"] == "AP-REP (15)"


def test_neg_token_init(capsys):
    entrypoint.main(
        [
            "--token",
            base64.b64encode(get_data("initial_context_token_neg_token_init")).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "SPNEGO InitialContextToken"
    assert actual["RawData"] is not None

    assert actual["Data"]["thisMech"] == "SPNEGO (1.3.6.1.5.5.2)"
    assert actual["Data"]["innerContextToken"]["MessageType"] == "SPNEGO NegTokenInit"
    assert actual["Data"]["innerContextToken"]["RawData"] is not None
    assert actual["Data"]["innerContextToken"]["Data"]["mechTypes"] == [
        "Kerberos (1.2.840.113554.1.2.2)",
        "NTLM (1.3.6.1.4.1.311.2.2.10)",
    ]
    assert actual["Data"]["innerContextToken"]["Data"]["reqFlags"] is None
    assert actual["Data"]["innerContextToken"]["Data"]["mechListMIC"] is None

    mech_token = actual["Data"]["innerContextToken"]["Data"]["mechToken"]
    assert mech_token is not None

    assert mech_token["MessageType"] == "SPNEGO InitialContextToken"
    assert mech_token["RawData"] is not None

    assert mech_token["Data"]["thisMech"] == "Kerberos (1.2.840.113554.1.2.2)"
    assert mech_token["Data"]["innerContextToken"]["MessageType"] == "AP-REQ (14)"


def test_neg_token_init2(capsys):
    entrypoint.main(
        [
            "--token",
            base64.b64encode(get_data("initial_context_token_neg_token_init2")).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "SPNEGO InitialContextToken"
    assert actual["RawData"] is not None

    assert actual["Data"]["thisMech"] == "SPNEGO (1.3.6.1.5.5.2)"
    assert actual["Data"]["innerContextToken"]["MessageType"] == "SPNEGO NegTokenInit2"
    assert actual["Data"]["innerContextToken"]["RawData"] is not None
    assert actual["Data"]["innerContextToken"]["Data"]["mechTypes"] == [
        "NEGOEX (1.3.6.1.4.1.311.2.2.30)",
        "MS Kerberos (1.2.840.48018.1.2.2)",
        "Kerberos (1.2.840.113554.1.2.2)",
        "Kerberos User to User (1.2.840.113554.1.2.2.3)",
        "NTLM (1.3.6.1.4.1.311.2.2.10)",
    ]
    assert actual["Data"]["innerContextToken"]["Data"]["reqFlags"] is None
    assert actual["Data"]["innerContextToken"]["Data"]["mechToken"] is None
    assert actual["Data"]["innerContextToken"]["Data"]["mechListMIC"] is None
    assert actual["Data"]["innerContextToken"]["Data"]["negHints"] == {
        "hintName": "not_defined_in_RFC4178@please_ignore",
        "hintAddress": None,
    }


def test_neg_token_resp(capsys):
    entrypoint.main(
        [
            "--token",
            base64.b64encode(get_data("neg_token_resp")).decode(),
        ]
    )
    actual_out = capsys.readouterr()

    assert actual_out.err == ""
    actual = json.loads(actual_out.out)

    assert actual["MessageType"] == "SPNEGO NegTokenResp"
    assert actual["RawData"] is not None
    assert actual["Data"]["negState"] == "accept-complete (0)"
    assert actual["Data"]["supportedMech"] == "Kerberos (1.2.840.113554.1.2.2)"
    assert actual["Data"]["responseToken"]["MessageType"] == "SPNEGO InitialContextToken"
    assert actual["Data"]["responseToken"]["Data"]["thisMech"] == "Kerberos (1.2.840.113554.1.2.2)"
    assert actual["Data"]["responseToken"]["Data"]["innerContextToken"]["MessageType"] == "AP-REP (15)"
    assert actual["Data"]["mechListMIC"] is None
