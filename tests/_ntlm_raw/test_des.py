# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os

import pytest

from spnego._ntlm_raw.des import DES


def test_des_invalid_key_size():
    with pytest.raises(ValueError, match="DES encryption key should be 8 bytes in length") as exc:
        DES(b"\x01\x02")


def test_expand_56bit_key():
    expected = b"\x01\x80\x80\x61\x40\x29\x19\x0E"
    actual = DES.key56_to_key64(b"\x01\x02\x03\x04\x05\x06\x07")
    assert actual == expected

    expected = b"\x51\x20\x54\x6b\x34\xba\x3d\xa4"
    actual = DES.key56_to_key64(b"PASSWOR")
    assert actual == expected

    expected = b"\x45\x01\x01\x01\x01\x01\x01\x01"
    actual = DES.key56_to_key64(b"D\x00\x00\x00\x00\x00\x00")
    assert actual == expected


def test_encrypt_block():
    with pytest.raises(ValueError, match="DES 7-byte key is not 7 bytes in length, actual: 1") as exc:
        DES.key56_to_key64(b"\x00")


def test_encrypt():
    des = DES(b"PASSWORD")
    expected = b"\x15\x14\x4f\x75\x8c\x83\xd0\x34"
    actual = des.encrypt(b"abcdefgh")
    assert actual == expected


def test_encrypt_large_bytes_padding():
    des = DES(b"PASSWORD")
    expected = (
        b"\x15\x14\x4f\x75\x8c\x83\xd0\x34"
        b"\xe6\x19\x4b\xe6\x51\x22\xe3\x91"
        b"\x68\x02\xa9\xd8\x6c\x04\x1f\x2d"
        b"\x95\x1d\xc7\x12\xe4\x7c\x79\x04"
    )
    actual = des.encrypt(b"abcdefghijklmnopqrstuvwxyz")
    assert actual == expected


def test_decrypt():
    des = DES(b"PASSWORD")
    expected = b"abcdefgh"
    actual = des.decrypt(b"\x15\x14\x4f\x75\x8c\x83\xd0\x34")
    assert actual == expected


def test_decrypt_large_bytes_padding():
    des = DES(b"PASSWORD")
    expected = b"abcdefghijklmnopqrstuvwxyz\x00\x00\x00\x00\x00\x00"
    data = (
        b"\x15\x14\x4f\x75\x8c\x83\xd0\x34"
        b"\xe6\x19\x4b\xe6\x51\x22\xe3\x91"
        b"\x68\x02\xa9\xd8\x6c\x04\x1f\x2d"
        b"\x95\x1d\xc7\x12\xe4\x7c\x79\x04"
    )
    actual = des.decrypt(data)
    assert actual == expected


def test_decrypt_fail_invalid_size():
    with pytest.raises(ValueError, match="DES decryption block must be a multiple of 8 bytes") as exc:
        des = DES(b"PASSWORD")
        des.decrypt(b"\x01\x02\x03\x04")


def test_encrypt_decrypt_multiple_keys():
    # run random tests with random keys and data
    for i in range(512):
        des = DES(os.urandom(8))
        data = os.urandom(16)
        enc_data = des.encrypt(data)
        dec_data = des.decrypt(enc_data)
        assert enc_data != data
        assert dec_data == data
