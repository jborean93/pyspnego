import base64
import logging
import re
import socket
import struct
import sys


root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


server = 'server2019.domain.local'
username = 'vagrant-domain@DOMAIN.LOCAL'
password = 'VagrantPass1'


def ntlm_auth(server, username, password):
    from spnego.ntlm import NTLM

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, 16854))

    package = b"NTLM"
    s.sendall(struct.pack("<I", len(package)) + package)

    in_token = None
    n = NTLM(username, password)
    token_gen = n.step()
    while not n.complete:
        out_token = token_gen.send(in_token)

        s.sendall(struct.pack("<I", len(out_token)) + out_token)

        in_token_len = struct.unpack("<I", s.recv(4))[0]
        if in_token_len:
            in_token = s.recv(in_token_len)
        else:
            in_token = None

    enc_header, enc_data = n.wrap(b"Hello world")
    enc_data = enc_header + enc_data
    s.sendall(struct.pack("<I", len(enc_data)) + enc_data)

    dec_msg_len = struct.unpack("<I", s.recv(4))[0]
    dec_meg = s.recv(dec_msg_len)
    a = ''


def gssapi_auth(server, username, password):
    from spnego.gssapi import GSSAPI

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, 16854))

    package = b"Negotiate"
    s.sendall(struct.pack("<I", len(package)) + package)

    in_token = None
    n = GSSAPI(username, password, protocol='kerberos', hostname=server, service='HOST')
    token_gen = n.step()
    while not n.complete:
        out_token = token_gen.send(in_token)

        if not out_token:
            break

        s.sendall(struct.pack("<I", len(out_token)) + out_token)

        in_token_len = struct.unpack("<I", s.recv(4))[0]
        if in_token_len:
            in_token = s.recv(in_token_len)
        else:
            in_token = None

    enc_header, enc_data = n.wrap(b"Hello world")
    enc_data = enc_header + enc_data
    s.sendall(struct.pack("<I", len(enc_data)) + enc_data)

    dec_msg_len = struct.unpack("<I", s.recv(4))[0]
    dec_meg = s.recv(dec_msg_len)
    a = ''


# ntlm_auth(server, username, password)
gssapi_auth(server, username, password)
