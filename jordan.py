import base64
import re
import socket
import struct


server = 'server2019.domain.local'
username = 'vagrant-domain@DOMAIN.LOCAL'
password = 'VagrantPass1'


def ntlm_auth(server, username, password):
    from spnego.ntlm import NTLM

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, 16854))

    s.sendall(struct.pack("<I", 9) + b"Negotiate")

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

ntlm_auth(server, username, password)
