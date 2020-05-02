import base64
import logging
import os
import re
import socket
import struct
import sys
import tempfile


root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


server = 'dc01.domain.local'
username = 'vagrant-domain@DOMAIN.LOCAL'
password = 'VagrantPass1'


def gssapi_auth(server, username, password):
    from spnego.gssapi import GSSAPIClient

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, 16854))

    package = b"Negotiate"
    s.sendall(struct.pack("<I", len(package)) + package)

    in_token = None
    with tempfile.NamedTemporaryFile() as temp_fd:
        with open(temp_fd.name, mode='wb') as fd:
            fd.write(b':vagrant-domain@DOMAIN.LOCAL:VagrantPass1')

        os.environ['NTLM_USER_FILE'] = temp_fd.name
        c = GSSAPIClient(username, password, server, protocol='negotiate')
        # c = GSSAPIClient(username, password, 'fake', protocol='negotiate')

        while not c.complete or in_token:
            out_token = c.step(in_token)

            if not out_token:
                break

            s.sendall(struct.pack("<I", len(out_token)) + out_token)

            in_token_len = struct.unpack("<I", s.recv(4))[0]
            if in_token_len:
                in_token = s.recv(in_token_len)
            else:
                in_token = None

        #enc_header, enc_data, padding = c.wrap_iov([(2, True, None), (1, False, b"Hello world"), (9, True, None)])
        enc_header, enc_data, padding = c.wrap_winrm(b"Hello world")
        enc_data = enc_header + enc_data + padding

        #enc_data = c.wrap(b"Hello world")

        s.sendall(struct.pack("<I", len(enc_data)) + enc_data)

        server_enc_msg_len = struct.unpack("<I", s.recv(4))[0]
        server_enc_msg = s.recv(server_enc_msg_len)

        # _, dec_msg, _ = n.unwrap_iov((2, False, header), (1, False, data), (1, True, None))
        dec_msg = c.unwrap(server_enc_msg)
        #dec_msg = c.unwrap_winrm(server_enc_msg[:16], server_enc_msg[16:])
        print(dec_msg.decode('utf-8'))

        print("Session key: %s" % base64.b64encode(c.session_key).decode('utf-8'))
        print("Protocol: %s" % c.negotiated_protocol)

        s.close()
        a = ''


def gssapi_auth_local(server, username, password):
    from spnego.gssapi import GSSAPIClient, GSSAPIServer

    # Need to set NTLM_USER_FILE to a file that contains 'domain:username:password'

    c = GSSAPIClient(username, password, server, protocol='ntlm')
    s = GSSAPIServer(username, password, server, protocol='ntlm')

    in_token = None
    while not c.complete:
        out_token = c.step(in_token)
        in_token = s.step(out_token)

    c_enc_msg = c.wrap(b"Hello World")
    s_dec_msg = s.unwrap(c_enc_msg)
    s_enc_msg = s.wrap(s_dec_msg)
    c_dec_msg = c.unwrap(s_enc_msg)

    print(c_dec_msg.decode('utf-8'))
    print("Client Session key: %s" % base64.b64encode(c.session_key).decode('utf-8'))
    print("Server Session key: %s" % base64.b64encode(s.session_key).decode('utf-8'))
    a = ''


def sspi_auth(server, username, password):
    from spnego.sspi import SSPIClient

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, 16854))

    package = b"Negotiate"
    s.sendall(struct.pack("<I", len(package)) + package)

    in_token = None
    c = SSPIClient(username, password, protocol='negotiate', hostname=server, service='HOST')

    while not c.complete:
        out_token = c.step(in_token)

        if not out_token:
            break

        s.sendall(struct.pack("<I", len(out_token)) + out_token)

        in_token_len = struct.unpack("<I", s.recv(4))[0]
        if in_token_len:
            in_token = s.recv(in_token_len)
        else:
            in_token = None

    enc_header, enc_data, padding = c.wrap_winrm(b"Hello world")
    enc_data = enc_header + enc_data + padding

    s.sendall(struct.pack("<I", len(enc_data)) + enc_data)

    server_enc_msg_len = struct.unpack("<I", s.recv(4))[0]
    server_enc_msg = s.recv(server_enc_msg_len)

    dec_msg = c.unwrap(server_enc_msg)
    print(dec_msg.decode('utf-8'))
    print("Session key: %s" % base64.b64encode(c.session_key).decode('utf-8'))
    print("Protocol: %s" % c.negotiated_protocol)

    s.close()
    a = ''


def sspi_auth_local(server, username, password):
    from spnego.sspi import SSPIClient, SSPIServer

    c = SSPIClient(username, password, hostname='localhost')
    s = SSPIServer(server)

    out_token = c.step()
    in_token = s.step(out_token)

    while not c.complete:
        out_token = c.step(in_token)
        in_token = s.step(out_token)

    c_enc_msg = c.wrap(b"Hello World")
    s_dec_msg = s.unwrap(c_enc_msg)
    s_enc_msg = s.wrap(s_dec_msg)
    c_dec_msg = c.unwrap(s_enc_msg)

    print(c_dec_msg.decode('utf-8'))
    print("Client Session key: %s" % base64.b64encode(c.session_key).decode('utf-8'))
    print("Server Session key: %s" % base64.b64encode(s.session_key).decode('utf-8'))
    a = ''



# ntlm_auth(server, username, password)
gssapi_auth(server, username, password)
# gssapi_auth_local(server, u"username@domain", u"password")
# sspi_auth(server, username, password)
# sspi_auth_local(server, username, password)
