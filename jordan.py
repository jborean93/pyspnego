import base64
import logging
import os
import socket
import struct
import sys
import tempfile

import spnego


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


def auth(server, username, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, 16854))

    package = b"Negotiate"
    s.sendall(struct.pack("<I", len(package)) + package)

    in_token = None
    with tempfile.NamedTemporaryFile() as temp_fd:
        with open(temp_fd.name, mode='wb') as fd:
            fd.write(b':vagrant-domain@DOMAIN.LOCAL:VagrantPass1')
            # fd.write(b'vagrant-domain@DOMAIN.LOCAL:1000:00000000000000000000000000000000:35816CD15A8A341DD2828BFC6C375E06:[U]:LCT-1')

        os.environ['NTLM_USER_FILE'] = temp_fd.name
        # os.environ['LM_COMPAT_LEVEL'] = '0'
        c = spnego.client(username, password, server, protocol='ntlm', options=spnego.NegotiateOptions.use_ntlm)

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

        print("Session key: %s" % base64.b64encode(c.session_key).decode('utf-8'))
        print("Protocol: %s" % c.negotiated_protocol)

        enc_data = c.wrap(b"Hello world").data
        s.sendall(struct.pack("<I", len(enc_data)) + enc_data)

        enc_data2 = c.wrap(b"Hello world").data
        s.sendall(struct.pack("<I", len(enc_data2)) + enc_data2)

        server_enc_msg_len = struct.unpack("<I", s.recv(4))[0]
        server_enc_msg = s.recv(server_enc_msg_len)

        dec_msg = c.unwrap(server_enc_msg).data
        print(dec_msg.decode('utf-8'))

        enc_data = c.wrap(b"Jordan").data

        s.sendall(struct.pack("<I", len(enc_data)) + enc_data)

        server_enc_msg_len = struct.unpack("<I", s.recv(4))[0]
        server_enc_msg = s.recv(server_enc_msg_len)

        dec_msg = c.unwrap(server_enc_msg).data
        print(dec_msg.decode('utf-8'))

        s.close()


def auth_local(server, username, password):
    with tempfile.NamedTemporaryFile() as temp_fd:
        with open(temp_fd.name, mode='wb') as fd:
            fd.write((u':%s:%s' % (username, password)).encode('utf-8'))

        os.environ['NTLM_USER_FILE'] = temp_fd.name

        c = spnego.client(username, password, server, protocol='ntlm', options=spnego.NegotiateOptions.use_ntlm)
        s = spnego.server(None, None, server, protocol='ntlm', options=spnego.NegotiateOptions.use_gssapi)
        out_token = c.step()
        _ = c._requires_mech_list_mic  # Test out when a MIC is set
        in_token = s.step(out_token)

        while not c.complete:
            out_token = c.step(in_token)
            if not out_token:
                break

            in_token = s.step(out_token)

        c_enc_msg = c.wrap(b"Hello World")
        s_dec_msg = s.unwrap(c_enc_msg.data)
        s_enc_msg = s.wrap(s_dec_msg.data)
        c_dec_msg = c.unwrap(s_enc_msg.data)

        c_sig = c.sign(b"data")
        s.verify(b"data", c_sig)

        s_sig = s.sign(b"data")
        c.verify(b"data", s_sig)

        print(c_dec_msg.data.decode('utf-8'))
        print("Client Session key: %s" % base64.b64encode(c.session_key).decode('utf-8'))
        print("Server Session key: %s" % base64.b64encode(s.session_key).decode('utf-8'))


# auth(server, username, password)
auth_local(server, username, password)
