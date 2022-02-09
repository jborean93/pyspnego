#!/usr/bin/python

import base64
import socket

import spnego


def main() -> None:
    server = socket.gethostname()
    username = 'vagrant-domain@DOMAIN.LOCAL'
    password = 'VagrantPass1'

    c = spnego.client(username, password, server)
    s = spnego.server(server)

    in_token = None
    while not c.complete:
        out_token = c.step(in_token)
        if not out_token:
            break

        in_token = s.step(out_token)

    print("Client Session key: %s" % base64.b64encode(c.session_key).decode('utf-8'))
    print("Server Session key: %s" % base64.b64encode(s.session_key).decode('utf-8'))
    print("Authenticated client: %s" % s.client_principal)

    c_enc_msg = c.wrap(b"Hello World")
    s_dec_msg = s.unwrap(c_enc_msg.data)
    s_enc_msg = s.wrap(s_dec_msg.data)
    c_dec_msg = c.unwrap(s_enc_msg.data)

    c_sig = c.sign(b"data")
    s.verify(b"data", c_sig)

    s_sig = s.sign(b"data")
    c.verify(b"data", s_sig)


if __name__ == '__main__':
    main()
