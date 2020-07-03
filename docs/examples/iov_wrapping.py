#!/usr/bin/python

import spnego
import spnego.iov
import struct


def exchange_data(data):
    # Insert code to send to acceptor and receive token
    return b""


def main():
    client = spnego.client('username', 'password', hostname='server')

    in_token = None
    while client.complete:
        out_token = client.step(in_token)
        if not out_token:
            break

        in_token = exchange_data(out_token)

    print("Negotiated protocol: %s" % client.negotiated_protocol)

    buffer = [
        spnego.iov.BufferType.header,
        b"my secret",
        spnego.iov.BufferType.padding,
    ]
    enc_result = client.wrap_iov(buffer)

    header = enc_result.buffers[0].data
    enc_data = enc_result.buffers[1].data + enc_result.buffers[2].data or b""

    resp = exchange_data(struct.pack("<I", len(header)) + header + enc_data)
    header_len = struct.unpack("<I", resp[:4])[0]
    header = resp[4:4 + header_len]
    enc_data = resp[4 + header_len:]

    buffer = [
        spnego.iov.IOVBuffer(spnego.iov.BufferType.header, header),
        enc_data,
    ]
    dec_result = client.unwrap_iov(buffer)

    print("Server response: %s" % dec_result.buffers[1].data.decode('utf-8'))


if __name__ == '__main__':
    main()
