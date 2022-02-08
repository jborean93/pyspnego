#!/usr/bin/python

import struct

import spnego
import spnego.iov


def exchange_data(data: bytes) -> bytes:
    # Insert code to send to acceptor and receive token
    return b""


def main() -> None:
    client = spnego.client('username', 'password', hostname='server')

    in_token = None
    while client.complete:
        out_token = client.step(in_token)
        if not out_token:
            break

        in_token = exchange_data(out_token)

    print("Negotiated protocol: %s" % client.negotiated_protocol)

    enc_result = client.wrap_iov([
        spnego.iov.BufferType.header,
        b"my secret",
        spnego.iov.BufferType.padding,
    ])

    header = enc_result.buffers[0].data or b""
    enc_data = enc_result.buffers[1].data or b""
    padding = enc_result.buffers[2].data or b""
    enc_payload = struct.pack("<I", len(header)) + header + enc_data + padding

    resp = exchange_data(enc_payload)
    header_len = struct.unpack("<I", resp[:4])[0]
    header = resp[4:4 + header_len]
    enc_data = resp[4 + header_len:]

    dec_result = client.unwrap_iov([
        spnego.iov.IOVBuffer(spnego.iov.BufferType.header, header),
        enc_data,
    ])
    dec_data = dec_result.buffers[1].data or b""

    print("Server response: %s" % dec_data.decode('utf-8'))


if __name__ == '__main__':
    main()
