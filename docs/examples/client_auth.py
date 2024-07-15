#!/usr/bin/python

import spnego


def exchange_data(data: bytes) -> bytes:
    # Insert code to send to acceptor and receive token
    return b""


def main() -> None:
    client = spnego.client("username", "password", hostname="server")

    in_token = None
    while not client.complete:
        out_token = client.step(in_token)
        if not out_token:
            break

        in_token = exchange_data(out_token)

    print("Negotiated protocol: %s" % client.negotiated_protocol)

    data = b"my secret"
    enc_data = client.wrap(data)

    resp = exchange_data(enc_data.data)
    dec_data = client.unwrap(resp)

    print("Server response: %s" % dec_data.data.decode("utf-8"))


if __name__ == "__main__":
    main()
