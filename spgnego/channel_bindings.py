# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class GssChannelBindings:

    def __init__(self, initiator_addrtype=None, initiator_address=None, acceptor_addrtype=None, acceptor_address=None,
                 application_data=None):
        self.initiator_addrtype = initiator_addrtype
        self.initiator_address = initiator_address
        self.acceptor_addrtype = acceptor_addrtype
        self.acceptor_address = acceptor_address
        self.application_data = application_data

    def get_data(self):
        # TODO: return byte representation of struct.
        return b""
