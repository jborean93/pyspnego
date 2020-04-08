# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from collections import namedtuple


class IOVBufferType:
    GSS_IOV_BUFFER_TYPE_EMPTY = 0
    GSS_IOV_BUFFER_TYPE_DATA = 1
    GSS_IOV_BUFFER_TYPE_HEADER = 2
    GSS_IOV_BUFFER_TYPE_MECH_PARAMS = 3
    GSS_IOV_BUFFER_TYPE_TRAILER = 7
    GSS_IOV_BUFFER_TYPE_PADDING = 9
    GSS_IOV_BUFFER_TYPE_STREAM = 10
    GSS_IOV_BUFFER_TYPE_SIGN_ONLY = 11


IOVBuffer = namedtuple('IOVBuffer', ['type', 'allocate', 'data'])


class IOV:

    def __init__(self, *args):
        a = ''
