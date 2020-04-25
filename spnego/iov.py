# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from collections import namedtuple


class BufferType:
    empty = 0  # SECBUFFER_EMPTY | GSS_IOV_BUFFER_TYPE_EMPTY
    data = 1  # SECBUFFER_DATA | GSS_IOV_BUFFER_TYPE_DATA
    header = 2  # SECBUFFER_TOKEN | GSS_IOV_BUFFER_TYPE_HEADER
    pkg_params = 3  # SECBUFFER_PKG_PARAMS | GSS_IOV_BUFFER_TYPE_MECH_PARAMS
    trailer = 7  # SECBUFFER_STREAM_HEADER | GSS_IOV_BUFFER_TYPE_TRAILER
    padding = 9  # SECBUFFER_PADDING | GSS_IOV_BUFFER_TYPE_PADDING
    stream = 10  # SECBUFFER_STREAM | GSS_IOV_BUFFER_TYPE_STREAM
    sign_only = 11  # SECBUFFER_MECHLIST | GSS_IOV_BUFFER_TYPE_SIGN_ONLY
    mic_token = 12  # SECBUFFER_MECHLIST_SIGNATURE | GSS_IOV_BUFFER_TYPE_MIC_TOKEN


IOVBuffer = namedtuple('IOVBuffer', ['type', 'data'])
