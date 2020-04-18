# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from spnego.sspi.security cimport (
    SecBuffer as NativeSecBuffer,
    SecBufferDesc as NativeSecBufferDesc,
)


cdef class SecBufferDesc:
    cdef NativeSecBufferDesc c_value
    cdef list _buffers


cdef class SecBuffer:
    cdef NativeSecBuffer c_value
    cdef object sys_alloc
