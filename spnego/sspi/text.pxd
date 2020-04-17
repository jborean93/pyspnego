# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from spnego.sspi.windows cimport LPWSTR


cdef unicode u16_to_text(LPWSTR s, size_t length)

cdef class WideChar:
    cdef LPWSTR buffer
    cdef int _length

    cdef unicode to_text(WideChar self, size_t length=*)

    @staticmethod
    cdef WideChar from_text(unicode text)
