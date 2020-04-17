# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from cpython.mem cimport (
    PyMem_Free,
    PyMem_Malloc,
)

from spnego.sspi.windows cimport (
    CP_UTF8,
    LPWSTR,
    MultiByteToWideChar,
    WCHAR,
)


cdef class WideChar:

    def __cinit__(WideChar self, size_t length):
        self._length = length

        self.buffer = <LPWSTR>PyMem_Malloc(length * sizeof(WCHAR))
        if not self.buffer:
            raise MemoryError()

    def __len__(WideChar self):
        return self._length

    def __dealloc__(WideChar self):
        if self.buffer:
            PyMem_Free(self.buffer)

    cdef unicode to_text(WideChar self, size_t length=0):
        return u16_to_text(self.buffer, length if length else self._length)

    @staticmethod
    cdef WideChar from_text(unicode text):
        b_text = text.encode('utf-8', 'strict')

        # Get the expected length of the text as a wide_char array and allocate it
        length = MultiByteToWideChar(CP_UTF8, 0, b_text, -1, NULL, 0)

        # Create the new WideChar object and set the text to the newly allocated buffer.
        wide_char = WideChar(length)
        MultiByteToWideChar(CP_UTF8, 0, b_text, -1, wide_char.buffer, length)
        return wide_char


cdef unicode u16_to_text(LPWSTR s, size_t length):
    return (<char*>s)[:length * sizeof(WCHAR)].decode('utf-16-le', 'strict')
