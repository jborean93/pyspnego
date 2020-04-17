from cpython.exc cimport (
    PyErr_SetFromWindowsErr,
)

from spnego.sspi.windows cimport (
    CreateFileW,
    CloseHandle,
    DWORD,
    GetLastError,
    HANDLE,
    INVALID_HANDLE_VALUE,
    LPWSTR,
    LPSECURITY_ATTRIBUTES,
)

from spnego.sspi.text cimport WideChar

cdef class FileHandle:

    def __cinit__(FileHandle self):
        self.handle = INVALID_HANDLE_VALUE

    def __dealloc__(FileHandle self):
        if self.handle != INVALID_HANDLE_VALUE:
            CloseHandle(self.handle)


def create_file(unicode file_name, desired_access, share_mode, creation_disposition,
    flags_and_attributes):

    cdef FileHandle fh = FileHandle()
    cdef WideChar w_file_name = WideChar.from_text(file_name)

    fh.handle = CreateFileW(
        w_file_name.buffer,
        desired_access,
        share_mode,
        NULL,
        creation_disposition,
        flags_and_attributes,
        NULL
    )

    if fh.handle == INVALID_HANDLE_VALUE:
        PyErr_SetFromWindowsErr(0)

    return fh
