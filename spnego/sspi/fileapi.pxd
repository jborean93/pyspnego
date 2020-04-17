from spnego.sspi.windows cimport (
    HANDLE,
)


cdef class FileHandle:
    cdef HANDLE handle
