# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from cpython.exc cimport (
    PyErr_SetFromWindowsErr,
)

from libc.stdlib cimport (
    free,
    malloc,
)

from libc.string cimport (
    memcpy,
)

from spnego.sspi.security cimport (
    AcquireCredentialsHandleW,
    CredHandle,
    CtxtHandle,
    DeleteSecurityContext,
    FreeContextBuffer,
    FreeCredentialsHandle,
    InitializeSecurityContextW,
    PCtxtHandle,
    SecBuffer as NativeSecBuffer,
    SecBufferDesc as NativeSecBufferDesc,
    SECBUFFER_VERSION,
    SECPKG_CRED_INBOUND,
    SECURITY_INTEGER,
    SECURITY_NATIVE_DREP,
)

from spnego.sspi.text cimport (
    WideChar,
)


cdef class Credential:
    cdef CredHandle handle
    cdef readonly unsigned long long expiry

    def __cinit__(Credential self):
        self.handle = CredHandle()
        self.expiry = 0

    def __dealloc__(Credential self):
        if self.expiry:
            FreeCredentialsHandle(&self.handle)


cdef class SecurityContext:
    cdef CtxtHandle handle
    cdef readonly unsigned long context_attr
    cdef readonly unsigned long long expiry

    def __cinit__(SecurityContext self):
        self.handle = CtxtHandle()
        self.context_attr = 0
        self.expiry = 0

    def __dealloc__(SecurityContext self):
        if self.expiry:
            DeleteSecurityContext(&self.handle)


cdef class SecBufferDesc:

    def __cinit__(SecBufferDesc self, list buffers not None):
        self.c_value = NativeSecBufferDesc(SECBUFFER_VERSION, len(buffers), NULL)

    def __len__(SecBufferDesc self):
        return self.c_value.cBuffers

    #def __dealloc__(SecBufferDesc self):
    #    free(self._sec_buffer)


cdef class SecBuffer:

    def __cinit__(SecBuffer self, unsigned long buffer_type, bytes buffer=None, sys_alloc=False):
        if sys_alloc and buffer:
            raise ValueError("Cannot sys_alloc a buffer with an existing buffer value")

        self.sys_alloc = sys_alloc
        self.c_value = NativeSecBuffer(0, buffer_type, NULL)
        if buffer:
            self.buffer = buffer

    @property
    def buffer_type(SecBuffer self):
        return self.c_value.BufferType

    @buffer_type.setter
    def buffer_type(SecBuffer self, unsigned long value):
        self.c_value.BufferType = value

    @property
    def buffer(SecBuffer self):
        if self.c_value.cbBuffer and self.c_value.pvBuffer != NULL:
            return (<char *>self.c_value.pvBuffer)[:self.c_value.cbBuffer]
        else:
            return b""

    @buffer.setter
    def buffer(SecBuffer self, bytes value):
        if self.sys_alloc:
            raise ValueError("Cannot set a buffer value for a sys_alloc SecBuffer")

        if self.c_value.pvBuffer:
            free(self.c_value.pvBuffer)
            self.c_value.pvBuffer = NULL

        self.c_value.pvBuffer = malloc(len(value))
        if not self.c_value.pvBuffer:
            raise MemoryError("Cannot malloc SecBuffer buffer")

        memcpy(self.c_value.pvBuffer, <char *>value, len(value))
        self.c_value.cbBuffer = len(value)

    def __dealloc__(SecBuffer self):
        if self.c_value.pvBuffer:
            if self.sys_alloc:
                FreeContextBuffer(self.c_value.pvBuffer)
            else:
                free(self.c_value.pvBuffer)

            self.c_value.pvBuffer = NULL


def acquire_credentials_handle(unicode principal, unicode package not None):
    cdef WideChar w_principal = WideChar.from_text(principal)
    cdef WideChar w_package = WideChar.from_text(package)
    cdef Credential cred = Credential()
    cdef SECURITY_INTEGER expiry

    res = AcquireCredentialsHandleW(w_principal.buffer, w_package.buffer, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL,
        &cred.handle, &expiry)

    if res != 0:
        PyErr_SetFromWindowsErr(res)
    cred.expiry = (expiry.HighPart << 32) | expiry.LowPart

    return cred


def initialize_security_context(Credential credential not None, SecurityContext context not None,
    unicode target_name not None, unsigned long context_req, SecBufferDesc input_buffer=None):

    #cdef PCtxtHandle input_context = &context.handle if context.expiry else NULL
    #cdef WideChar w_target_name = WideChar.from_text(target_name)
    #cdef PSecBufferDesc output
    #cdef SECURITY_INTEGER expiry

    #res = InitializeSecurityContextW(&credential.handle, input_context, w_target_name.buffer, context_req, 0,
    #    SECURITY_NATIVE_DREP, NULL, 0, &context.handle, output, &context.context_attr, &expiry)

    #if res != 0:
    #    PyErr_SetFromWindowsErr(res)
    #context.expiry = (expiry.HighPart << 32) | expiry.LowPart

    return
