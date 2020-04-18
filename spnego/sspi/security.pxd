# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from spnego.sspi.windows cimport (
    LONG,
    LPWSTR,
    PVOID,
)


cdef extern from "Security.h":
    # Types
    ctypedef LONG SECURITY_STATUS

    # Defs
    cdef unsigned long SECBUFFER_VERSION

    cdef unsigned long SECBUFFER_EMPTY
    cdef unsigned long SECBUFFER_DATA
    cdef unsigned long SECBUFFER_TOKEN
    cdef unsigned long SECBUFFER_PKG_PARAMS
    cdef unsigned long SECBUFFER_MISSING
    cdef unsigned long SECBUFFER_EXTRA
    cdef unsigned long SECBUFFER_STREAM_TRAILER
    cdef unsigned long SECBUFFER_STREAM_HEADER
    cdef unsigned long SECBUFFER_NEGOTIATION_INFO
    cdef unsigned long SECBUFFER_PADDING
    cdef unsigned long SECBUFFER_STREAM
    cdef unsigned long SECBUFFER_MECHLIST
    cdef unsigned long SECBUFFER_MECHLIST_SIGNATURE
    cdef unsigned long SECBUFFER_TARGET
    cdef unsigned long SECBUFFER_CHANNEL_BINDINGS
    cdef unsigned long SECBUFFER_CHANGE_PASS_RESPONSE
    cdef unsigned long SECBUFFER_TARGET_HOST
    cdef unsigned long SECBUFFER_APPLICATION_PROTOCOLS
    cdef unsigned long SECBUFFER_SRTP_PROTECTION_PROFILES
    cdef unsigned long SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER
    cdef unsigned long SECBUFFER_TOKEN_BINDING
    cdef unsigned long SECBUFFER_PRESHARED_KEY
    cdef unsigned long SECBUFFER_PRESHARED_KEY_IDENTITY

    cdef unsigned long SECBUFFER_ATTRMASK
    cdef unsigned long SECBUFFER_READONLY
    cdef unsigned long SECBUFFER_READONLY_WITH_CHECKSUM
    cdef unsigned long SECBUFFER_RESERVED

    cdef unsigned long SECURITY_NATIVE_DREP
    cdef unsigned long SECURITY_NETWORK_DREP

    cdef unsigned long SECPKG_CRED_INBOUND
    cdef unsigned long SECPKG_CRED_OUTBOUND
    cdef unsigned long SECPKG_CRED_BOTH
    cdef unsigned long SECPKG_CRED_DEFAULT
    cdef unsigned long SECPKG_CRED_RESERVED

    cdef unsigned long ISC_REQ_DELEGATE
    cdef unsigned long ISC_REQ_MUTUAL_AUTH
    cdef unsigned long ISC_REQ_REPLAY_DETECT
    cdef unsigned long ISC_REQ_SEQUENCE_DETECT
    cdef unsigned long ISC_REQ_CONFIDENTIALITY
    cdef unsigned long ISC_REQ_USE_SESSION_KEY
    cdef unsigned long ISC_REQ_PROMPT_FOR_CREDS
    cdef unsigned long ISC_REQ_USE_SUPPLIED_CREDS
    cdef unsigned long ISC_REQ_ALLOCATE_MEMORY
    cdef unsigned long ISC_REQ_USE_DCE_STYLE
    cdef unsigned long ISC_REQ_DATAGRAM
    cdef unsigned long ISC_REQ_CONNECTION
    cdef unsigned long ISC_REQ_CALL_LEVEL
    cdef unsigned long ISC_REQ_FRAGMENT_SUPPLIED
    cdef unsigned long ISC_REQ_EXTENDED_ERROR
    cdef unsigned long ISC_REQ_STREAM
    cdef unsigned long ISC_REQ_INTEGRITY
    cdef unsigned long ISC_REQ_IDENTIFY
    cdef unsigned long ISC_REQ_NULL_SESSION
    cdef unsigned long ISC_REQ_MANUAL_CRED_VALIDATION
    cdef unsigned long ISC_REQ_RESERVED1
    cdef unsigned long ISC_REQ_FRAGMENT_TO_FIT
    cdef unsigned long ISC_REQ_FORWARD_CREDENTIALS
    cdef unsigned long ISC_REQ_NO_INTEGRITY
    cdef unsigned long ISC_REQ_USE_HTTP_STYLE
    cdef unsigned long ISC_REQ_UNVERIFIED_TARGET_NAME
    cdef unsigned long ISC_REQ_CONFIDENTIALITY_ONLY

    cdef unsigned long ISC_RET_DELEGATE
    cdef unsigned long ISC_RET_MUTUAL_AUTH
    cdef unsigned long ISC_RET_REPLAY_DETECT
    cdef unsigned long ISC_RET_SEQUENCE_DETECT
    cdef unsigned long ISC_RET_CONFIDENTIALITY
    cdef unsigned long ISC_RET_USE_SESSION_KEY
    cdef unsigned long ISC_RET_USED_COLLECTED_CREDS
    cdef unsigned long ISC_RET_USED_SUPPLIED_CREDS
    cdef unsigned long ISC_RET_ALLOCATED_MEMORY
    cdef unsigned long ISC_RET_USED_DCE_STYLE
    cdef unsigned long ISC_RET_DATAGRAM
    cdef unsigned long ISC_RET_CONNECTION
    cdef unsigned long ISC_RET_INTERMEDIATE_RETURN
    cdef unsigned long ISC_RET_CALL_LEVEL
    cdef unsigned long ISC_RET_EXTENDED_ERROR
    cdef unsigned long ISC_RET_STREAM
    cdef unsigned long ISC_RET_INTEGRITY
    cdef unsigned long ISC_RET_IDENTIFY
    cdef unsigned long ISC_RET_NULL_SESSION
    cdef unsigned long ISC_RET_MANUAL_CRED_VALIDATION
    cdef unsigned long ISC_RET_RESERVED1
    cdef unsigned long ISC_RET_FRAGMENT_ONLY
    cdef unsigned long ISC_RET_FORWARD_CREDENTIALS
    cdef unsigned long ISC_RET_USED_HTTP_STYLE
    cdef unsigned long ISC_RET_NO_ADDITIONAL_TOKEN
    cdef unsigned long ISC_RET_REAUTHENTICATION
    cdef unsigned long ISC_RET_CONFIDENTIALITY_ONLY

    # Structs
    struct _SecBuffer:
        unsigned long cbBuffer
        unsigned long BufferType
        void *pvBuffer
    ctypedef _SecBuffer SecBuffer
    ctypedef SecBuffer *PSecBuffer

    struct _SecBufferDesc:
        unsigned long ulVersion
        unsigned long cBuffers
        PSecBuffer pBuffers
    ctypedef _SecBufferDesc SecBufferDesc
    ctypedef SecBufferDesc *PSecBufferDesc

    struct _SecHandle:
        pass
    ctypedef _SecHandle SecHandle
    ctypedef SecHandle *PSecHandle

    ctypedef SecHandle CredHandle
    ctypedef PSecHandle PCredHandle

    ctypedef SecHandle CtxtHandle
    ctypedef PSecHandle PCtxtHandle

    ctypedef struct _SECURITY_INTEGER:
        unsigned long LowPart
        long HighPart
    ctypedef _SECURITY_INTEGER SECURITY_INTEGER
    ctypedef SECURITY_INTEGER *PSECURITY_INTEGER
    ctypedef SECURITY_INTEGER TimeStamp
    ctypedef SECURITY_INTEGER *PTimeStamp

    # Functions
    SECURITY_STATUS __stdcall AcquireCredentialsHandleW(
        LPWSTR pPrincipal,
        LPWSTR pPackage,
        unsigned long    fCredentialUse,
        void             *pvLogonId,
        void             *pAuthData,
        void             *pGetKeyFn,
        void             *pvGetKeyArgument,
        PCredHandle      phCredential,
        PTimeStamp       ptsExpiry
    )

    SECURITY_STATUS __stdcall DeleteSecurityContext(
        PCtxtHandle phContext
    )

    SECURITY_STATUS __stdcall FreeContextBuffer(
        PVOID pvContextBuffer
    )

    SECURITY_STATUS __stdcall FreeCredentialsHandle(
        PCredHandle phCredential
    )

    SECURITY_STATUS __stdcall InitializeSecurityContextW(
        PCredHandle      phCredential,
        PCtxtHandle      phContext,
        LPWSTR           pTargetName,
        unsigned long    fContextReq,
        unsigned long    Reserved1,
        unsigned long    TargetDataRep,
        PSecBufferDesc   pInput,
        unsigned long    Reserved2,
        PCtxtHandle      phNewContext,
        PSecBufferDesc   pOutput,
        unsigned long    *pfContextAttr,
        PTimeStamp       ptsExpiry
    )
