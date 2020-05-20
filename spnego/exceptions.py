# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from spnego._compat import (
    add_metaclass,

    Optional,
    Union,

    IntEnum,
)

from spnego._text import (
    text_type,
    to_native,
)

try:
    from gssapi.exceptions import GSSError
except ImportError:
    GSSError = ()

try:
    WinError = WindowsError
except NameError:
    WinError = ()


class ErrorCode(IntEnum):
    """Common error codes for SPNEGO operations.

    Mostly a copy of the `GSS major error codes`_ with the names made more pythonic.

    .. _GSS major error codes:
        https://docs.oracle.com/cd/E19683-01/816-1331/reference-4/index.html
    """
    bad_mech = 1
    bad_named = 2
    bad_nametype = 3
    bad_bindings = 4
    bad_status = 5
    bad_mic = 6
    no_cred = 7
    no_context = 8
    invalid_token = 9
    invalid_credential = 10
    credentials_expired = 11
    context_expired = 12
    failure = 13
    bad_qop = 14
    unauthorized = 15
    unavailable = 16
    duplicate_element = 17
    name_not_mn = 18


# Implementation is inspired by the python-gssapi project https://github.com/pythongssapi/python-gssapi.
# https://github.com/pythongssapi/python-gssapi/blob/826c02de1c1885896924bf342c60087f369c6b1a/gssapi/raw/misc.pyx#L180
class _SpnegoErrorRegistry(type):
    __registry = {}
    __gssapi_map = {}
    __sspi_map = {}

    def __init__(cls, name, bases, attributes):
        # Load up the registry with the instantiated class so we can look it up when creating a SpnegoError.
        error_code = getattr(cls, 'ERROR_CODE', None)

        if error_code is not None and error_code not in cls.__registry:
            cls.__registry[error_code] = cls

        # Map the system error codes to the common spnego error code.
        for system_attr, mapping in [('_GSSAPI_CODE', cls.__gssapi_map), ('_SSPI_CODE', cls.__sspi_map)]:
            codes = getattr(cls, system_attr, None)

            if codes is None:
                continue

            if not isinstance(codes, (list, tuple)):
                codes = [codes]

            for c in codes:
                mapping[c] = error_code

    def __call__(cls, error_code=None, base_error=None, *args, **kwargs):
        error_code = error_code if error_code is not None else getattr(cls, 'ERROR_CODE', None)

        if error_code is None:
            if not base_error:
                raise ValueError("%s requires either an error_code or base_error" % cls.__name__)

            if hasattr(base_error, 'maj_code'):
                error_code = cls.__gssapi_map.get(base_error.maj_code, None)

            elif hasattr(base_error, 'winerror'):
                error_code = cls.__sspi_map.get(base_error.winerror, None)

            else:
                raise ValueError("base_error of type '%s' is not supported, must be a gssapi.exceptions.GSSError or "
                                 "WindowsError" % type(base_error).__name__)

        new_cls = cls.__registry.get(error_code, cls)
        return super(_SpnegoErrorRegistry, new_cls).__call__(error_code, base_error, *args, **kwargs)


@add_metaclass(_SpnegoErrorRegistry)
class SpnegoError(Exception):
    """Common error for SPNEGO exception.

    Creates an common error record for SPNEGO errors raised by pyspnego. This error record can wrap system level error
    records raised by GSSAPI or SSPI and wrap them into a common error record across the various platforms.

    Args:
        error_code: The ErrorCode for the error, this must be set if base_error is not set.
        base_error: The system level error from SSPI or GSSAPI, this must be set if error_code is not set.
        context_msg: Optional message to provide more context around the error.

    Attributes:
        base_error (Optional[Union[GSSError, WinError]]): The system level error if one was provided.
    """

    # Classes the subclass this type need to provide the following class attribute:
    #
    # ERROR_CODE = common ErrorCode value for the exception
    # _BASE_MESSAGE = common string that explains the error code
    #
    # The following attributes are used to map specific system error codes to the common ErrorCode error.
    # _GSSAPI_CODE = The GSSAPI major_code from GSSError to map to the common error code
    # _SSPI_CODE = The winerror value from an WindowsError to map to the common error code

    def __init__(self, error_code=None, base_error=None, context_msg=None):
        self.base_error = base_error  # type: Optional[Union[GSSError, WinError]]
        self._error_code = error_code  # type: Optional[ErrorCode]
        self._context_message = context_msg  # type: Optional[text_type]

        super(SpnegoError, self).__init__(self.message)

    def __str__(self):
        msg = self.message

        # We want to preserve the base error message if possible in the exception output.
        if self.base_error:
            msg += "\nBase Error: %s" % str(self.base_error)

        return to_native(msg)

    @property
    def message(self):
        error_code = self._error_code if self._error_code is not None else 0xFFFFFFFF
        base_message = getattr(self, '_BASE_MESSAGE', 'Unknown error code')

        msg = "SpnegoError (%d): %s" % (error_code, base_message)
        if self._context_message:
            msg += " - %s" % self._context_message

        return msg


class InvalidTokenError(SpnegoError):
    ERROR_CODE = ErrorCode.invalid_token

    _BASE_MESSAGE = "A token was invalid"
    _GSSAPI_CODE = 589824  # None | GSS_S_DEFECTIVE_TOKEN | None
    _SSPI_TOKEN = -2146893048  # SEC_E_INVALID_TOKEN


class OperationNotAvailableError(SpnegoError):
    ERROR_CODE = ErrorCode.unavailable

    _BASE_MESSAGE = "Operation not supported or available"
    _GSSAPI_CODE = 1048576  # None | GSS_S_UNAVAILABLE | None
    _SSPI_CODE = -2146893054  # SEC_E_UNSUPPORTED_FUNCTION
