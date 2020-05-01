# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from spnego._context import (
    FeatureFlags,
)


class SpnegoError(Exception):
    pass


class FeatureMissingError(SpnegoError):

    @property
    def feature_id(self):
        return self.args[0]

    @property
    def message(self):
        msg = {
            FeatureFlags.NEGO_KERBEROS: 'The Python gssapi library is not installed so Kerberos cannot be negotiated.',
            FeatureFlags.WRAPPING_IOV: 'The system is missing the GSSAPI IOV extension headers, cannot utilitze '
                                       'wrap_iov and unwrap_iov',
            FeatureFlags.WRAPPING_WINRM: 'The system is missing the GSSAPI IOV extension headers required for WinRM '
                                         'encryption with Kerberos.',

            # The below shouldn't be raised in an exception as it controls the negotiate logic but still have something
            # here just in case.
            FeatureFlags.SESSION_KEY: 'The GSSAPI NTLM mech does not expose a mechanism to extract the session key.',
        }.get(self.feature_id, 'Unknown feature flag: %d' % self.feature_id)

        return msg

    def __str__(self):
        return self.message
