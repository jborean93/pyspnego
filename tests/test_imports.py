import subprocess
import sys
import textwrap

import pytest


@pytest.mark.parametrize("exception_type", ["ImportError", "OSError"])
def test_unavailable_gssapi_runtime(tmp_path, exception_type):
    # python-gssapi raises OSError when its native Kerberos runtime is missing,
    # such as on Windows without MIT Kerberos for Windows installed.
    (tmp_path / "gssapi.py").write_text(f"raise {exception_type}('missing native GSSAPI runtime')\n")
    script = textwrap.dedent(
        """
        import spnego
        import spnego._gss

        assert not spnego._gss.HAS_GSSAPI
        assert not spnego._gss.HAS_IOV
        assert spnego._gss.GSSAPI_IMP_ERR == 'missing native GSSAPI runtime'
        assert spnego._gss.GSSAPI_IOV_IMP_ERR == 'missing native GSSAPI runtime'

        # A broken optional provider must not prevent other providers being used.
        client = spnego.client('user', 'password', protocol='ntlm')
        assert client.step().startswith(b'NTLMSSP\\x00')

        # Explicit GSSAPI selection retains the native runtime failure diagnostic.
        try:
            spnego.client('user', 'password', options=spnego.NegotiateOptions.use_gssapi)
        except ImportError as error:
            assert 'missing native GSSAPI runtime' in str(error)
        else:
            raise AssertionError('unavailable GSSAPI provider was accepted')
        """
    )
    result = subprocess.run([sys.executable, "-c", script], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
