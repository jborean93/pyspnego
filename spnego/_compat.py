# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type  # noqa (fixes E402 for the imports below)

# typing, remove once Python 2.7 is dropped
try:
    from typing import (
        Callable,
        Dict,
        List,
        Optional,
        Tuple,
        Union,
    )

except ImportError:
    Callable = any
    Dict = any
    List = any
    Optional = any
    Tuple = any
    Union = any


# enum.IntFlag, remove once Python 2.7, 3.5 is dropped.
try:
    # IntFlag was added in Python 3.6.
    from enum import (
        Enum,
        IntEnum,
        IntFlag,
    )
except ImportError:
    # IntEnum is similar but the type is lost when using bitwise operations.
    from enum import (
        Enum,
        IntEnum,
    )
    IntFlag = IntEnum
