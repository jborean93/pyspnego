# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)
# This is just a test file to test out string handling between Python and C code.

from spnego.sspi.text cimport WideChar
from spnego.sspi.windows cimport (
    GetConsoleTitle,
    SetConsoleTitle,
)


def get_console_title():
    cdef WideChar title

    buffer_size = 1024
    i = 1
    while (True):
        size = buffer_size * i
        title = WideChar(size)
        res = GetConsoleTitle(title.buffer, size)
        if res == 0:
            i += 1
            continue

        return title.to_text(length=res)

def set_console_title(unicode title):
    cdef WideChar console_title = WideChar.from_text(title)
    SetConsoleTitle(console_title.buffer)
