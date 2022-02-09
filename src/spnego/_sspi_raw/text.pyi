# Copyright: (c) 2022, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing as t

class WideChar:

    length: int

    def __new__(
        self,
        length: int,
    ) -> "WideChar": ...
    def __len__(self) -> int: ...
    def to_text(
        self,
        length: int = 0,
    ) -> str: ...
    @staticmethod
    def from_text(
        text: str,
    ) -> "WideChar": ...
