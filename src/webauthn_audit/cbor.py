from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import Any


class CBORError(ValueError):
    pass


@dataclass
class Decoder:
    data: bytes
    offset: int = 0
    max_depth: int = 32
    max_items: int = 10_000
    items: int = 0

    def decode(self, depth: int = 0) -> Any:
        if depth > self.max_depth:
            raise CBORError("CBOR nesting limit exceeded")
        if self.offset >= len(self.data):
            raise CBORError("truncated CBOR")
        self.items += 1
        if self.items > self.max_items:
            raise CBORError("CBOR item limit exceeded")
        initial = self._take(1)[0]
        major, additional = initial >> 5, initial & 31
        if additional == 31:
            raise CBORError("indefinite-length CBOR is not accepted")
        argument = self._argument(additional)
        if major == 0:
            return argument
        if major == 1:
            return -1 - argument
        if major == 2:
            return self._take(argument)
        if major == 3:
            try:
                return self._take(argument).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CBORError("invalid UTF-8 in CBOR text") from exc
        if major == 4:
            return [self.decode(depth + 1) for _ in range(argument)]
        if major == 5:
            result: dict[Any, Any] = {}
            for _ in range(argument):
                key = self.decode(depth + 1)
                try:
                    if key in result:
                        raise CBORError("duplicate CBOR map key")
                    result[key] = self.decode(depth + 1)
                except TypeError as exc:
                    raise CBORError("unhashable CBOR map key") from exc
            return result
        if major == 6:
            return {"__cbor_tag__": argument, "value": self.decode(depth + 1)}
        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional in (22, 23):
                return None
            if additional == 25:
                return struct.unpack(">e", argument.to_bytes(2, "big"))[0]
            if additional == 26:
                return struct.unpack(">f", argument.to_bytes(4, "big"))[0]
            if additional == 27:
                value = struct.unpack(">d", argument.to_bytes(8, "big"))[0]
                if not math.isfinite(value):
                    raise CBORError("non-finite CBOR float")
                return value
            return {"__cbor_simple__": argument}
        raise CBORError("unsupported CBOR major type")

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            raise CBORError("reserved CBOR additional information")
        return int.from_bytes(self._take(width), "big")

    def _take(self, amount: int) -> bytes:
        end = self.offset + amount
        if amount < 0 or end > len(self.data):
            raise CBORError("truncated CBOR")
        value = self.data[self.offset : end]
        self.offset = end
        return value


def decode_one(data: bytes, *, require_eof: bool = True) -> tuple[Any, int]:
    decoder = Decoder(data)
    value = decoder.decode()
    if require_eof and decoder.offset != len(data):
        raise CBORError("trailing bytes after CBOR value")
    return value, decoder.offset
