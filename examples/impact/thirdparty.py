# -*- coding: utf-8 -*-
from filetype.types import Type


class LegacyJpeg(Type):
    MIME = "image/x-legacy-jpeg"
    EXTENSION = "legacy-jpg"

    def __init__(self):
        super(LegacyJpeg, self).__init__(
            mime=LegacyJpeg.MIME,
            extension=LegacyJpeg.EXTENSION,
        )

    def match(self, buf):
        return (len(buf) > 2 and
                buf[0] == 0xFF and
                buf[1] == 0xD8 and
                buf[2] == 0xFF)


class FooType(Type):
    MIME = "application/x-foo"
    EXTENSION = "foo"

    def __init__(self):
        super(FooType, self).__init__(
            mime=FooType.MIME,
            extension=FooType.EXTENSION,
        )

    def match(self, buf):
        return bytes(buf[:4]) == b"FOO\x00"


class BrokenType(Type):
    MIME = "application/x-broken"
    EXTENSION = "broken"

    def __init__(self):
        super(BrokenType, self).__init__(
            mime=BrokenType.MIME,
            extension=BrokenType.EXTENSION,
        )

    def match(self, buf):
        raise RuntimeError("third-party matcher exploded")
