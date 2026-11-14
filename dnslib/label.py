# -*- coding: utf-8 -*-

"""
    DNSLabel/DNSBuffer - DNS label handling & encoding/decoding
"""

from __future__ import print_function

import fnmatch,re,string

from dnslib.bit import get_bits,set_bits
from dnslib.buffer import Buffer, BufferError

# In theory valid label characters should be letters,digits,hyphen,underscore (LDH)
# LDH = set(bytearray(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'))
# For compatibility we only escape non-printable characters
LDH = set(range(33,127))
ESCAPE = re.compile(r'\\([0-9][0-9][0-9])')

# Strict bounds for (possibly compressed) name decompression (RFC 1035)
MAX_LABEL_SIZE = 63          # Max length of an uncompressed label
MAX_NAME_SIZE = 255          # Max expanded name length in wire octets
MAX_LABEL_COUNT = 127        # Max number of labels in an expanded name
MAX_POINTER_HOPS = 127       # Max compression pointers followed per name

class DNSLabelError(Exception):
    pass

class DNSDecodeError(BufferError):
    """Base class for errors decoding a (possibly compressed) DNS name"""

class DNSPointerOutOfBoundsError(DNSDecodeError):
    """Compression pointer references an offset outside the message"""

class DNSCompressionLoopError(DNSDecodeError):
    """Compression pointer is forward/self-referential or repeats an offset"""

class DNSNameTooLongError(DNSDecodeError):
    """Expanded name exceeds the label count / name size limits"""

class DNSInvalidLabelError(DNSDecodeError):
    """Uncompressed label has an invalid type, length or content"""

class DNSLabel(object):

    """
    Container for DNS label

    Supports IDNA encoding for unicode domain names

    >>> l1 = DNSLabel("aaa.bbb.ccc.")
    >>> l2 = DNSLabel([b"aaa",b"bbb",b"ccc"])
    >>> l1 == l2
    True
    >>> l3 = DNSLabel("AAA.BBB.CCC")
    >>> l1 == l3
    True
    >>> l1 == 'AAA.BBB.CCC'
    True
    >>> x = { l1 : 1 }
    >>> x[l1]
    1
    >>> l1
    <DNSLabel: 'aaa.bbb.ccc.'>
    >>> str(l1)
    'aaa.bbb.ccc.'
    >>> l3 = l1.add("xxx.yyy")
    >>> l3
    <DNSLabel: 'xxx.yyy.aaa.bbb.ccc.'>
    >>> l3.matchSuffix(l1)
    True
    >>> l3.matchSuffix("xxx.yyy.")
    False
    >>> l3.matchSuffix("Bbb.ccc.")
    True
    >>> l3.stripSuffix("bbb.ccc.")
    <DNSLabel: 'xxx.yyy.aaa.'>
    >>> l3.matchGlob("*.[abc]aa.BBB.ccc")
    True
    >>> l3.matchGlob("*.[abc]xx.bbb.ccc")
    False
    >>> l1.matchWildcard("*.bbb.ccc")
    True
    >>> l1.matchWildcard("*.CCC")
    True
    >>> l1.matchWildcard("*.xxx.bbb.ccc")
    False
    >>> l1.matchWildcard("aaa.bbb.ccc")
    True
    >>> l1.matchWildcard("bbb.ccc")
    False
    >>> l1.matchWildcard("xxx.aaa.bbb.ccc")
    False

    # Too hard to get unicode doctests to work on Python 3.2
    # (works on 3.3)
    # >>> u1 = DNSLabel(u'\u2295.com')
    # >>> u1.__str__() == u'\u2295.com.'
    # True
    # >>> u1.label == ( b"xn--keh", b"com" )
    # True

    """
    def __init__(self,label):
        """
            Create DNS label instance

            Label can be specified as:
            - a list/tuple of byte strings
            - a byte string (split into components separated by b'.')
            - a unicode string which will be encoded according to RFC3490/IDNA
        """
        if type(label) == DNSLabel:
            self.label = label.label
        elif type(label) in (list,tuple):
            self.label = tuple(label)
        else:
            if not label or label in (b'.','.'):
                self.label = ()
            elif type(label) is not bytes:
                if type('') != type(b''):
                    # Py3
                    label = ESCAPE.sub(lambda m:chr(int(m[1])),label)
                self.label = tuple(label.encode("idna").\
                                rstrip(b".").split(b"."))
            else:
                if type('') == type(b''):
                    # Py2
                    label = ESCAPE.sub(lambda m:chr(int(m.groups()[0])),label)
                self.label = tuple(label.rstrip(b".").split(b"."))

    def add(self,name):
        """
            Prepend name to label
        """
        new = DNSLabel(name)
        if self.label:
            new.label += self.label
        return new

    def matchGlob(self,pattern):
        if type(pattern) != DNSLabel:
            pattern = DNSLabel(pattern)
        return fnmatch.fnmatch(str(self).lower(),str(pattern).lower())

    def matchWildcard(self,pattern):
        """
            Wildcard match according to https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.3   
            (This only allows a single '*' prefix wildcard which matches one or more labels)

            Note that the spec is defined at the zone level (if there is a more
            specific overlapping match within the zone) some soem additional
            logic is required in the resolved to implement this.

        """
        if type(pattern) != DNSLabel:
            pattern = DNSLabel(pattern)
        if pattern.label[0] != b'*' and len(self.label) != len(pattern.label):
            # No wildcard - number of labels must match
            return False
        for (a,b) in zip(reversed(self.label),reversed(pattern.label)):
            if b != b'*' and a.lower() != b.lower():
                return False
        return True

    def matchSuffix(self,suffix):
        """
            Return True if label suffix matches
        """
        suffix = DNSLabel(suffix)
        return DNSLabel(self.label[-len(suffix.label):]) == suffix

    def stripSuffix(self,suffix):
        """
            Strip suffix from label
        """
        suffix = DNSLabel(suffix)
        if self.matchSuffix(suffix):
            return DNSLabel(self.label[:-len(suffix.label)])
        else:
            return self

    def idna(self):
        return ".".join([ s.decode("idna") for s in self.label ]) + "."

    def _decode(self,s):
        if set(s).issubset(LDH):
            # All chars in LDH
            return s.decode()
        else:
            # Need to encode
            return "".join([(chr(c) if (c in LDH) else "\\%03d" % c) for c in s])

    def __str__(self):
        return ".".join([ self._decode(bytearray(s)) for s in self.label ]) + "."

    def __repr__(self):
        return "<DNSLabel: '%s'>" % str(self)

    def __hash__(self):
        return hash(tuple(map(lambda x:x.lower(),self.label)))

    def __ne__(self,other):
        return not self == other

    def __eq__(self,other):
        if type(other) != DNSLabel:
            return self.__eq__(DNSLabel(other))
        else:
            return [ l.lower() for l in self.label ] == \
                   [ l.lower() for l in other.label ]

    def __len__(self):
        return len(b'.'.join(self.label))

class DNSBuffer(Buffer):

    """
    Extends Buffer to provide DNS name encoding/decoding (with caching)

    # Needed for Python 2/3 doctest compatibility
    >>> def p(s):
    ...     if not isinstance(s,str):
    ...         return s.decode()
    ...     return s

    >>> b = DNSBuffer()
    >>> b.encode_name(b'aaa.bbb.ccc.')
    >>> len(b)
    13
    >>> b.encode_name(b'aaa.bbb.ccc.')
    >>> len(b)
    15
    >>> b.encode_name(b'xxx.yyy.zzz')
    >>> len(b)
    28
    >>> b.encode_name(b'zzz.xxx.bbb.ccc.')
    >>> len(b)
    38
    >>> b.encode_name(b'aaa.xxx.bbb.ccc')
    >>> len(b)
    44
    >>> b.offset = 0
    >>> print(b.decode_name())
    aaa.bbb.ccc.
    >>> print(b.decode_name())
    aaa.bbb.ccc.
    >>> print(b.decode_name())
    xxx.yyy.zzz.
    >>> print(b.decode_name())
    zzz.xxx.bbb.ccc.
    >>> print(b.decode_name())
    aaa.xxx.bbb.ccc.

    >>> b = DNSBuffer()
    >>> b.encode_name([b'a.aa',b'b.bb',b'c.cc'])
    >>> b.offset = 0
    >>> len(b.decode_name().label)
    3

    >>> b = DNSBuffer()
    >>> b.encode_name_nocompress(b'aaa.bbb.ccc.')
    >>> len(b)
    13
    >>> b.encode_name_nocompress(b'aaa.bbb.ccc.')
    >>> len(b)
    26
    >>> b.offset = 0
    >>> print(b.decode_name())
    aaa.bbb.ccc.
    >>> print(b.decode_name())
    aaa.bbb.ccc.
    """

    def __init__(self,data=b''):
        """
            Add 'names' dict to cache stored labels
        """
        super(DNSBuffer,self).__init__(data)
        self.names = {}

    def decode_name(self):
        """
            Decode label at current offset in buffer, following compression
            pointers where necessary.

            Decompression is iterative (never recursive) and enforces strict
            bounds:

            - Compression pointers must point strictly backwards to an offset
              within the message; self loops, forward jumps and repeated
              offsets are rejected.
            - The expanded name is bounded by label count, wire size and
              total pointer hop limits.
            - Uncompressed labels are validated for type, length and content.

            On failure the buffer offset is restored to the start of the name
            so a failed name cannot corrupt parsing of subsequent records.
        """
        start = self.offset
        label = []
        visited = set()
        pointer_hops = 0
        wire_size = 1
        end = None
        done = False
        try:
            while not done:
                if self.remaining() < 1:
                    raise DNSDecodeError("Truncated label length octet in DNSLabel "\
                            "[offset=%d,length=%d]" % (self.offset,len(self.data)))
                length = self.data[self.offset]
                label_type = get_bits(length,6,2)
                if label_type == 3:
                    # Compression pointer (two octets)
                    if self.remaining() < 2:
                        raise DNSPointerOutOfBoundsError("Truncated compression pointer "\
                                "in DNSLabel [offset=%d,length=%d]" %
                                (self.offset,len(self.data)))
                    source = self.offset
                    pointer = get_bits(self.unpack("!H")[0],0,14)
                    if end is None:
                        # Name ends in the enclosing stream after the pointer
                        end = self.offset
                    pointer_hops += 1
                    if pointer_hops > MAX_POINTER_HOPS:
                        raise DNSCompressionLoopError("Too many compression pointer hops "\
                                "in DNSLabel [offset=%d,pointer=%d,hops=%d]" %
                                (self.offset,pointer,pointer_hops))
                    if pointer >= len(self.data):
                        raise DNSPointerOutOfBoundsError("Compression pointer outside "\
                                "message in DNSLabel [offset=%d,pointer=%d,length=%d]" %
                                (self.offset,pointer,len(self.data)))
                    if pointer >= source:
                        # Pointers may only point to data strictly earlier
                        # than the pointer itself
                        raise DNSCompressionLoopError("Invalid/recursive compression "\
                                "pointer in DNSLabel [offset=%d,pointer=%d,length=%d]" %
                                (self.offset,pointer,len(self.data)))
                    if pointer in visited:
                        # Repeated offset in the pointer chain - a loop
                        raise DNSCompressionLoopError("Repeated name offset in DNSLabel "\
                                "[offset=%d,pointer=%d,length=%d]" %
                                (self.offset,pointer,len(self.data)))
                    visited.add(source)
                    self.offset = pointer
                elif label_type == 0:
                    # Uncompressed label
                    self.offset += 1
                    size = get_bits(length,0,6)
                    if size > MAX_LABEL_SIZE:
                        raise DNSInvalidLabelError("Label component too long in "\
                                "DNSLabel [offset=%d,size=%d]" % (self.offset,size))
                    if self.remaining() < size:
                        raise DNSInvalidLabelError("Truncated label in DNSLabel "\
                                "[offset=%d,size=%d,length=%d]" %
                                (self.offset,size,len(self.data)))
                    if size > 0:
                        component = self.get(size)
                        try:
                            component.decode()
                        except UnicodeDecodeError:
                            raise DNSInvalidLabelError("Invalid label <%s>" % component)
                        label.append(component)
                        if len(label) > MAX_LABEL_COUNT:
                            raise DNSNameTooLongError("Too many label components in "\
                                    "DNSLabel [offset=%d,limit=%d]" %
                                    (self.offset,MAX_LABEL_COUNT))
                        wire_size += size + 1
                        if wire_size > MAX_NAME_SIZE:
                            raise DNSNameTooLongError("Domain label too long in "\
                                    "DNSLabel [offset=%d,wire_size=%d,limit=%d]" %
                                    (self.offset,wire_size,MAX_NAME_SIZE))
                    else:
                        # Root label - end of name
                        done = True
                else:
                    # Reserved label types (0b01 / 0b10) are not valid names
                    raise DNSInvalidLabelError("Invalid label type in DNSLabel "\
                            "[offset=%d,type=%d]" % (self.offset,label_type))
        except BufferError:
            self.offset = start
            raise
        if end is not None:
            self.offset = end
        return DNSLabel(label)

    def encode_name(self,name):
        """
            Encode label and store at end of buffer (compressing
            cached elements where needed) and store elements
            in 'names' dict
        """
        if not isinstance(name,DNSLabel):
            name = DNSLabel(name)
        if len(name) > 253:
            raise DNSLabelError("Domain label too long: %r" % name)
        name = list(name.label)
        while name:
            if tuple(name) in self.names:
                # Cached - set pointer
                pointer = self.names[tuple(name)]
                pointer = set_bits(pointer,3,14,2)
                self.pack("!H",pointer)
                return
            else:
                self.names[tuple(name)] = self.offset
                element = name.pop(0)
                if len(element) > 63:
                    raise DNSLabelError("Label component too long: %r" % element)
                self.pack("!B",len(element))
                self.append(element)
        self.append(b'\x00')

    def encode_name_nocompress(self,name):
        """
            Encode and store label with no compression
            (needed for RRSIG, SRV, NSEC)
        """
        if not isinstance(name,DNSLabel):
            name = DNSLabel(name)
        if len(name) > 253:
            raise DNSLabelError("Domain label too long: %r" % name)
        name = list(name.label)
        while name:
            element = name.pop(0)
            if len(element) > 63:
                raise DNSLabelError("Label component too long: %r" % element)
            self.pack("!B",len(element))
            self.append(element)
        self.append(b'\x00')

if __name__ == '__main__':
    import doctest,sys
    sys.exit(0 if doctest.testmod().failed == 0 else 1)
