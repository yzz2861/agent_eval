"""
olefile (formerly OleFileIO_PL)

Module to read/write Microsoft OLE2 files (also called Structured Storage or
Microsoft Compound Document File Format), such as Microsoft Office 97-2003
documents, Image Composer and FlashPix files, Outlook messages, ...
This version is compatible with Python 2.7 and 3.5+

Project website: https://www.decalage.info/olefile

olefile is copyright (c) 2005-2023 Philippe Lagadec
(https://www.decalage.info)

olefile is based on the OleFileIO module from the PIL library v1.1.7
See: http://www.pythonware.com/products/pil/index.htm
and http://svn.effbot.org/public/tags/pil-1.1.7/PIL/OleFileIO.py

The Python Imaging Library (PIL) is
Copyright (c) 1997-2009 by Secret Labs AB
Copyright (c) 1995-2009 by Fredrik Lundh

See source code and LICENSE.txt for information on usage and redistribution.
"""

# Since olefile v0.47, only Python 2.7 and 3.5+ are supported
# This import enables print() as a function rather than a keyword
# (main requirement to be compatible with Python 3.x)
# The comment on the line below should be printed on Python 2.5 or older:
from __future__ import print_function   # This version of olefile requires Python 2.7 or 3.5+.


#--- LICENSE ------------------------------------------------------------------

# olefile (formerly OleFileIO_PL) is copyright (c) 2005-2023 Philippe Lagadec
# (https://www.decalage.info)
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# ----------
# PIL License:
#
# olefile is based on source code from the OleFileIO module of the Python
# Imaging Library (PIL) published by Fredrik Lundh under the following license:

# The Python Imaging Library (PIL) is
#    Copyright (c) 1997-2009 by Secret Labs AB
#    Copyright (c) 1995-2009 by Fredrik Lundh
#
# By obtaining, using, and/or copying this software and/or its associated
# documentation, you agree that you have read, understood, and will comply with
# the following terms and conditions:
#
# Permission to use, copy, modify, and distribute this software and its
# associated documentation for any purpose and without fee is hereby granted,
# provided that the above copyright notice appears in all copies, and that both
# that copyright notice and this permission notice appear in supporting
# documentation, and that the name of Secret Labs AB or the author(s) not be used
# in advertising or publicity pertaining to distribution of the software
# without specific, written prior permission.
#
# SECRET LABS AB AND THE AUTHORS DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
# SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.
# IN NO EVENT SHALL SECRET LABS AB OR THE AUTHORS BE LIABLE FOR ANY SPECIAL,
# INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

__date__    = "2023-12-01"
__version__ = '0.47'
__author__  = "Philippe Lagadec"

__all__ = ['isOleFile', 'OleFileIO', 'OleMetadata', 'enable_logging',
           'OleExportManifest', 'build_export_manifest', 'forensic_manifest',
           'export_manifest', 'forensic_checklist',
           'build_export_checklist', 'pre_export_checklist', 'forensic_export_manifest',
           'MAGIC', 'STGTY_EMPTY',
           'STGTY_STREAM', 'STGTY_STORAGE', 'STGTY_ROOT', 'STGTY_PROPERTY',
           'STGTY_LOCKBYTES', 'MINIMAL_OLEFILE_SIZE',
           'DEFECT_UNSURE', 'DEFECT_POTENTIAL', 'DEFECT_INCORRECT',
           'DEFECT_FATAL', 'DEFAULT_PATH_ENCODING',
           'MAXREGSECT', 'DIFSECT', 'FATSECT', 'ENDOFCHAIN', 'FREESECT',
           'MAXREGSID', 'NOSTREAM', 'UNKNOWN_SIZE', 'WORD_CLSID',
           'OleFileIONotClosed'
]

import io
import sys
import struct, array, os.path, datetime, logging, warnings, traceback

#=== COMPATIBILITY WORKAROUNDS ================================================

# For Python 3.x, need to redefine long as int:
if str is not bytes:
    long = int

# Need to make sure we use xrange both on Python 2 and 3.x:
try:
    # on Python 2 we need xrange:
    iterrange = xrange
except Exception:
    # no xrange, for Python 3 it was renamed as range:
    iterrange = range

# [PL] workaround to fix an issue with array item size on 64 bits systems:
if array.array('L').itemsize == 4:
    # on 32 bits platforms, long integers in an array are 32 bits:
    UINT32 = 'L'
elif array.array('I').itemsize == 4:
    # on 64 bits platforms, integers in an array are 32 bits:
    UINT32 = 'I'
elif array.array('i').itemsize == 4:
    # On 64 bit Jython, signed integers ('i') are the only way to store our 32
    # bit values in an array in a *somewhat* reasonable way, as the otherwise
    # perfectly suited 'H' (unsigned int, 32 bits) results in a completely
    # unusable behaviour. This is most likely caused by the fact that Java
    # doesn't have unsigned values, and thus Jython's "array" implementation,
    # which is based on "jarray", doesn't have them either.
    # NOTE: to trick Jython into converting the values it would normally
    # interpret as "signed" into "unsigned", a binary-and operation with
    # 0xFFFFFFFF can be used. This way it is possible to use the same comparing
    # operations on all platforms / implementations. The corresponding code
    # lines are flagged with a 'JYTHON-WORKAROUND' tag below.
    UINT32 = 'i'
else:
    raise ValueError('Need to fix a bug with 32 bit arrays, please contact author...')


# [PL] These workarounds were inspired from the Path module
# (see http://www.jorendorff.com/articles/python/path/)
# TODO: remove the use of basestring, as it was removed in Python 3
try:
    basestring
except NameError:
    basestring = str

if sys.version_info[0] < 3:
    # On Python 2.x, the default encoding for path names is UTF-8:
    DEFAULT_PATH_ENCODING = 'utf-8'
else:
    # On Python 3.x, the default encoding for path names is Unicode (None):
    DEFAULT_PATH_ENCODING = None


# === LOGGING =================================================================

def get_logger(name, level=logging.CRITICAL+1):
    """
    Create a suitable logger object for this module.
    The goal is not to change settings of the root logger, to avoid getting
    other modules' logs on the screen.
    If a logger exists with same name, reuse it. (Else it would have duplicate
    handlers and messages would be doubled.)
    The level is set to CRITICAL+1 by default, to avoid any logging.
    """
    # First, test if there is already a logger with the same name, else it
    # will generate duplicate messages (due to duplicate handlers):
    if name in logging.Logger.manager.loggerDict:
        #NOTE: another less intrusive but more "hackish" solution would be to
        # use getLogger then test if its effective level is not default.
        logger = logging.getLogger(name)
        # make sure level is OK:
        logger.setLevel(level)
        return logger
    # get a new logger:
    logger = logging.getLogger(name)
    # only add a NullHandler for this logger, it is up to the application
    # to configure its own logging:
    logger.addHandler(logging.NullHandler())
    logger.setLevel(level)
    return logger


# a global logger object used for debugging:
log = get_logger('olefile')


def enable_logging():
    """
    Enable logging for this module (disabled by default).
    This will set the module-specific logger level to NOTSET, which
    means the main application controls the actual logging level.
    """
    log.setLevel(logging.NOTSET)


#=== CONSTANTS ===============================================================

#: magic bytes that should be at the beginning of every OLE file:
MAGIC = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'

# [PL]: added constants for Sector IDs (from AAF specifications)
MAXREGSECT = 0xFFFFFFFA #: (-6) maximum SECT
DIFSECT    = 0xFFFFFFFC #: (-4) denotes a DIFAT sector in a FAT
FATSECT    = 0xFFFFFFFD #: (-3) denotes a FAT sector in a FAT
ENDOFCHAIN = 0xFFFFFFFE #: (-2) end of a virtual stream chain
FREESECT   = 0xFFFFFFFF #: (-1) unallocated sector

# [PL]: added constants for Directory Entry IDs (from AAF specifications)
MAXREGSID  = 0xFFFFFFFA #: (-6) maximum directory entry ID
NOSTREAM   = 0xFFFFFFFF #: (-1) unallocated directory entry

# [PL] object types in storage (from AAF specifications)
STGTY_EMPTY     = 0 #: empty directory entry
STGTY_STORAGE   = 1 #: element is a storage object
STGTY_STREAM    = 2 #: element is a stream object
STGTY_LOCKBYTES = 3 #: element is an ILockBytes object
STGTY_PROPERTY  = 4 #: element is an IPropertyStorage object
STGTY_ROOT      = 5 #: element is a root storage

# Unknown size for a stream (used by OleStream):
UNKNOWN_SIZE = 0x7FFFFFFF

#
# --------------------------------------------------------------------
# property types

VT_EMPTY=0; VT_NULL=1; VT_I2=2; VT_I4=3; VT_R4=4; VT_R8=5; VT_CY=6;
VT_DATE=7; VT_BSTR=8; VT_DISPATCH=9; VT_ERROR=10; VT_BOOL=11;
VT_VARIANT=12; VT_UNKNOWN=13; VT_DECIMAL=14; VT_I1=16; VT_UI1=17;
VT_UI2=18; VT_UI4=19; VT_I8=20; VT_UI8=21; VT_INT=22; VT_UINT=23;
VT_VOID=24; VT_HRESULT=25; VT_PTR=26; VT_SAFEARRAY=27; VT_CARRAY=28;
VT_USERDEFINED=29; VT_LPSTR=30; VT_LPWSTR=31; VT_FILETIME=64;
VT_BLOB=65; VT_STREAM=66; VT_STORAGE=67; VT_STREAMED_OBJECT=68;
VT_STORED_OBJECT=69; VT_BLOB_OBJECT=70; VT_CF=71; VT_CLSID=72;
VT_VECTOR=0x1000;

# map property id to name (for debugging purposes)
VT = {}
for keyword, var in list(vars().items()):
    if keyword[:3] == "VT_":
        VT[var] = keyword

#
# --------------------------------------------------------------------
# Some common document types (root.clsid fields)

WORD_CLSID = "00020900-0000-0000-C000-000000000046"
# TODO: check Excel, PPT, ...

# [PL]: Defect levels to classify parsing errors - see OleFileIO._raise_defect()
DEFECT_UNSURE =    10    # a case which looks weird, but not sure it's a defect
DEFECT_POTENTIAL = 20    # a potential defect
DEFECT_INCORRECT = 30    # an error according to specifications, but parsing
                         # can go on
DEFECT_FATAL =     40    # an error which cannot be ignored, parsing is
                         # impossible

# Minimal size of an empty OLE file, with 512-bytes sectors = 1536 bytes
# (this is used in isOleFile and OleFileIO.open)
MINIMAL_OLEFILE_SIZE = 1536

#=== FUNCTIONS ===============================================================

def isOleFile (filename=None, data=None):
    """
    Test if a file is an OLE container (according to the magic bytes in its header).

    .. note::
        This function only checks the first 8 bytes of the file, not the
        rest of the OLE structure.
        If data is provided, it also checks if the file size is above
        the minimal size of an OLE file (1536 bytes).
        If filename is provided with the path of the file on disk, the file is
        open only to read the first 8 bytes, then closed.

    .. versionadded:: 0.16

    :param filename: filename, contents or file-like object of the OLE file (string-like or file-like object)

        - if data is provided, filename is ignored.
        - if filename is a unicode string, it is used as path of the file to open on disk.
        - if filename is a bytes string smaller than 1536 bytes, it is used as path
          of the file to open on disk.
        - [deprecated] if filename is a bytes string longer than 1535 bytes, it is parsed
          as the content of an OLE file in memory. (bytes type only)
          Note that this use case is deprecated and should be replaced by the new data parameter
        - if filename is a file-like object (with read and seek methods),
          it is parsed as-is.
    :type filename: bytes, str, unicode or file-like object

    :param data: bytes string with the contents of the file to be checked, when the file is in memory
                 (added in olefile 0.47)
    :type data: bytes

    :returns: True if OLE, False otherwise.
    :rtype: bool
    """
    header = None
    # first check if data is provided and large enough
    if data is not None:
        if len(data) >= MINIMAL_OLEFILE_SIZE:
            header = data[:len(MAGIC)]
        else:
            # the file is too small, cannot be OLE
            return False
    # check if filename is a string-like or file-like object:
    elif hasattr(filename, 'read') and hasattr(filename, 'seek'):
        # file-like object: use it directly
        header = filename.read(len(MAGIC))
        # just in case, seek back to start of file:
        filename.seek(0)
    elif isinstance(filename, bytes) and len(filename) >= MINIMAL_OLEFILE_SIZE:
        # filename is a bytes string containing the OLE file to be parsed:
        header = filename[:len(MAGIC)]
    else:
        # string-like object: filename of file on disk
        with open(filename, 'rb') as fp:
            header = fp.read(len(MAGIC))
    if header == MAGIC:
        return True
    else:
        return False


if bytes is str:
    # version for Python 2.x
    def i8(c):
        return ord(c)
else:
    # version for Python 3.x
    def i8(c):
        return c if c.__class__ is int else c[0]


def i16(c, o = 0):
    """
    Converts a 2-bytes (16 bits) string to an integer.

    :param c: string containing bytes to convert
    :param o: offset of bytes to convert in string
    """
    return struct.unpack("<H", c[o:o+2])[0]


def i32(c, o = 0):
    """
    Converts a 4-bytes (32 bits) string to an integer.

    :param c: string containing bytes to convert
    :param o: offset of bytes to convert in string
    """
    return struct.unpack("<I", c[o:o+4])[0]


def _clsid(clsid):
    """
    Converts a CLSID to a human-readable string.

    :param clsid: string of length 16.
    """
    assert len(clsid) == 16
    # if clsid is only made of null bytes, return an empty string:
    # (PL: why not simply return the string with zeroes?)
    if not clsid.strip(b"\0"):
        return ""
    return (("%08X-%04X-%04X-%02X%02X-" + "%02X" * 6) %
            ((i32(clsid, 0), i16(clsid, 4), i16(clsid, 6)) +
            tuple(map(i8, clsid[8:16]))))



def filetime2datetime(filetime):
    """
    convert FILETIME (64 bits int) to Python datetime.datetime
    """
    # TODO: manage exception when microseconds is too large
    # inspired from https://code.activestate.com/recipes/511425-filetime-to-datetime/
    _FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)
    # log.debug('timedelta days=%d' % (filetime//(10*1000000*3600*24)))
    return _FILETIME_null_date + datetime.timedelta(microseconds=filetime//10)



#=== CLASSES ==================================================================

class OleFileError(IOError):
    """
    Generic base error for this module.
    """
    pass

class NotOleFileError(OleFileError):
    """
    Error raised when the opened file is not an OLE file.
    """
    pass

class OleMetadata:
    """
    Class to parse and store metadata from standard properties of OLE files.

    Available attributes:
    codepage, title, subject, author, keywords, comments, template,
    last_saved_by, revision_number, total_edit_time, last_printed, create_time,
    last_saved_time, num_pages, num_words, num_chars, thumbnail,
    creating_application, security, codepage_doc, category, presentation_target,
    bytes, lines, paragraphs, slides, notes, hidden_slides, mm_clips,
    scale_crop, heading_pairs, titles_of_parts, manager, company, links_dirty,
    chars_with_spaces, unused, shared_doc, link_base, hlinks, hlinks_changed,
    version, dig_sig, content_type, content_status, language, doc_version

    Note: an attribute is set to None when not present in the properties of the
    OLE file.

    References for SummaryInformation stream:

    - https://msdn.microsoft.com/en-us/library/dd942545.aspx
    - https://msdn.microsoft.com/en-us/library/dd925819%28v=office.12%29.aspx
    - https://msdn.microsoft.com/en-us/library/windows/desktop/aa380376%28v=vs.85%29.aspx
    - https://msdn.microsoft.com/en-us/library/aa372045.aspx
    - http://sedna-soft.de/articles/summary-information-stream/
    - https://poi.apache.org/apidocs/org/apache/poi/hpsf/SummaryInformation.html

    References for DocumentSummaryInformation stream:

    - https://msdn.microsoft.com/en-us/library/dd945671%28v=office.12%29.aspx
    - https://msdn.microsoft.com/en-us/library/windows/desktop/aa380374%28v=vs.85%29.aspx
    - https://poi.apache.org/apidocs/org/apache/poi/hpsf/DocumentSummaryInformation.html

    New in version 0.25
    """

    # attribute names for SummaryInformation stream properties:
    # (ordered by property id, starting at 1)
    SUMMARY_ATTRIBS = ['codepage', 'title', 'subject', 'author', 'keywords', 'comments',
        'template', 'last_saved_by', 'revision_number', 'total_edit_time',
        'last_printed', 'create_time', 'last_saved_time', 'num_pages',
        'num_words', 'num_chars', 'thumbnail', 'creating_application',
        'security']

    # attribute names for DocumentSummaryInformation stream properties:
    # (ordered by property id, starting at 1)
    DOCSUM_ATTRIBS = ['codepage_doc', 'category', 'presentation_target', 'bytes', 'lines', 'paragraphs',
        'slides', 'notes', 'hidden_slides', 'mm_clips',
        'scale_crop', 'heading_pairs', 'titles_of_parts', 'manager',
        'company', 'links_dirty', 'chars_with_spaces', 'unused', 'shared_doc',
        'link_base', 'hlinks', 'hlinks_changed', 'version', 'dig_sig',
        'content_type', 'content_status', 'language', 'doc_version']

    def __init__(self):
        """
        Constructor for OleMetadata
        All attributes are set to None by default
        """
        # properties from SummaryInformation stream
        self.codepage = None
        self.title = None
        self.subject = None
        self.author = None
        self.keywords = None
        self.comments = None
        self.template = None
        self.last_saved_by = None
        self.revision_number = None
        self.total_edit_time = None
        self.last_printed = None
        self.create_time = None
        self.last_saved_time = None
        self.num_pages = None
        self.num_words = None
        self.num_chars = None
        self.thumbnail = None
        self.creating_application = None
        self.security = None
        # properties from DocumentSummaryInformation stream
        self.codepage_doc = None
        self.category = None
        self.presentation_target = None
        self.bytes = None
        self.lines = None
        self.paragraphs = None
        self.slides = None
        self.notes = None
        self.hidden_slides = None
        self.mm_clips = None
        self.scale_crop = None
        self.heading_pairs = None
        self.titles_of_parts = None
        self.manager = None
        self.company = None
        self.links_dirty = None
        self.chars_with_spaces = None
        self.unused = None
        self.shared_doc = None
        self.link_base = None
        self.hlinks = None
        self.hlinks_changed = None
        self.version = None
        self.dig_sig = None
        self.content_type = None
        self.content_status = None
        self.language = None
        self.doc_version = None

    def parse_properties(self, ole_file):
        """
        Parse standard properties of an OLE file, from the streams
        ``\\x05SummaryInformation`` and ``\\x05DocumentSummaryInformation``,
        if present.
        Properties are converted to strings, integers or python datetime objects.
        If a property is not present, its value is set to None.

        :param ole_file: OleFileIO object from which to parse properties
        """
        # first set all attributes to None:
        for attrib in (self.SUMMARY_ATTRIBS + self.DOCSUM_ATTRIBS):
            setattr(self, attrib, None)
        if ole_file.exists("\x05SummaryInformation"):
            # get properties from the stream:
            # (converting timestamps to python datetime, except total_edit_time,
            # which is property #10)
            props = ole_file.getproperties("\x05SummaryInformation",
                                           convert_time=True, no_conversion=[10])
            # store them into this object's attributes:
            for i in range(len(self.SUMMARY_ATTRIBS)):
                # ids for standards properties start at 0x01, until 0x13
                value = props.get(i+1, None)
                setattr(self, self.SUMMARY_ATTRIBS[i], value)
        if ole_file.exists("\x05DocumentSummaryInformation"):
            # get properties from the stream:
            props = ole_file.getproperties("\x05DocumentSummaryInformation",
                                           convert_time=True)
            # store them into this object's attributes:
            for i in range(len(self.DOCSUM_ATTRIBS)):
                # ids for standards properties start at 0x01, until 0x13
                value = props.get(i+1, None)
                setattr(self, self.DOCSUM_ATTRIBS[i], value)

    def dump(self):
        """
        Dump all metadata, for debugging purposes.
        """
        print('Properties from SummaryInformation stream:')
        for prop in self.SUMMARY_ATTRIBS:
            value = getattr(self, prop)
            print('- {}: {}'.format(prop, repr(value)))
        print('Properties from DocumentSummaryInformation stream:')
        for prop in self.DOCSUM_ATTRIBS:
            value = getattr(self, prop)
            print('- {}: {}'.format(prop, repr(value)))

class OleFileIONotClosed(RuntimeWarning):
    """
    Warning type used when OleFileIO is destructed but has open file handle.
    """
    def __init__(self, stack_of_open=None):
        super(OleFileIONotClosed, self).__init__()
        self.stack_of_open = stack_of_open

    def __str__(self):
        msg = 'Deleting OleFileIO instance with open file handle. ' \
              'You should ensure that OleFileIO is never deleted ' \
              'without calling close() first. Consider using '\
              '"with OleFileIO(...) as ole: ...".'
        if self.stack_of_open:
            return ''.join([msg, '\n', 'Stacktrace of open() call:\n'] +
                           self.stack_of_open.format())
        else:
            return msg


# --- OleStream ---------------------------------------------------------------

class OleStream(io.BytesIO):
    """
    OLE2 Stream

    Returns a read-only file object which can be used to read
    the contents of a OLE stream (instance of the BytesIO class).
    To open a stream, use the openstream method in the OleFileIO class.

    This function can be used with either ordinary streams,
    or ministreams, depending on the offset, sectorsize, and
    fat table arguments.

    Attributes:

        - size: actual size of data stream, after it was opened.
    """
    # FIXME: should store the list of sects obtained by following
    # the fat chain, and load new sectors on demand instead of
    # loading it all in one go.

    def __init__(self, fp, sect, size, offset, sectorsize, fat, filesize, olefileio):
        """
        Constructor for OleStream class.

        :param fp: file object, the OLE container or the MiniFAT stream
        :param sect: sector index of first sector in the stream
        :param size: total size of the stream
        :param offset: offset in bytes for the first FAT or MiniFAT sector
        :param sectorsize: size of one sector
        :param fat: array/list of sector indexes (FAT or MiniFAT)
        :param filesize: size of OLE file (for debugging)
        :param olefileio: OleFileIO object containing this stream
        :returns: a BytesIO instance containing the OLE stream
        """
        log.debug('OleStream.__init__:')
        log.debug('  sect=%d (%X), size=%d, offset=%d, sectorsize=%d, len(fat)=%d, fp=%s'
            %(sect,sect,size,offset,sectorsize,len(fat), repr(fp)))
        self.ole = olefileio
        # this check is necessary, otherwise when attempting to open a stream
        # from a closed OleFileIO, a stream of size zero is returned without
        # raising an exception. (see issue #81)
        if self.ole.fp.closed:
            raise OSError('Attempting to open a stream from a closed OLE File')
        # [PL] To detect malformed documents with FAT loops, we compute the
        # expected number of sectors in the stream:
        unknown_size = False
        if size == UNKNOWN_SIZE:
            # this is the case when called from OleFileIO._open(), and stream
            # size is not known in advance (for example when reading the
            # Directory stream). Then we can only guess maximum size:
            size = len(fat)*sectorsize
            # and we keep a record that size was unknown:
            unknown_size = True
            log.debug('  stream with UNKNOWN SIZE')
        nb_sectors = (size + (sectorsize-1)) // sectorsize
        log.debug('nb_sectors = %d' % nb_sectors)
        # This number should (at least) be less than the total number of
        # sectors in the given FAT:
        if nb_sectors > len(fat):
            self.ole._raise_defect(DEFECT_INCORRECT, 'malformed OLE document, stream too large')
        # optimization(?): data is first a list of strings, and join() is called
        # at the end to concatenate all in one string.
        # (this may not be really useful with recent Python versions)
        data = []
        # if size is zero, then first sector index should be ENDOFCHAIN:
        if size == 0 and sect != ENDOFCHAIN:
            log.debug('size == 0 and sect != ENDOFCHAIN:')
            self.ole._raise_defect(DEFECT_INCORRECT, 'incorrect OLE sector index for empty stream')
        # [PL] A fixed-length for loop is used instead of an undefined while
        # loop to avoid DoS attacks:
        for i in range(nb_sectors):
            log.debug('Reading stream sector[%d] = %Xh' % (i, sect))
            # Sector index may be ENDOFCHAIN, but only if size was unknown
            if sect == ENDOFCHAIN:
                if unknown_size:
                    log.debug('Reached ENDOFCHAIN sector for stream with unknown size')
                    break
                else:
                    # else this means that the stream is smaller than declared:
                    log.debug('sect=ENDOFCHAIN before expected size')
                    self.ole._raise_defect(DEFECT_INCORRECT, 'incomplete OLE stream')
            # sector index should be within FAT:
            if sect<0 or sect>=len(fat):
                log.debug('sect=%d (%X) / len(fat)=%d' % (sect, sect, len(fat)))
                log.debug('i=%d / nb_sectors=%d' %(i, nb_sectors))
##                tmp_data = b"".join(data)
##                f = open('test_debug.bin', 'wb')
##                f.write(tmp_data)
##                f.close()
##                log.debug('data read so far: %d bytes' % len(tmp_data))
                self.ole._raise_defect(DEFECT_INCORRECT, 'incorrect OLE FAT, sector index out of range')
                # stop reading here if the exception is ignored:
                break
            # TODO: merge this code with OleFileIO.getsect() ?
            # TODO: check if this works with 4K sectors:
            try:
                fp.seek(offset + sectorsize * sect)
            except Exception:
                log.debug('sect=%d, seek=%d, filesize=%d' %
                    (sect, offset+sectorsize*sect, filesize))
                self.ole._raise_defect(DEFECT_INCORRECT, 'OLE sector index out of range')
                # stop reading here if the exception is ignored:
                break
            sector_data = fp.read(sectorsize)
            # [PL] check if there was enough data:
            # Note: if sector is the last of the file, sometimes it is not a
            # complete sector (of 512 or 4K), so we may read less than
            # sectorsize.
            if len(sector_data)!=sectorsize and sect!=(len(fat)-1):
                log.debug('sect=%d / len(fat)=%d, seek=%d / filesize=%d, len read=%d' %
                    (sect, len(fat), offset+sectorsize*sect, filesize, len(sector_data)))
                log.debug('seek+len(read)=%d' % (offset+sectorsize*sect+len(sector_data)))
                self.ole._raise_defect(DEFECT_INCORRECT, 'incomplete OLE sector')
            data.append(sector_data)
            # jump to next sector in the FAT:
            try:
                sect = fat[sect] & 0xFFFFFFFF  # JYTHON-WORKAROUND
            except IndexError:
                # [PL] if pointer is out of the FAT an exception is raised
                self.ole._raise_defect(DEFECT_INCORRECT, 'incorrect OLE FAT, sector index out of range')
                # stop reading here if the exception is ignored:
                break
        # [PL] Last sector should be a "end of chain" marker:
        # if sect != ENDOFCHAIN:
        #     raise IOError('incorrect last sector index in OLE stream')
        data = b"".join(data)
        # Data is truncated to the actual stream size:
        if len(data) >= size:
            log.debug('Read data of length %d, truncated to stream size %d' % (len(data), size))
            data = data[:size]
            # actual stream size is stored for future use:
            self.size = size
        elif unknown_size:
            # actual stream size was not known, now we know the size of read
            # data:
            log.debug('Read data of length %d, the stream size was unknown' % len(data))
            self.size = len(data)
        else:
            # read data is less than expected:
            log.debug('Read data of length %d, less than expected stream size %d' % (len(data), size))
            # TODO: provide details in exception message
            self.size = len(data)
            self.ole._raise_defect(DEFECT_INCORRECT, 'OLE stream size is less than declared')
        # when all data is read in memory, BytesIO constructor is called
        io.BytesIO.__init__(self, data)
        # Then the OleStream object can be used as a read-only file object.


# --- OleExportManifest -------------------------------------------------------

class OleExportManifest(dict):
    """
    Result of :meth:`OleFileIO.export_manifest`.

    The manifest is a plain ``dict`` so that it can be serialized directly.
    Its top-level keys are also exposed as attributes for convenience::

        manifest = ole.export_manifest(['WordDocument'])
        print(manifest['gaps'])   # dict access
        print(manifest.gaps)      # attribute access

    The manifest deliberately contains locators and structural metadata only.
    It never contains the bytes of a stream, and it never adds a stream to
    ``export_streams`` unless that stream was explicitly approved.
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


# --- OleDirectoryEntry -------------------------------------------------------

class OleDirectoryEntry:
    """
    OLE2 Directory Entry pointing to a stream or a storage
    """
    # struct to parse directory entries:
    # <: little-endian byte order, standard sizes
    #    (note: this should guarantee that Q returns a 64 bits int)
    # 64s: string containing entry name in unicode UTF-16 (max 31 chars) + null char = 64 bytes
    # H: uint16, number of bytes used in name buffer, including null = (len+1)*2
    # B: uint8, dir entry type (between 0 and 5)
    # B: uint8, color: 0=black, 1=red
    # I: uint32, index of left child node in the red-black tree, NOSTREAM if none
    # I: uint32, index of right child node in the red-black tree, NOSTREAM if none
    # I: uint32, index of child root node if it is a storage, else NOSTREAM
    # 16s: CLSID, unique identifier (only used if it is a storage)
    # I: uint32, user flags
    # Q (was 8s): uint64, creation timestamp or zero
    # Q (was 8s): uint64, modification timestamp or zero
    # I: uint32, SID of first sector if stream or ministream, SID of 1st sector
    #    of stream containing ministreams if root entry, 0 otherwise
    # I: uint32, total stream size in bytes if stream (low 32 bits), 0 otherwise
    # I: uint32, total stream size in bytes if stream (high 32 bits), 0 otherwise
    STRUCT_DIRENTRY = '<64sHBBIII16sIQQIII'
    # size of a directory entry: 128 bytes
    DIRENTRY_SIZE = 128
    assert struct.calcsize(STRUCT_DIRENTRY) == DIRENTRY_SIZE

    def __init__(self, entry, sid, ole_file):
        """
        Constructor for an OleDirectoryEntry object.
        Parses a 128-bytes entry from the OLE Directory stream.

        :param bytes entry: bytes string (must be 128 bytes long)
        :param int sid: index of this directory entry in the OLE file directory
        :param OleFileIO ole_file: OleFileIO object containing this directory entry
        """
        self.sid = sid
        # ref to ole_file is stored for future use
        self.olefile = ole_file
        # kids is a list of children entries, if this entry is a storage:
        # (list of OleDirectoryEntry objects)
        self.kids = []
        # kids_dict is a dictionary of children entries, indexed by their
        # name in lowercase: used to quickly find an entry, and to detect
        # duplicates
        self.kids_dict = {}
        # flag used to detect if the entry is referenced more than once in
        # directory:
        self.used = False
        # decode DirEntry
        (
            self.name_raw, # 64s: string containing entry name in unicode UTF-16 (max 31 chars) + null char = 64 bytes
            self.namelength, # H: uint16, number of bytes used in name buffer, including null = (len+1)*2
            self.entry_type,
            self.color,
            self.sid_left,
            self.sid_right,
            self.sid_child,
            clsid,
            self.dwUserFlags,
            self.createTime,
            self.modifyTime,
            self.isectStart,
            self.sizeLow,
            self.sizeHigh
        ) = struct.unpack(OleDirectoryEntry.STRUCT_DIRENTRY, entry)
        if self.entry_type not in [STGTY_ROOT, STGTY_STORAGE, STGTY_STREAM, STGTY_EMPTY]:
            ole_file._raise_defect(DEFECT_INCORRECT, 'unhandled OLE storage type')
        # only first directory entry can (and should) be root:
        if self.entry_type == STGTY_ROOT and sid != 0:
            ole_file._raise_defect(DEFECT_INCORRECT, 'duplicate OLE root entry')
        if sid == 0 and self.entry_type != STGTY_ROOT:
            ole_file._raise_defect(DEFECT_INCORRECT, 'incorrect OLE root entry')
        # log.debug(struct.unpack(fmt_entry, entry[:len_entry]))
        # name should be at most 31 unicode characters + null character,
        # so 64 bytes in total (31*2 + 2):
        if self.namelength > 64:
            ole_file._raise_defect(DEFECT_INCORRECT, 'incorrect DirEntry name length >64 bytes')
            # if exception not raised, namelength is set to the maximum value:
            self.namelength = 64
        # only characters without ending null char are kept:
        self.name_utf16 = self.name_raw[:(self.namelength-2)]
        # TODO: check if the name is actually followed by a null unicode character ([MS-CFB] 2.6.1)
        # TODO: check if the name does not contain forbidden characters:
        # [MS-CFB] 2.6.1: "The following characters are illegal and MUST NOT be part of the name: '/', '\', ':', '!'."
        # name is converted from UTF-16LE to the path encoding specified in the OleFileIO:
        self.name = ole_file._decode_utf16_str(self.name_utf16)

        log.debug('DirEntry SID=%d: %s' % (self.sid, repr(self.name)))
        log.debug(' - type: %d' % self.entry_type)
        log.debug(' - sect: %Xh' % self.isectStart)
        log.debug(' - SID left: %d, right: %d, child: %d' % (self.sid_left,
            self.sid_right, self.sid_child))

        # sizeHigh is only used for 4K sectors, it should be zero for 512 bytes
        # sectors, BUT apparently some implementations set it as 0xFFFFFFFF, 1
        # or some other value so it cannot be raised as a defect in general:
        if ole_file.sectorsize == 512:
            if self.sizeHigh != 0 and self.sizeHigh != 0xFFFFFFFF:
                log.debug('sectorsize=%d, sizeLow=%d, sizeHigh=%d (%X)' %
                          (ole_file.sectorsize, self.sizeLow, self.sizeHigh, self.sizeHigh))
                ole_file._raise_defect(DEFECT_UNSURE, 'incorrect OLE stream size')
            self.size = self.sizeLow
        else:
            self.size = self.sizeLow + (long(self.sizeHigh)<<32)
        log.debug(' - size: %d (sizeLow=%d, sizeHigh=%d)' % (self.size, self.sizeLow, self.sizeHigh))

        self.clsid = _clsid(clsid)
        # a storage should have a null size, BUT some implementations such as
        # Word 8 for Mac seem to allow non-null values => Potential defect:
        if self.entry_type == STGTY_STORAGE and self.size != 0:
            ole_file._raise_defect(DEFECT_POTENTIAL, 'OLE storage with size>0')
        # check if stream is not already referenced elsewhere:
        self.is_minifat = False
        if self.entry_type in (STGTY_ROOT, STGTY_STREAM) and self.size>0:
            if self.size < ole_file.minisectorcutoff \
            and self.entry_type==STGTY_STREAM: # only streams can be in MiniFAT
                # ministream object
                self.is_minifat = True
            else:
                self.is_minifat = False
            ole_file._check_duplicate_stream(self.isectStart, self.is_minifat)
        self.sect_chain = None

    def build_sect_chain(self, ole_file):
        """
        Build the sector chain for a stream (from the FAT or the MiniFAT)

        :param OleFileIO ole_file: OleFileIO object containing this directory entry
        :return: nothing
        """
        # TODO: seems to be used only from _write_mini_stream, is it useful?
        # TODO: use self.olefile instead of ole_file
        if self.sect_chain:
            return
        if self.entry_type not in (STGTY_ROOT, STGTY_STREAM) or self.size == 0:
            return

        self.sect_chain = list()

        if self.is_minifat and not ole_file.minifat:
            ole_file.loadminifat()

        next_sect = self.isectStart
        while next_sect != ENDOFCHAIN:
            self.sect_chain.append(next_sect)
            if self.is_minifat:
                next_sect = ole_file.minifat[next_sect]
            else:
                next_sect = ole_file.fat[next_sect]

    def build_storage_tree(self):
        """
        Read and build the red-black tree attached to this OleDirectoryEntry
        object, if it is a storage.
        Note that this method builds a tree of all subentries, so it should
        only be called for the root object once.
        """
        log.debug('build_storage_tree: SID=%d - %s - sid_child=%d'
            % (self.sid, repr(self.name), self.sid_child))
        if self.sid_child != NOSTREAM:
            # if child SID is not NOSTREAM, then this entry is a storage.
            # Let's walk through the tree of children to fill the kids list:
            self.append_kids(self.sid_child)

            # Note from OpenOffice documentation: the safest way is to
            # recreate the tree because some implementations may store broken
            # red-black trees...

            # in the OLE file, entries are sorted on (length, name).
            # for convenience, we sort them on name instead:
            # (see rich comparison methods in this class)
            self.kids.sort()

    def append_kids(self, child_sid):
        """
        Walk through red-black tree of children of this directory entry to add
        all of them to the kids list. (recursive method)

        :param child_sid: index of child directory entry to use, or None when called
            first time for the root. (only used during recursion)
        """
        log.debug('append_kids: child_sid=%d' % child_sid)
        # [PL] this method was added to use simple recursion instead of a complex
        # algorithm.
        # if this is not a storage or a leaf of the tree, nothing to do:
        if child_sid == NOSTREAM:
            return
        # check if child SID is in the proper range:
        if child_sid<0 or child_sid>=len(self.olefile.direntries):
            self.olefile._raise_defect(DEFECT_INCORRECT, 'OLE DirEntry index out of range')
        else:
            # get child direntry:
            child = self.olefile._load_direntry(child_sid) #direntries[child_sid]
            log.debug('append_kids: child_sid=%d - %s - sid_left=%d, sid_right=%d, sid_child=%d'
                % (child.sid, repr(child.name), child.sid_left, child.sid_right, child.sid_child))
            # Check if kid was not already referenced in a storage:
            if child.used:
                self.olefile._raise_defect(DEFECT_INCORRECT,
                    'OLE Entry referenced more than once')
                return
            child.used = True
            # the directory entries are organized as a red-black tree.
            # (cf. Wikipedia for details)
            # First walk through left side of the tree:
            self.append_kids(child.sid_left)
            # Check if its name is not already used (case-insensitive):
            name_lower = child.name.lower()
            if name_lower in self.kids_dict:
                self.olefile._raise_defect(DEFECT_INCORRECT,
                    "Duplicate filename in OLE storage")
            # Then the child_sid OleDirectoryEntry object is appended to the
            # kids list and dictionary:
            self.kids.append(child)
            self.kids_dict[name_lower] = child
            # Finally walk through right side of the tree:
            self.append_kids(child.sid_right)
            # Afterwards build kid's own tree if it's also a storage:
            child.build_storage_tree()

    def __eq__(self, other):
        "Compare entries by name"
        return self.name == other.name

    def __lt__(self, other):
        "Compare entries by name"
        return self.name < other.name

    def __ne__(self, other):
        return not self.__eq__(other)

    def __le__(self, other):
        return self.__eq__(other) or self.__lt__(other)

    # Reflected __lt__() and __le__() will be used for __gt__() and __ge__()

    # TODO: replace by the same function as MS implementation ?
    # (order by name length first, then case-insensitive order)

    def dump(self, tab = 0):
        "Dump this entry, and all its subentries (for debug purposes only)"
        TYPES = ["(invalid)", "(storage)", "(stream)", "(lockbytes)",
                 "(property)", "(root)"]
        try:
            type_name = TYPES[self.entry_type]
        except IndexError:
            type_name = '(UNKNOWN)'
        print(" "*tab + repr(self.name), type_name, end=' ')
        if self.entry_type in (STGTY_STREAM, STGTY_ROOT):
            print(self.size, "bytes", end=' ')
        print()
        if self.entry_type in (STGTY_STORAGE, STGTY_ROOT) and self.clsid:
            print(" "*tab + "{%s}" % self.clsid)

        for kid in self.kids:
            kid.dump(tab + 2)

    def getmtime(self):
        """
        Return modification time of a directory entry.

        :returns: None if modification time is null, a python datetime object
            otherwise (UTC timezone)

        new in version 0.26
        """
        if self.modifyTime == 0:
            return None
        return filetime2datetime(self.modifyTime)


    def getctime(self):
        """
        Return creation time of a directory entry.

        :returns: None if modification time is null, a python datetime object
            otherwise (UTC timezone)

        new in version 0.26
        """
        if self.createTime == 0:
            return None
        return filetime2datetime(self.createTime)


#--- OleFileIO ----------------------------------------------------------------

class OleFileIO:
    """
    OLE container object

    This class encapsulates the interface to an OLE 2 structured
    storage file.  Use the listdir and openstream methods to
    access the contents of this file.

    Object names are given as a list of strings, one for each subentry
    level.  The root entry should be omitted.  For example, the following
    code extracts all image streams from a Microsoft Image Composer file::

        with OleFileIO("fan.mic") as ole:

            for entry in ole.listdir():
                if entry[1:2] == "Image":
                    fin = ole.openstream(entry)
                    fout = open(entry[0:1], "wb")
                    while True:
                        s = fin.read(8192)
                        if not s:
                            break
                        fout.write(s)

    You can use the viewer application provided with the Python Imaging
    Library to view the resulting files (which happens to be standard
    TIFF files).
    """

    def __init__(self, filename=None, raise_defects=DEFECT_FATAL,
                 write_mode=False, debug=False, path_encoding=DEFAULT_PATH_ENCODING):
        """
        Constructor for the OleFileIO class.

        :param filename: file to open.

            - if filename is a string smaller than 1536 bytes, it is the path
              of the file to open. (bytes or unicode string)
            - if filename is a string longer than 1535 bytes, it is parsed
              as the content of an OLE file in memory. (bytes type only)
            - if filename is a file-like object (with read, seek and tell methods),
              it is parsed as-is. The caller is responsible for closing it when done.

        :param raise_defects: minimal level for defects to be raised as exceptions.
            (use DEFECT_FATAL for a typical application, DEFECT_INCORRECT for a
            security-oriented application, see source code for details)

        :param write_mode: bool, if True the file is opened in read/write mode instead
            of read-only by default.

        :param debug: bool, set debug mode (deprecated, not used anymore)

        :param path_encoding: None or str, name of the codec to use for path
            names (streams and storages), or None for Unicode.
            Unicode by default on Python 3+, UTF-8 on Python 2.x.
            (new in olefile 0.42, was hardcoded to Latin-1 until olefile v0.41)
        """
        # minimal level for defects to be raised as exceptions:
        self._raise_defects_level = raise_defects
        #: list of defects/issues not raised as exceptions:
        #: tuples of (exception type, message)
        self.parsing_issues = []
        self.write_mode = write_mode
        self.path_encoding = path_encoding
        # initialize all attributes to default values:
        self._filesize = None
        self.ministream = None
        self._used_streams_fat = []
        self._used_streams_minifat = []
        self.byte_order = None
        self.directory_fp = None
        self.direntries = None
        self.dll_version = None
        self.fat = None
        self.first_difat_sector = None
        self.first_dir_sector = None
        self.first_mini_fat_sector = None
        self.fp = None
        self.header_clsid = None
        self.header_signature = None
        self.metadata = None
        self.mini_sector_shift = None
        self.mini_sector_size = None
        self.mini_stream_cutoff_size = None
        self.minifat = None
        self.minifatsect = None
        # TODO: duplicates?
        self.minisectorcutoff = None
        self.minisectorsize = None
        self.ministream = None
        self.minor_version = None
        self.nb_sect = None
        self.num_difat_sectors = None
        self.num_dir_sectors = None
        self.num_fat_sectors = None
        self.num_mini_fat_sectors = None
        self.reserved1 = None
        self.reserved2 = None
        self.root = None
        self.sector_shift = None
        self.sector_size = None
        self.transaction_signature_number = None
        self.warn_if_not_closed = False
        self._we_opened_fp = False
        self._open_stack = None
        if filename:
            # try opening, ensure fp is closed if that fails
            try:
                self.open(filename, write_mode=write_mode)
            except Exception:
                # caller has no chance of calling close() now
                self._close(warn=False)
                raise

    def __del__(self):
        """Destructor, ensures all file handles are closed that we opened."""
        self._close(warn=True)
        # super(OleFileIO, self).__del__()  # there's no super-class destructor


    def __enter__(self):
        return self


    def __exit__(self, *args):
        self._close(warn=False)


    def _raise_defect(self, defect_level, message, exception_type=OleFileError):
        """
        This method should be called for any defect found during file parsing.
        It may raise an OleFileError exception according to the minimal level chosen
        for the OleFileIO object.

        :param defect_level: defect level, possible values are:

            - DEFECT_UNSURE    : a case which looks weird, but not sure it's a defect
            - DEFECT_POTENTIAL : a potential defect
            - DEFECT_INCORRECT : an error according to specifications, but parsing can go on
            - DEFECT_FATAL     : an error which cannot be ignored, parsing is impossible

        :param message: string describing the defect, used with raised exception.
        :param exception_type: exception class to be raised, OleFileError by default
        """
        # added by [PL]
        if defect_level >= self._raise_defects_level:
            log.error(message)
            raise exception_type(message)
        else:
            # just record the issue, no exception raised:
            self.parsing_issues.append((exception_type, message))
            log.warning(message)


    def _decode_utf16_str(self, utf16_str, errors='replace'):
        """
        Decode a string encoded in UTF-16 LE format, as found in the OLE
        directory or in property streams. Return a string encoded
        according to the path_encoding specified for the OleFileIO object.

        :param bytes utf16_str: bytes string encoded in UTF-16 LE format
        :param str errors: str, see python documentation for str.decode()
        :return: str, encoded according to path_encoding
        :rtype: str
        """
        unicode_str = utf16_str.decode('UTF-16LE', errors)
        if self.path_encoding:
            # an encoding has been specified for path names:
            return unicode_str.encode(self.path_encoding, errors)
        else:
            # path_encoding=None, return the Unicode string as-is:
            return unicode_str


    def open(self, filename, write_mode=False):
        """
        Open an OLE2 file in read-only or read/write mode.
        Read and parse the header, FAT and directory.

        :param filename: string-like or file-like object, OLE file to parse

            - if filename is a string smaller than 1536 bytes, it is the path
              of the file to open. (bytes or unicode string)
            - if filename is a string longer than 1535 bytes, it is parsed
              as the content of an OLE file in memory. (bytes type only)
            - if filename is a file-like object (with read, seek and tell methods),
              it is parsed as-is. The caller is responsible for closing it when done

        :param write_mode: bool, if True the file is opened in read/write mode instead
            of read-only by default. (ignored if filename is not a path)
        """
        self.write_mode = write_mode
        # [PL] check if filename is a string-like or file-like object:
        # (it is better to check for a read() method)
        if hasattr(filename, 'read'):
            # TODO: also check seek and tell methods?
            # file-like object: use it directly
            self.fp = filename
        elif isinstance(filename, bytes) and len(filename) >= MINIMAL_OLEFILE_SIZE:
            # filename is a bytes string containing the OLE file to be parsed:
            # convert it to BytesIO
            self.fp = io.BytesIO(filename)
        else:
            # string-like object: filename of file on disk
            if self.write_mode:
                # open file in mode 'read with update, binary'
                # According to https://docs.python.org/library/functions.html#open
                # 'w' would truncate the file, 'a' may only append on some Unixes
                mode = 'r+b'
            else:
                # read-only mode by default
                mode = 'rb'
            self.fp = open(filename, mode)
            self._we_opened_fp = True
            self._open_stack = traceback.extract_stack()   # remember for warning
        # obtain the filesize by using seek and tell, which should work on most
        # file-like objects:
        # TODO: do it above, using getsize with filename when possible?
        # TODO: fix code to fail with clear exception when filesize cannot be obtained
        filesize = 0
        self.fp.seek(0, os.SEEK_END)
        try:
            filesize = self.fp.tell()
        finally:
            self.fp.seek(0)
        self._filesize = filesize
        log.debug('File size: %d bytes (%Xh)' % (self._filesize, self._filesize))

        # lists of streams in FAT and MiniFAT, to detect duplicate references
        # (list of indexes of first sectors of each stream)
        self._used_streams_fat = []
        self._used_streams_minifat = []

        header = self.fp.read(512)

        if len(header) != 512 or header[:8] != MAGIC:
            log.debug('Magic = {!r} instead of {!r}'.format(header[:8], MAGIC))
            self._raise_defect(DEFECT_FATAL, "not an OLE2 structured storage file", NotOleFileError)

        # [PL] header structure according to AAF specifications:
        ##Header
        ##struct StructuredStorageHeader { // [offset from start (bytes), length (bytes)]
        ##BYTE _abSig[8]; // [00H,08] {0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1,
        ##                // 0x1a, 0xe1} for current version
        ##CLSID _clsid;   // [08H,16] reserved must be zero (WriteClassStg/
        ##                // GetClassFile uses root directory class id)
        ##USHORT _uMinorVersion; // [18H,02] minor version of the format: 33 is
        ##                       // written by reference implementation
        ##USHORT _uDllVersion;   // [1AH,02] major version of the dll/format: 3 for
        ##                       // 512-byte sectors, 4 for 4 KB sectors
        ##USHORT _uByteOrder;    // [1CH,02] 0xFFFE: indicates Intel byte-ordering
        ##USHORT _uSectorShift;  // [1EH,02] size of sectors in power-of-two;
        ##                       // typically 9 indicating 512-byte sectors
        ##USHORT _uMiniSectorShift; // [20H,02] size of mini-sectors in power-of-two;
        ##                          // typically 6 indicating 64-byte mini-sectors
        ##USHORT _usReserved; // [22H,02] reserved, must be zero
        ##ULONG _ulReserved1; // [24H,04] reserved, must be zero
        ##FSINDEX _csectDir; // [28H,04] must be zero for 512-byte sectors,
        ##                   // number of SECTs in directory chain for 4 KB
        ##                   // sectors
        ##FSINDEX _csectFat; // [2CH,04] number of SECTs in the FAT chain
        ##SECT _sectDirStart; // [30H,04] first SECT in the directory chain
        ##DFSIGNATURE _signature; // [34H,04] signature used for transactions; must
        ##                        // be zero. The reference implementation
        ##                        // does not support transactions
        ##ULONG _ulMiniSectorCutoff; // [38H,04] maximum size for a mini stream;
        ##                           // typically 4096 bytes
        ##SECT _sectMiniFatStart; // [3CH,04] first SECT in the MiniFAT chain
        ##FSINDEX _csectMiniFat; // [40H,04] number of SECTs in the MiniFAT chain
        ##SECT _sectDifStart; // [44H,04] first SECT in the DIFAT chain
        ##FSINDEX _csectDif; // [48H,04] number of SECTs in the DIFAT chain
        ##SECT _sectFat[109]; // [4CH,436] the SECTs of first 109 FAT sectors
        ##};

        # [PL] header decoding:
        # '<' indicates little-endian byte ordering for Intel (cf. struct module help)
        fmt_header = '<8s16sHHHHHHLLLLLLLLLL'
        header_size = struct.calcsize(fmt_header)
        log.debug( "fmt_header size = %d, +FAT = %d" % (header_size, header_size + 109*4) )
        header1 = header[:header_size]
        (
            self.header_signature,
            self.header_clsid,
            self.minor_version,
            self.dll_version,
            self.byte_order,
            self.sector_shift,
            self.mini_sector_shift,
            self.reserved1,
            self.reserved2,
            self.num_dir_sectors,
            self.num_fat_sectors,
            self.first_dir_sector,
            self.transaction_signature_number,
            self.mini_stream_cutoff_size,
            self.first_mini_fat_sector,
            self.num_mini_fat_sectors,
            self.first_difat_sector,
            self.num_difat_sectors
        ) = struct.unpack(fmt_header, header1)
        log.debug( struct.unpack(fmt_header,    header1))

        if self.header_signature != MAGIC:
            # OLE signature should always be present
            self._raise_defect(DEFECT_FATAL, "incorrect OLE signature")
        if self.header_clsid != bytearray(16):
            # according to AAF specs, CLSID should always be zero
            self._raise_defect(DEFECT_INCORRECT, "incorrect CLSID in OLE header")
        log.debug( "Minor Version = %d" % self.minor_version )
        # TODO: according to MS-CFB, minor version should be 0x003E
        log.debug( "DLL Version   = %d (expected: 3 or 4)" % self.dll_version )
        if self.dll_version not in [3, 4]:
            # version 3: usual format, 512 bytes per sector
            # version 4: large format, 4K per sector
            self._raise_defect(DEFECT_INCORRECT, "incorrect DllVersion in OLE header")
        log.debug( "Byte Order    = %X (expected: FFFE)" % self.byte_order )
        if self.byte_order != 0xFFFE:
            # For now only common little-endian documents are handled correctly
            self._raise_defect(DEFECT_INCORRECT, "incorrect ByteOrder in OLE header")
            # TODO: add big-endian support for documents created on Mac ?
            # But according to [MS-CFB] ? v20140502, ByteOrder MUST be 0xFFFE.
        self.sector_size = 2**self.sector_shift
        log.debug( "Sector Size   = %d bytes (expected: 512 or 4096)" % self.sector_size )
        if self.sector_size not in [512, 4096]:
            self._raise_defect(DEFECT_INCORRECT, "incorrect sector_size in OLE header")
        if (self.dll_version==3 and self.sector_size!=512) \
        or (self.dll_version==4 and self.sector_size!=4096):
            self._raise_defect(DEFECT_INCORRECT, "sector_size does not match DllVersion in OLE header")
        self.mini_sector_size = 2**self.mini_sector_shift
        log.debug( "MiniFAT Sector Size   = %d bytes (expected: 64)" % self.mini_sector_size )
        if self.mini_sector_size not in [64]:
            self._raise_defect(DEFECT_INCORRECT, "incorrect mini_sector_size in OLE header")
        if self.reserved1 != 0 or self.reserved2 != 0:
            self._raise_defect(DEFECT_INCORRECT, "incorrect OLE header (non-null reserved bytes)")
        log.debug( "Number of Directory sectors = %d" % self.num_dir_sectors )
        # Number of directory sectors (only allowed if DllVersion != 3)
        if self.sector_size==512 and self.num_dir_sectors!=0:
            self._raise_defect(DEFECT_INCORRECT, "incorrect number of directory sectors in OLE header")
        log.debug( "Number of FAT sectors = %d" % self.num_fat_sectors )
        # num_fat_sectors = number of FAT sectors in the file
        log.debug( "First Directory sector  = %Xh" % self.first_dir_sector )
        # first_dir_sector = 1st sector containing the directory
        log.debug( "Transaction Signature Number    = %d" % self.transaction_signature_number )
        # Signature should be zero, BUT some implementations do not follow this
        # rule => only a potential defect:
        # (according to MS-CFB, may be != 0 for applications supporting file
        # transactions)
        if self.transaction_signature_number != 0:
            self._raise_defect(DEFECT_POTENTIAL, "incorrect OLE header (transaction_signature_number>0)")
        log.debug( "Mini Stream cutoff size = %Xh (expected: 1000h)" % self.mini_stream_cutoff_size )
        # MS-CFB: This integer field MUST be set to 0x00001000. This field
        # specifies the maximum size of a user-defined data stream allocated
        # from the mini FAT and mini stream, and that cutoff is 4096 bytes.
        # Any user-defined data stream larger than or equal to this cutoff size
        # must be allocated as normal sectors from the FAT.
        if self.mini_stream_cutoff_size != 0x1000:
            self._raise_defect(DEFECT_INCORRECT, "incorrect mini_stream_cutoff_size in OLE header")
            # if no exception is raised, the cutoff size is fixed to 0x1000
            log.warning('Fixing the mini_stream_cutoff_size to 4096 (mandatory value) instead of %d' %
                        self.mini_stream_cutoff_size)
            self.mini_stream_cutoff_size = 0x1000
        # TODO: check if these values are OK
        log.debug( "First MiniFAT sector      = %Xh" % self.first_mini_fat_sector )
        log.debug( "Number of MiniFAT sectors = %d" % self.num_mini_fat_sectors )
        log.debug( "First DIFAT sector        = %Xh" % self.first_difat_sector )
        log.debug( "Number of DIFAT sectors   = %d" % self.num_difat_sectors )

        # calculate the number of sectors in the file
        # (-1 because header doesn't count)
        self.nb_sect = ( (filesize + self.sector_size-1) // self.sector_size) - 1
        log.debug( "Maximum number of sectors in the file: %d (%Xh)" % (self.nb_sect, self.nb_sect))
        # TODO: change this test, because an OLE file MAY contain other data
        # after the last sector.

        # file clsid
        self.header_clsid = _clsid(header[8:24])

        # TODO: remove redundant attributes, and fix the code which uses them?
        self.sectorsize = self.sector_size #1 << i16(header, 30)
        self.minisectorsize = self.mini_sector_size  #1 << i16(header, 32)
        self.minisectorcutoff = self.mini_stream_cutoff_size # i32(header, 56)

        # check known streams for duplicate references (these are always in FAT,
        # never in MiniFAT):
        self._check_duplicate_stream(self.first_dir_sector)
        # check MiniFAT only if it is not empty:
        if self.num_mini_fat_sectors:
            self._check_duplicate_stream(self.first_mini_fat_sector)
        # check DIFAT only if it is not empty:
        if self.num_difat_sectors:
            self._check_duplicate_stream(self.first_difat_sector)

        # Load file allocation tables
        self.loadfat(header)
        # Load directory.  This sets both the direntries list (ordered by sid)
        # and the root (ordered by hierarchy) members.
        self.loaddirectory(self.first_dir_sector)
        self.minifatsect = self.first_mini_fat_sector

    def close(self):
        """
        close the OLE file, release the file object if we created it ourselves.

        Leaves the file handle open if it was provided by the caller.
        """
        self._close(warn=False)

    def _close(self, warn=False):
        """Implementation of close() with internal arg `warn`."""
        if self._we_opened_fp:
            if warn and self.warn_if_not_closed:
                # we only raise a warning if the file was not explicitly closed,
                # and if the option warn_if_not_closed is enabled
                warnings.warn(OleFileIONotClosed(self._open_stack))
            self.fp.close()
            self._we_opened_fp = False

    def _check_duplicate_stream(self, first_sect, minifat=False):
        """
        Checks if a stream has not been already referenced elsewhere.
        This method should only be called once for each known stream, and only
        if stream size is not null.

        :param first_sect: int, index of first sector of the stream in FAT
        :param minifat: bool, if True, stream is located in the MiniFAT, else in the FAT
        """
        if minifat:
            log.debug('_check_duplicate_stream: sect=%Xh in MiniFAT' % first_sect)
            used_streams = self._used_streams_minifat
        else:
            log.debug('_check_duplicate_stream: sect=%Xh in FAT' % first_sect)
            # some values can be safely ignored (not a real stream):
            if first_sect in (DIFSECT,FATSECT,ENDOFCHAIN,FREESECT):
                return
            used_streams = self._used_streams_fat
        # TODO: would it be more efficient using a dict or hash values, instead
        #      of a list of long ?
        if first_sect in used_streams:
            self._raise_defect(DEFECT_INCORRECT, 'Stream referenced twice')
        else:
            used_streams.append(first_sect)

    def dumpfat(self, fat, firstindex=0):
        """
        Display a part of FAT in human-readable form for debugging purposes
        """
        # dictionary to convert special FAT values in human-readable strings
        VPL = 8 # values per line (8+1 * 8+1 = 81)
        fatnames = {
            FREESECT:   "..free..",
            ENDOFCHAIN: "[ END. ]",
            FATSECT:    "FATSECT ",
            DIFSECT:    "DIFSECT "
            }
        nbsect = len(fat)
        nlines = (nbsect+VPL-1)//VPL
        print("index", end=" ")
        for i in range(VPL):
            print("%8X" % i, end=" ")
        print()
        for l in range(nlines):
            index = l*VPL
            print("%6X:" % (firstindex+index), end=" ")
            for i in range(index, index+VPL):
                if i>=nbsect:
                    break
                sect = fat[i]
                aux = sect & 0xFFFFFFFF  # JYTHON-WORKAROUND
                if aux in fatnames:
                    name = fatnames[aux]
                else:
                    if sect == i+1:
                        name = "    --->"
                    else:
                        name = "%8X" % sect
                print(name, end=" ")
            print()

    def dumpsect(self, sector, firstindex=0):
        """
        Display a sector in a human-readable form, for debugging purposes
        """
        VPL=8 # number of values per line (8+1 * 8+1 = 81)
        tab = array.array(UINT32, sector)
        if sys.byteorder == 'big':
            tab.byteswap()
        nbsect = len(tab)
        nlines = (nbsect+VPL-1)//VPL
        print("index", end=" ")
        for i in range(VPL):
            print("%8X" % i, end=" ")
        print()
        for l in range(nlines):
            index = l*VPL
            print("%6X:" % (firstindex+index), end=" ")
            for i in range(index, index+VPL):
                if i>=nbsect:
                    break
                sect = tab[i]
                name = "%8X" % sect
                print(name, end=" ")
            print()

    def sect2array(self, sect):
        """
        convert a sector to an array of 32 bits unsigned integers,
        swapping bytes on big endian CPUs such as PowerPC (old Macs)
        """
        # TODO: make this a static function
        a = array.array(UINT32, sect)
        # if CPU is big endian, swap bytes:
        if sys.byteorder == 'big':
            a.byteswap()
        return a

    def loadfat_sect(self, sect):
        """
        Adds the indexes of the given sector to the FAT

        :param sect: string containing the first FAT sector, or array of long integers
        :returns: index of last FAT sector.
        """
        # a FAT sector is an array of ulong integers.
        if isinstance(sect, array.array):
            # if sect is already an array it is directly used
            fat1 = sect
        else:
            # if it's a raw sector, it is parsed in an array
            fat1 = self.sect2array(sect)
            # Display the sector contents only if the logging level is debug:
            if log.isEnabledFor(logging.DEBUG):
                self.dumpsect(sect)
        # The FAT is a sector chain starting at the first index of itself.
        # initialize isect, just in case:
        isect = None
        for isect in fat1:
            isect = isect & 0xFFFFFFFF  # JYTHON-WORKAROUND
            log.debug("isect = %X" % isect)
            if isect == ENDOFCHAIN or isect == FREESECT:
                # the end of the sector chain has been reached
                log.debug("found end of sector chain")
                break
            # read the FAT sector
            s = self.getsect(isect)
            # parse it as an array of 32 bits integers, and add it to the
            # global FAT array
            nextfat = self.sect2array(s)
            self.fat = self.fat + nextfat
        return isect

    def loadfat(self, header):
        """
        Load the FAT table.
        """
        # The 1st sector of the file contains sector numbers for the first 109
        # FAT sectors, right after the header which is 76 bytes long.
        # (always 109, whatever the sector size: 512 bytes = 76+4*109)
        # Additional sectors are described by DIF blocks

        log.debug('Loading the FAT table, starting with the 1st sector after the header')
        sect = header[76:512]
        log.debug( "len(sect)=%d, so %d integers" % (len(sect), len(sect)//4) )
        # fat    = []
        # FAT is an array of 32 bits unsigned ints, it's more effective
        # to use an array than a list in Python.
        # It's initialized as empty first:
        self.fat = array.array(UINT32)
        self.loadfat_sect(sect)
        # self.dumpfat(self.fat)
        # for i in range(0, len(sect), 4):
        #     ix = i32(sect, i)
        #     # [PL] if ix == -2 or ix == -1: # ix == 0xFFFFFFFE or ix == 0xFFFFFFFF:
        #     if ix == 0xFFFFFFFE or ix == 0xFFFFFFFF:
        #         break
        #     s = self.getsect(ix)
        #     # fat    = fat + [i32(s, i) for i in range(0, len(s), 4)]
        #     fat = fat + array.array(UINT32, s)
        if self.num_difat_sectors != 0:
            log.debug('DIFAT is used, because file size > 6.8MB.')
            # [PL] There's a DIFAT because file is larger than 6.8MB
            # some checks just in case:
            if self.num_fat_sectors <= 109:
                # there must be at least 109 blocks in header and the rest in
                # DIFAT, so number of sectors must be >109.
                self._raise_defect(DEFECT_INCORRECT, 'incorrect DIFAT, not enough sectors')
            if self.first_difat_sector >= self.nb_sect:
                # initial DIFAT block index must be valid
                self._raise_defect(DEFECT_FATAL, 'incorrect DIFAT, first index out of range')
            log.debug( "DIFAT analysis..." )
            # We compute the necessary number of DIFAT sectors :
            # Number of pointers per DIFAT sector = (sectorsize/4)-1
            # (-1 because the last pointer is the next DIFAT sector number)
            nb_difat_sectors = (self.sectorsize//4)-1
            # (if 512 bytes: each DIFAT sector = 127 pointers + 1 towards next DIFAT sector)
            nb_difat = (self.num_fat_sectors-109 + nb_difat_sectors-1)//nb_difat_sectors
            log.debug( "nb_difat = %d" % nb_difat )
            if self.num_difat_sectors != nb_difat:
                raise IOError('incorrect DIFAT')
            isect_difat = self.first_difat_sector
            for i in iterrange(nb_difat):
                log.debug( "DIFAT block %d, sector %X" % (i, isect_difat) )
                # TODO: check if corresponding FAT SID = DIFSECT
                sector_difat = self.getsect(isect_difat)
                difat = self.sect2array(sector_difat)
                # Display the sector contents only if the logging level is debug:
                if log.isEnabledFor(logging.DEBUG):
                    self.dumpsect(sector_difat)
                self.loadfat_sect(difat[:nb_difat_sectors])
                # last DIFAT pointer is next DIFAT sector:
                isect_difat = difat[nb_difat_sectors]
                log.debug( "next DIFAT sector: %X" % isect_difat )
            # checks:
            if isect_difat not in [ENDOFCHAIN, FREESECT]:
                # last DIFAT pointer value must be ENDOFCHAIN or FREESECT
                raise IOError('incorrect end of DIFAT')
            # if len(self.fat) != self.num_fat_sectors:
            #     # FAT should contain num_fat_sectors blocks
            #     print("FAT length: %d instead of %d" % (len(self.fat), self.num_fat_sectors))
            #     raise IOError('incorrect DIFAT')
        else:
            log.debug('No DIFAT, because file size < 6.8MB.')
        # since FAT is read from fixed-size sectors, it may contain more values
        # than the actual number of sectors in the file.
        # Keep only the relevant sector indexes:
        if len(self.fat) > self.nb_sect:
            log.debug('len(fat)=%d, shrunk to nb_sect=%d' % (len(self.fat), self.nb_sect))
            self.fat = self.fat[:self.nb_sect]
        log.debug('FAT references %d sectors / Maximum %d sectors in file' % (len(self.fat), self.nb_sect))
        # Display the FAT contents only if the logging level is debug:
        if log.isEnabledFor(logging.DEBUG):
            log.debug('\nFAT:')
            self.dumpfat(self.fat)

    def loadminifat(self):
        """
        Load the MiniFAT table.
        """
        # MiniFAT is stored in a standard  sub-stream, pointed to by a header
        # field.
        # NOTE: there are two sizes to take into account for this stream:
        # 1) Stream size is calculated according to the number of sectors
        #    declared in the OLE header. This allocated stream may be more than
        #    needed to store the actual sector indexes.
        # (self.num_mini_fat_sectors is the number of sectors of size self.sector_size)
        stream_size = self.num_mini_fat_sectors * self.sector_size
        # 2) Actually used size is calculated by dividing the MiniStream size
        #    (given by root entry size) by the size of mini sectors, *4 for
        #    32 bits indexes:
        nb_minisectors = (self.root.size + self.mini_sector_size-1) // self.mini_sector_size
        used_size = nb_minisectors * 4
        log.debug('loadminifat(): minifatsect=%d, nb FAT sectors=%d, used_size=%d, stream_size=%d, nb MiniSectors=%d' %
            (self.minifatsect, self.num_mini_fat_sectors, used_size, stream_size, nb_minisectors))
        if used_size > stream_size:
            # This is not really a problem, but may indicate a wrong implementation:
            self._raise_defect(DEFECT_INCORRECT, 'OLE MiniStream is larger than MiniFAT')
        # In any case, first read stream_size:
        s = self._open(self.minifatsect, stream_size, force_FAT=True).read()
        # [PL] Old code replaced by an array:
        #self.minifat = [i32(s, i) for i in range(0, len(s), 4)]
        self.minifat = self.sect2array(s)
        # Then shrink the array to used size, to avoid indexes out of MiniStream:
        log.debug('MiniFAT shrunk from %d to %d sectors' % (len(self.minifat), nb_minisectors))
        self.minifat = self.minifat[:nb_minisectors]
        log.debug('loadminifat(): len=%d' % len(self.minifat))
        # Display the FAT contents only if the logging level is debug:
        if log.isEnabledFor(logging.DEBUG):
            log.debug('\nMiniFAT:')
            self.dumpfat(self.minifat)

    def getsect(self, sect):
        """
        Read given sector from file on disk.

        :param sect: int, sector index
        :returns: a string containing the sector data.
        """
        # From [MS-CFB]: A sector number can be converted into a byte offset
        # into the file by using the following formula:
        # (sector number + 1) x Sector Size.
        # This implies that sector #0 of the file begins at byte offset Sector
        # Size, not at 0.

        # [PL] the original code in PIL was wrong when sectors are 4KB instead of
        # 512 bytes:
        #self.fp.seek(512 + self.sectorsize * sect)
        # [PL]: added safety checks:
        #print("getsect(%X)" % sect)
        try:
            self.fp.seek(self.sectorsize * (sect+1))
        except Exception:
            log.debug('getsect(): sect=%X, seek=%d, filesize=%d' %
                (sect, self.sectorsize*(sect+1), self._filesize))
            self._raise_defect(DEFECT_FATAL, 'OLE sector index out of range')
        sector = self.fp.read(self.sectorsize)
        if len(sector) != self.sectorsize:
            log.debug('getsect(): sect=%X, read=%d, sectorsize=%d' %
                (sect, len(sector), self.sectorsize))
            self._raise_defect(DEFECT_FATAL, 'incomplete OLE sector')
        return sector

    def write_sect(self, sect, data, padding=b'\x00'):
        """
        Write given sector to file on disk.

        :param sect: int, sector index
        :param data: bytes, sector data
        :param padding: single byte, padding character if data < sector size
        """
        if not isinstance(data, bytes):
            raise TypeError("write_sect: data must be a bytes string")
        if not isinstance(padding, bytes) or len(padding)!=1:
            raise TypeError("write_sect: padding must be a bytes string of 1 char")
        # TODO: we could allow padding=None for no padding at all
        try:
            self.fp.seek(self.sectorsize * (sect+1))
        except Exception:
            log.debug('write_sect(): sect=%X, seek=%d, filesize=%d' %
                (sect, self.sectorsize*(sect+1), self._filesize))
            self._raise_defect(DEFECT_FATAL, 'OLE sector index out of range')
        if len(data) < self.sectorsize:
            # add padding
            data += padding * (self.sectorsize - len(data))
        elif len(data) > self.sectorsize:
            raise ValueError("Data is larger than sector size")
        self.fp.write(data)

    def _write_mini_sect(self, fp_pos, data, padding = b'\x00'):
        """
        Write given sector to file on disk.

        :param fp_pos: int, file position
        :param data: bytes, sector data
        :param padding: single byte, padding character if data < sector size
        """
        if not isinstance(data, bytes):
            raise TypeError("write_mini_sect: data must be a bytes string")
        if not isinstance(padding, bytes) or len(padding) != 1:
            raise TypeError("write_mini_sect: padding must be a bytes string of 1 char")

        try:
            self.fp.seek(fp_pos)
        except Exception:
            log.debug('write_mini_sect(): fp_pos=%d, filesize=%d' %
                      (fp_pos, self._filesize))
            self._raise_defect(DEFECT_FATAL, 'OLE sector index out of range')
        len_data = len(data)
        if len_data < self.mini_sector_size:
            data += padding * (self.mini_sector_size - len_data)
        if self.mini_sector_size < len_data:
            raise ValueError("Data is larger than sector size")
        self.fp.write(data)

    def loaddirectory(self, sect):
        """
        Load the directory.

        :param sect: sector index of directory stream.
        """
        log.debug('Loading the Directory:')
        # The directory is  stored in a standard
        # substream, independent of its size.

        # open directory stream as a read-only file:
        # (stream size is not known in advance)
        self.directory_fp = self._open(sect, force_FAT=True)

        # [PL] to detect malformed documents and avoid DoS attacks, the maximum
        # number of directory entries can be calculated:
        max_entries = self.directory_fp.size // 128
        log.debug('loaddirectory: size=%d, max_entries=%d' %
            (self.directory_fp.size, max_entries))

        # Create list of directory entries
        # self.direntries = []
        # We start with a list of "None" object
        self.direntries = [None] * max_entries
        # for sid in iterrange(max_entries):
        #     entry = fp.read(128)
        #     if not entry:
        #         break
        #     self.direntries.append(OleDirectoryEntry(entry, sid, self))
        # load root entry:
        root_entry = self._load_direntry(0)
        # Root entry is the first entry:
        self.root = self.direntries[0]
        # TODO: read ALL directory entries (ignore bad entries?)
        # TODO: adapt build_storage_tree to avoid duplicate reads
        # for i in range(1, max_entries):
        #     self._load_direntry(i)
        # read and build all storage trees, starting from the root:
        self.root.build_storage_tree()

    def _load_direntry (self, sid):
        """
        Load a directory entry from the directory.
        This method should only be called once for each storage/stream when
        loading the directory.

        :param sid: index of storage/stream in the directory.
        :returns: a OleDirectoryEntry object

        :exception OleFileError: if the entry has always been referenced.
        """
        # check if SID is OK:
        if sid<0 or sid>=len(self.direntries):
            self._raise_defect(DEFECT_FATAL, "OLE directory index out of range")
        # check if entry was already referenced:
        if self.direntries[sid] is not None:
            self._raise_defect(DEFECT_INCORRECT,
                "double reference for OLE stream/storage")
            # if exception not raised, return the object
            return self.direntries[sid]
        self.directory_fp.seek(sid * 128)
        entry = self.directory_fp.read(128)
        self.direntries[sid] = OleDirectoryEntry(entry, sid, self)
        return self.direntries[sid]

    def dumpdirectory(self):
        """
        Dump directory (for debugging only)
        """
        self.root.dump()

    def _open(self, start, size = UNKNOWN_SIZE, force_FAT=False):
        """
        Open a stream, either in FAT or MiniFAT according to its size.
        (openstream helper)

        :param start: index of first sector
        :param size: size of stream (or nothing if size is unknown)
        :param force_FAT: if False (default), stream will be opened in FAT or MiniFAT
            according to size. If True, it will always be opened in FAT.
        """
        log.debug('OleFileIO.open(): sect=%Xh, size=%d, force_FAT=%s' %
            (start, size, str(force_FAT)))
        # stream size is compared to the mini_stream_cutoff_size threshold:
        if size < self.minisectorcutoff and not force_FAT:
            # ministream object
            if not self.ministream:
                # load MiniFAT if it wasn't already done:
                self.loadminifat()
                # The first sector index of the miniFAT stream is stored in the
                # root directory entry:
                size_ministream = self.root.size
                log.debug('Opening MiniStream: sect=%Xh, size=%d' %
                    (self.root.isectStart, size_ministream))
                self.ministream = self._open(self.root.isectStart,
                    size_ministream, force_FAT=True)
            return OleStream(fp=self.ministream, sect=start, size=size,
                             offset=0, sectorsize=self.minisectorsize,
                             fat=self.minifat, filesize=self.ministream.size,
                             olefileio=self)
        else:
            # standard stream
            return OleStream(fp=self.fp, sect=start, size=size,
                             offset=self.sectorsize,
                             sectorsize=self.sectorsize, fat=self.fat,
                             filesize=self._filesize,
                             olefileio=self)

    def _list(self, files, prefix, node, streams=True, storages=False):
        """
        listdir helper

        :param files: list of files to fill in
        :param prefix: current location in storage tree (list of names)
        :param node: current node (OleDirectoryEntry object)
        :param streams: bool, include streams if True (True by default) - new in v0.26
        :param storages: bool, include storages if True (False by default) - new in v0.26
            (note: the root storage is never included)
        """
        prefix = prefix + [node.name]
        for entry in node.kids:
            if entry.entry_type == STGTY_STORAGE:
                # this is a storage
                if storages:
                    # add it to the list
                    files.append(prefix[1:] + [entry.name])
                # check its kids
                self._list(files, prefix, entry, streams, storages)
            elif entry.entry_type == STGTY_STREAM:
                # this is a stream
                if streams:
                    # add it to the list
                    files.append(prefix[1:] + [entry.name])
            else:
                self._raise_defect(DEFECT_INCORRECT, 'The directory tree contains an entry which is not a stream nor a storage.')

    def listdir(self, streams=True, storages=False):
        """
        Return a list of streams and/or storages stored in this file

        :param streams: bool, include streams if True (True by default) - new in v0.26
        :param storages: bool, include storages if True (False by default) - new in v0.26
            (note: the root storage is never included)
        :returns: list of stream and/or storage paths
        """
        files = []
        self._list(files, [], self.root, streams, storages)
        return files

    def _find(self, filename):
        """
        Returns directory entry of given filename. (openstream helper)
        Note: this method is case-insensitive.

        :param filename: path of stream in storage tree (except root entry), either:

            - a string using Unix path syntax, for example:
              'storage_1/storage_1.2/stream'
            - or a list of storage filenames, path to the desired stream/storage.
              Example: ['storage_1', 'storage_1.2', 'stream']

        :returns: sid of requested filename
        :exception IOError: if file not found
        """

        # if filename is a string instead of a list, split it on slashes to
        # convert to a list:
        if isinstance(filename, basestring):
            filename = filename.split('/')
        # walk across storage tree, following given path:
        node = self.root
        for name in filename:
            for kid in node.kids:
                if kid.name.lower() == name.lower():
                    break
            else:
                raise IOError("file not found")
            node = kid
        return node.sid

    def openstream(self, filename):
        """
        Open a stream as a read-only file object (BytesIO).
        Note: filename is case-insensitive.

        :param filename: path of stream in storage tree (except root entry), either:

            - a string using Unix path syntax, for example:
              'storage_1/storage_1.2/stream'
            - or a list of storage filenames, path to the desired stream/storage.
              Example: ['storage_1', 'storage_1.2', 'stream']

        :returns: file object (read-only)
        :exception IOError: if filename not found, or if this is not a stream.
        """
        sid = self._find(filename)
        entry = self.direntries[sid]
        if entry.entry_type != STGTY_STREAM:
            raise IOError("this file is not a stream")
        return self._open(entry.isectStart, entry.size)

    # --- export manifest helpers ------------------------------------------

    def _manifest_name_text(self, name):
        """Return a printable path component, without changing the real name."""
        if isinstance(name, bytes):
            return name.decode('utf-8', 'replace')
        if not isinstance(name, basestring):
            return str(name)
        return name

    def _manifest_path_text(self, components):
        return '/'.join(self._manifest_name_text(part) for part in components)

    def _manifest_read_header(self):
        """Read the 512-byte header without leaving the file position moved."""
        position = self.fp.tell()
        try:
            self.fp.seek(0)
            return self.fp.read(512)
        finally:
            self.fp.seek(position)

    def _manifest_fat_layout(self):
        """
        Return the physical FAT sector ids and the DIFAT chain.

        ``self.fat`` is the logical FAT array.  To point a reviewer back into
        the original file, each logical FAT entry must also be mapped to the
        physical sector that stores it.  The order of FAT sectors is defined
        by the 109 header slots followed by the DIFAT chain.
        """
        header = self._manifest_read_header()
        fat_ids = []
        difat_chain = []
        if len(header) == 512:
            for index in range(109):
                value = struct.unpack_from('<I', header, 76 + index * 4)[0]
                if value in (FREESECT, ENDOFCHAIN, FATSECT, DIFSECT):
                    continue
                if value >= self.nb_sect:
                    continue
                fat_ids.append(value)
            if self.num_difat_sectors:
                entries_per_sector = self.sectorsize // 4
                current = self.first_difat_sector
                seen = set()
                for _ in range(self.num_difat_sectors):
                    if current in (ENDOFCHAIN, FREESECT) or current in seen:
                        break
                    if current < 0 or current >= self.nb_sect:
                        break
                    seen.add(current)
                    difat_chain.append(current)
                    try:
                        data = self.getsect(current)
                    except Exception:
                        break
                    for index in range(entries_per_sector - 1):
                        value = struct.unpack_from('<I', data, index * 4)[0]
                        if value in (FREESECT, ENDOFCHAIN, FATSECT, DIFSECT):
                            continue
                        if value >= self.nb_sect:
                            continue
                        fat_ids.append(value)
                    current = struct.unpack_from(
                        '<I', data, (entries_per_sector - 1) * 4)[0]
        if self.num_fat_sectors:
            fat_ids = fat_ids[:self.num_fat_sectors]
        # Fall back to the physical sectors already parsed when the header is
        # damaged.  This keeps locators useful for forensic review.
        if not fat_ids and self.fat is not None:
            per_sector = self.sectorsize // 4
            count = (len(self.fat) + per_sector - 1) // per_sector
            fat_ids = list(range(min(count, self.nb_sect)))
        return fat_ids, difat_chain

    def _manifest_sector_locator(self, sect, length=None):
        if sect is None or sect < 0 or sect >= self.nb_sect:
            return None
        if length is None:
            length = self.sectorsize
        offset = (sect + 1) * self.sectorsize
        return {
            'kind': 'sector',
            'sector': sect,
            'index': sect,
            'file_offset': offset,
            'offset': offset,
            'length': length,
            'label': 'sector %d at file offset 0x%X' % (sect, offset),
        }

    def _manifest_range(self, sect):
        return self._manifest_sector_locator(sect, self.sectorsize)

    def _manifest_issue(self, code, message, severity='error', locator=None,
                        **extra):
        issue = {
            'code': code,
            'type': code,
            'message': message,
            'reason': message,
            'severity': severity,
            'blocking': severity == 'error',
            'requires_authorization': extra.pop('requires_authorization', False),
        }
        if locator is not None:
            issue['locator'] = locator
            if locator.get('file_offset') is not None:
                issue['file_offset'] = locator['file_offset']
                issue['offset'] = locator['file_offset']
            if locator.get('sector') is not None:
                issue['sector'] = locator['sector']
            if locator.get('unit_index') is not None:
                issue['unit_index'] = locator['unit_index']
            if locator.get('unit_kind') is not None:
                issue['unit_kind'] = locator['unit_kind']
            issue['location'] = locator.get('label', '')
        issue.update(extra)
        return issue

    def _manifest_follow_chain(self, table, start, expected_units, unit_kind):
        """
        Follow a FAT or MiniFAT chain without reading stream payload bytes.

        Returns ``(units, issues)``.  ``units`` is the ordered list of sector
        or mini-sector indexes that back the stream.
        """
        units = []
        issues = []
        if expected_units == 0:
            if start not in (ENDOFCHAIN, FREESECT):
                issues.append(self._manifest_issue(
                    'empty_stream_has_allocation',
                    'zero-size stream has a start allocation unit',
                    severity='warning',
                    locator={'kind': unit_kind, 'unit_kind': unit_kind,
                             'unit_index': start, 'index': start,
                             'file_offset': None,
                             'label': '%s %s' % (unit_kind, start)}))
            return units, issues
        if start in (ENDOFCHAIN, FREESECT):
            issues.append(self._manifest_issue(
                'missing_allocation_chain',
                'stream has a non-zero size but no allocation chain',
                locator={'kind': unit_kind, 'unit_kind': unit_kind,
                         'unit_index': start, 'index': start,
                         'file_offset': None,
                         'label': '%s start marker %s' % (unit_kind, start)},
                path=None))
            return units, issues
        if table is None:
            issues.append(self._manifest_issue(
                'allocation_table_unavailable',
                'allocation table is not available for this %s chain' % unit_kind,
                locator={'kind': unit_kind, 'unit_kind': unit_kind,
                         'unit_index': start, 'index': start,
                         'file_offset': None,
                         'label': '%s %s (table unavailable)' % (unit_kind, start)}))
            return units, issues

        seen = set()
        current = start
        limit = max(len(table) + 1, expected_units or 0)
        while current not in (ENDOFCHAIN, FREESECT):
            current = int(current) & 0xFFFFFFFF
            if current < 0 or current > MAXREGSECT or current >= len(table):
                issues.append(self._manifest_issue(
                    'allocation_unit_out_of_range',
                    'allocation chain refers outside the %s table' % unit_kind,
                    locator={'kind': unit_kind, 'unit_kind': unit_kind,
                             'unit_index': current, 'index': current,
                             'file_offset': None,
                             'label': '%s %s (out of range)' % (unit_kind, current)}))
                break
            if current in seen:
                issues.append(self._manifest_issue(
                    'allocation_chain_loop',
                    'allocation chain loops at %s %s' % (unit_kind, current),
                    locator={'kind': unit_kind, 'unit_kind': unit_kind,
                             'unit_index': current, 'index': current,
                             'file_offset': None,
                             'label': '%s %s (loop)' % (unit_kind, current)}))
                break
            seen.add(current)
            units.append(current)
            try:
                current = int(table[current]) & 0xFFFFFFFF
            except (IndexError, TypeError, ValueError):
                issues.append(self._manifest_issue(
                    'allocation_table_entry_unreadable',
                    'cannot read allocation table entry for %s %s' %
                    (unit_kind, units[-1]),
                    locator={'kind': unit_kind, 'unit_kind': unit_kind,
                             'unit_index': units[-1], 'index': units[-1],
                             'file_offset': None,
                             'label': '%s %s (unreadable entry)' %
                                      (unit_kind, units[-1])}))
                break
            if len(units) > limit:
                issues.append(self._manifest_issue(
                    'allocation_chain_too_long',
                    'allocation chain is longer than the table'))
                break

        if current == FREESECT:
            issues.append(self._manifest_issue(
                'allocation_chain_hits_free_unit',
                'allocation chain reaches a FREE%s marker' %
                ('SECT' if unit_kind == 'sector' else ' mini-sector'),
                locator={'kind': unit_kind, 'unit_kind': unit_kind,
                         'unit_index': units[-1] if units else None,
                         'index': units[-1] if units else None,
                         'file_offset': None,
                         'label': 'FREE marker'}))
        if expected_units is not None and len(units) != expected_units:
            severity = 'error' if len(units) < expected_units else 'warning'
            issues.append(self._manifest_issue(
                'allocation_chain_length_mismatch',
                'stream needs %d %s(s) but its chain contains %d' %
                (expected_units, unit_kind, len(units)),
                severity=severity,
                locator={'kind': unit_kind, 'unit_kind': unit_kind,
                         'unit_index': units[0] if units else start,
                         'index': units[0] if units else start,
                         'file_offset': None,
                         'label': '%s chain start' %
                                  (units[0] if units else start)}))
        return units, issues

    def _manifest_chain_for_entry(self, entry):
        if entry.entry_type != STGTY_STREAM or entry.size == 0:
            return [], []
        if entry.is_minifat:
            if self.minifat is None:
                try:
                    self.loadminifat()
                except Exception as exc:
                    return [], [self._manifest_issue(
                        'minifat_unavailable',
                        'MiniFAT cannot be loaded: %s' % exc,
                        locator={'kind': 'minisector',
                                 'unit_kind': 'minisector',
                                 'unit_index': entry.isectStart,
                                 'index': entry.isectStart,
                                 'file_offset': None,
                                 'label': 'mini-sector %s' % entry.isectStart})]
            table = self.minifat
            unit_size = self.minisectorsize
            unit_kind = 'minisector'
        else:
            table = self.fat
            unit_size = self.sectorsize
            unit_kind = 'sector'
        expected = (entry.size + unit_size - 1) // unit_size
        return self._manifest_follow_chain(
            table, entry.isectStart, expected, unit_kind)

    def _manifest_fat_entry_locator(self, index, fat_ids):
        entries_per_sector = self.sectorsize // 4
        ordinal = index // entries_per_sector
        within = (index % entries_per_sector) * 4
        if ordinal >= len(fat_ids):
            return None
        sector = fat_ids[ordinal]
        if sector < 0 or sector >= self.nb_sect:
            return None
        offset = (sector + 1) * self.sectorsize + within
        return {
            'kind': 'fat-entry',
            'index': index,
            'file_offset': offset,
            'offset': offset,
            'length': 4,
            'fat_sector': sector,
            'sector': sector,
            'offset_in_sector': within,
            'label': 'FAT entry %d in sector %d at file offset 0x%X' %
                     (index, sector, offset),
        }

    def _manifest_minifat_entry_locator(self, index, minifat_chain):
        ordinal = (index * 4) // self.sectorsize
        within = (index * 4) % self.sectorsize
        if ordinal >= len(minifat_chain):
            return None
        sector = minifat_chain[ordinal]
        if sector < 0 or sector >= self.nb_sect:
            return None
        offset = (sector + 1) * self.sectorsize + within
        return {
            'kind': 'minifat-entry',
            'index': index,
            'file_offset': offset,
            'offset': offset,
            'length': 4,
            'minifat_sector': sector,
            'fat_sector': sector,
            'sector': sector,
            'offset_in_sector': within,
            'label': 'MiniFAT entry %d in sector %d at file offset 0x%X' %
                     (index, sector, offset),
        }

    def _manifest_mini_data_locator(self, index, root_chain):
        logical = index * self.minisectorsize
        ordinal = logical // self.sectorsize
        within = logical % self.sectorsize
        if ordinal >= len(root_chain):
            return {
                'kind': 'minisector',
                'unit_kind': 'minisector',
                'unit_index': index,
                'index': index,
                'logical_offset': logical,
                'file_offset': None,
                'offset': None,
                'length': self.minisectorsize,
                'sector': None,
                'offset_in_sector': within,
                'label': 'mini-sector %d (MiniStream mapping unavailable)' % index,
            }
        sector = root_chain[ordinal]
        offset = (sector + 1) * self.sectorsize + within
        return {
            'kind': 'minisector',
            'unit_kind': 'minisector',
            'unit_index': index,
            'index': index,
            'logical_offset': logical,
            'file_offset': offset,
            'offset': offset,
            'length': self.minisectorsize,
            'sector': sector,
            'ministream_sector': sector,
            'offset_in_sector': within,
            'label': 'mini-sector %d in MiniStream sector %d at file offset 0x%X' %
                     (index, sector, offset),
        }

    def _manifest_directory_entry_locator(self, sid, directory_chain):
        entry_offset = sid * OleDirectoryEntry.DIRENTRY_SIZE
        if directory_chain:
            ordinal = entry_offset // self.sectorsize
            within = entry_offset % self.sectorsize
            sector = directory_chain[ordinal] if ordinal < len(directory_chain) else None
        else:
            sector = None
            within = entry_offset % self.sectorsize
        if sector is None:
            file_offset = None
        else:
            file_offset = (sector + 1) * self.sectorsize + within
        return {
            'kind': 'directory-entry',
            'sid': sid,
            'index': sid,
            'directory_stream_offset': entry_offset,
            'offset_in_sector': within,
            'sector': sector,
            'file_offset': file_offset,
            'offset': file_offset,
            'length': OleDirectoryEntry.DIRENTRY_SIZE,
            'label': 'directory entry SID %d at file offset %s' %
                     (sid, '0x%X' % file_offset if file_offset is not None
                      else 'unavailable'),
        }

    def _manifest_resolve_path(self, path_components):
        node = self.root
        ancestors = [self.root]
        actual = []
        for component in path_components:
            wanted = self._manifest_name_text(component).lower()
            for kid in node.kids:
                if self._manifest_name_text(kid.name).lower() == wanted:
                    node = kid
                    ancestors.append(kid)
                    actual.append(kid.name)
                    break
            else:
                return None, ancestors, actual, 'not_found'
        if node.entry_type != STGTY_STREAM:
            return node, ancestors, actual, 'not_a_stream'
        return node, ancestors, actual, 'ok'

    def _manifest_structural_context(self):
        fat_ids, difat_chain = self._manifest_fat_layout()
        directory_size = getattr(self.directory_fp, 'size', None)
        expected_directory = None
        if directory_size:
            expected_directory = (
                directory_size + self.sectorsize - 1) // self.sectorsize
        directory_chain, directory_issues = self._manifest_follow_chain(
            self.fat, self.first_dir_sector, expected_directory, 'sector')

        minifat_chain = []
        minifat_issues = []
        if self.num_mini_fat_sectors:
            minifat_chain, minifat_issues = self._manifest_follow_chain(
                self.fat, self.first_mini_fat_sector,
                self.num_mini_fat_sectors, 'sector')

        root_chain = []
        root_issues = []
        if self.root is not None and self.root.size:
            expected_root = (
                self.root.size + self.sectorsize - 1) // self.sectorsize
            root_chain, root_issues = self._manifest_follow_chain(
                self.fat, self.root.isectStart, expected_root, 'sector')
        return {
            'fat_ids': fat_ids,
            'difat_chain': difat_chain,
            'directory_chain': directory_chain,
            'directory_issues': directory_issues,
            'minifat_chain': minifat_chain,
            'minifat_issues': minifat_issues,
            'root_chain': root_chain,
            'root_issues': root_issues,
        }

    def _manifest_all_user_streams(self):
        records = []
        known_sids = set()
        for path in self.listdir():
            sid = self._find(path)
            entry = self.direntries[sid]
            known_sids.add(sid)
            chain, issues = self._manifest_chain_for_entry(entry)
            records.append({
                'sid': sid,
                'entry': entry,
                'path_components': list(path),
                'path': self._manifest_path_text(path),
                'chain': chain,
                'issues': issues,
                'unit_kind': 'minisector' if entry.is_minifat else 'sector',
                'unreferenced': False,
            })
        records.extend(self._manifest_unreferenced_streams(known_sids))
        return records

    def _manifest_unreferenced_streams(self, known_sids):
        # Parse stream entries present in the directory stream but not
        # reachable from the storage tree. A withdrawn or crafted attachment
        # can hide a second claim on the same allocation unit there. Only the
        # 128-byte directory entry and its allocation chain are read.
        records = []
        if not self.directory_fp or self.direntries is None:
            return records

        class EntryView(object):
            pass

        for sid in range(len(self.direntries)):
            if sid in known_sids or sid == 0:
                continue
            try:
                self.directory_fp.seek(sid * OleDirectoryEntry.DIRENTRY_SIZE)
                raw = self.directory_fp.read(OleDirectoryEntry.DIRENTRY_SIZE)
            except Exception:
                break
            if len(raw) != OleDirectoryEntry.DIRENTRY_SIZE:
                break
            (name_raw, namelength, entry_type, color, sid_left, sid_right,
             sid_child, clsid, flags, ctime, mtime, isectStart,
             sizeLow, sizeHigh) = struct.unpack(
                 OleDirectoryEntry.STRUCT_DIRENTRY, raw)
            if entry_type != STGTY_STREAM or (sizeLow == 0 and sizeHigh == 0):
                continue
            if self.sectorsize == 512:
                size = sizeLow
            else:
                size = sizeLow + (long(sizeHigh) << 32)
            if size <= 0:
                continue
            name_length = min(namelength, len(name_raw))
            name_utf16 = name_raw[:max(name_length - 2, 0)]
            try:
                name = self._manifest_name_text(
                    self._decode_utf16_str(name_utf16))
            except Exception:
                name = ''
            view = EntryView()
            view.entry_type = entry_type
            view.size = size
            view.is_minifat = size < self.minisectorcutoff
            view.isectStart = isectStart
            chain, issues = self._manifest_chain_for_entry(view)
            path = '<unreferenced SID %d>' % sid
            records.append({
                'sid': sid,
                'entry': view,
                'path_components': [path],
                'path': path,
                'chain': chain,
                'issues': issues,
                'unit_kind': (
                    'minisector' if view.is_minifat else 'sector'),
                'unreferenced': True,
                'directory_name': name,
            })
        return records

    def _manifest_stream_record(self, record, role, structural):
        """
        Expand one directory entry into an auditable list of locators.

        Only structural data is inspected: directory entries, FAT/MiniFAT
        pointers, and the MiniStream layout.  Stream payload bytes are never
        read by this method.
        """
        entry = record['entry']
        chain = record['chain']
        is_mini = entry.is_minifat
        unit_kind = record['unit_kind']
        unit_size = self.minisectorsize if is_mini else self.sectorsize
        table = self.minifat if is_mini else self.fat
        fat_ids = structural['fat_ids']
        minifat_chain = structural['minifat_chain']
        root_chain = structural['root_chain']
        directory_chain = structural['directory_chain']

        directory_entry = self._manifest_directory_entry_locator(
            entry.sid, directory_chain)
        ctime = entry.getctime()
        mtime = entry.getmtime()
        directory_entry.update({
            'name': self._manifest_name_text(entry.name),
            'entry_type': entry.entry_type,
            'size': entry.size,
            'is_minifat': is_mini,
            'isectStart': entry.isectStart,
            'clsid': entry.clsid,
            'flags': entry.dwUserFlags,
            'create_time_raw': entry.createTime,
            'modify_time_raw': entry.modifyTime,
            'create_time': ctime.isoformat() if ctime else None,
            'modify_time': mtime.isoformat() if mtime else None,
        })

        parent_entries = []
        directory_sectors = set()
        for ancestor in record.get('ancestors', []):
            locator = self._manifest_directory_entry_locator(
                ancestor.sid, directory_chain)
            locator = dict(locator)
            locator.update({
                'name': self._manifest_name_text(ancestor.name),
                'entry_type': ancestor.entry_type,
                'size': ancestor.size,
            })
            parent_entries.append(locator)
            if locator.get('sector') is not None:
                directory_sectors.add(locator['sector'])
        if directory_entry.get('sector') is not None:
            directory_sectors.add(directory_entry['sector'])

        data_units = []
        allocation_entries = []
        fat_sectors = set()
        minifat_sectors = set()
        ministream_sectors = set()
        for ordinal, unit in enumerate(chain):
            if is_mini:
                unit_locator = self._manifest_mini_data_locator(unit, root_chain)
                table_locator = self._manifest_minifat_entry_locator(
                    unit, minifat_chain)
                if table_locator:
                    minifat_sectors.add(table_locator.get('minifat_sector'))
                if unit_locator.get('sector') is not None:
                    ministream_sectors.add(unit_locator['sector'])
            else:
                unit_locator = self._manifest_sector_locator(unit)
                table_locator = self._manifest_fat_entry_locator(unit, fat_ids)
                if table_locator:
                    fat_sectors.add(table_locator.get('fat_sector'))

            if unit_locator is None:
                unit_locator = {
                    'kind': unit_kind,
                    'unit_kind': unit_kind,
                    'unit_index': unit,
                    'index': unit,
                    'file_offset': None,
                    'offset': None,
                    'length': unit_size,
                    'label': '%s %s (mapping unavailable)' % (unit_kind, unit),
                }
            else:
                unit_locator = dict(unit_locator)
            unit_locator['logical_offset'] = ordinal * unit_size
            unit_locator['data_length'] = max(
                0, min(unit_size, entry.size - ordinal * unit_size))
            unit_locator['unit_kind'] = unit_kind
            unit_locator['unit_index'] = unit
            data_units.append(unit_locator)

            next_unit = None
            if table is not None and unit < len(table):
                next_unit = int(table[unit]) & 0xFFFFFFFF
            allocation_entries.append({
                'unit': unit,
                'next': next_unit,
                'table': 'MiniFAT' if is_mini else 'FAT',
                'locator': table_locator,
                'fat_sector': (table_locator or {}).get('fat_sector'),
                'minifat_sector': (table_locator or {}).get('minifat_sector'),
                'file_offset': (table_locator or {}).get('file_offset'),
            })

        # The FAT entries that point from one directory, MiniFAT or
        # MiniStream sector to the next are supporting metadata too.
        for unit in directory_chain:
            locator = self._manifest_fat_entry_locator(unit, fat_ids)
            if locator:
                fat_sectors.add(locator.get('fat_sector'))
        if is_mini:
            for unit in minifat_chain:
                locator = self._manifest_fat_entry_locator(unit, fat_ids)
                if locator:
                    fat_sectors.add(locator.get('fat_sector'))
            for unit in root_chain:
                locator = self._manifest_fat_entry_locator(unit, fat_ids)
                if locator:
                    fat_sectors.add(locator.get('fat_sector'))

        fat_sectors.discard(None)
        minifat_sectors.discard(None)
        ministream_sectors.discard(None)

        support = {
            'header': {
                'kind': 'header',
                'file_offset': 0,
                'offset': 0,
                'length': 512,
                'label': 'OLE header at file offset 0x0',
            },
            'directory': {
                'sectors': sorted(directory_sectors),
                'ranges': [self._manifest_range(sect)
                           for sect in sorted(directory_sectors)],
            },
            'fat': {
                'sectors': sorted(fat_sectors),
                'ranges': [self._manifest_range(sect)
                           for sect in sorted(fat_sectors)],
            },
            'difat': {
                'sectors': list(structural['difat_chain']),
                'ranges': [self._manifest_range(sect)
                           for sect in structural['difat_chain']],
            },
        }
        if is_mini:
            support['minifat'] = {
                'sectors': sorted(minifat_sectors),
                'ranges': [self._manifest_range(sect)
                           for sect in sorted(minifat_sectors)],
            }
            support['ministream'] = {
                'sectors': sorted(ministream_sectors),
                'ranges': [self._manifest_range(sect)
                           for sect in sorted(ministream_sectors)],
            }

        allocation_table_sectors = (
            sorted(minifat_sectors) if is_mini else sorted(fat_sectors))
        return {
            'path': record['path'],
            'sid': entry.sid,
            'size': entry.size,
            'storage': 'minifat' if is_mini else 'fat',
            'allocation_domain': 'MiniFAT' if is_mini else 'FAT',
            'role': role,
            'directory_entry': directory_entry,
            'parent_entries': parent_entries,
            'start_unit': entry.isectStart,
            'allocation_chain': list(chain),
            'unit_count': len(chain),
            'unit_kind': unit_kind,
            'data_units': data_units,
            'allocation_table': {
                'type': 'MiniFAT' if is_mini else 'FAT',
                'unit_kind': unit_kind,
                'unit_size': unit_size,
                'expected_unit_count': (
                    (entry.size + unit_size - 1) // unit_size
                    if entry.size else 0),
                'units': list(chain),
                'entries': allocation_entries,
                'sectors': allocation_table_sectors,
                'terminator': ENDOFCHAIN,
            },
            'support': support,
            'issues': list(record.get('issues', [])),
        }

    def export_manifest(self, approved_streams=None, allow_shared_units=False,
                        metadata_streams=None, **kwargs):
        """
        Build a pre-export forensic checklist for an OLE attachment.

        The checklist is deliberately narrower than a generic OLE dump: only
        streams named by the caller are placed in ``export_streams``.  For each
        approved stream the manifest lists every locator a reviewer needs to
        find the judgement again in the original file:

        * the 128-byte directory entry (SID, sector and absolute file offset),
        * the parent storage directory entries,
        * the FAT or MiniFAT allocation chain,
        * the physical FAT/MiniFAT sectors holding each next pointer,
        * for MiniFAT streams, the MiniStream sectors and mini-sector spans.

        Allocation units are cross-checked against every stream in the file.
        If a unit backing an approved stream is also referenced by a stream
        that was not approved (or by a structural stream such as the directory
        or MiniFAT), a ``shared_allocation_unit`` gap is returned.  The other
        stream is named only so that the reviewer can locate it; it is never
        added to ``export_streams`` and its payload is never read or included.

        :param approved_streams: explicit approval list.  Each item may be a
            path string (``'Storage/Stream'``), a list of path components, or
            a dict with a ``path``/``stream`` key.  A policy dict with
            ``streams``/``approved_streams`` and optional ``metadata`` keys is
            also accepted.  No wildcards or implicit expansion are performed.
        :param allow_shared_units: if False (default), a shared allocation
            unit is a blocking gap.  If True, it remains a warning and still
            requires the caller to have obtained the extra authorization.
        :param metadata_streams: optional explicit list of metadata streams
            (for example ``\\x05SummaryInformation``) to include in the export.
            They are not discovered implicitly.
        :returns: :class:`OleExportManifest` (a dict subclass).
        """
        if 'approved' in kwargs and approved_streams is None:
            approved_streams = kwargs.pop('approved')
        if 'streams' in kwargs and approved_streams is None:
            approved_streams = kwargs.pop('streams')
        if 'approvals' in kwargs and approved_streams is None:
            approved_streams = kwargs.pop('approvals')
        if 'allowed_streams' in kwargs and approved_streams is None:
            approved_streams = kwargs.pop('allowed_streams')
        if 'allowed' in kwargs and approved_streams is None:
            approved_streams = kwargs.pop('allowed')
        if 'allow_shared' in kwargs:
            allow_shared_units = kwargs.pop('allow_shared')
        if 'include_metadata' in kwargs and metadata_streams is None:
            metadata_streams = kwargs.pop('include_metadata')
        if 'metadata' in kwargs and metadata_streams is None:
            metadata_streams = kwargs.pop('metadata')

        # A policy dict may carry both payload and metadata approvals.  A
        # single-entry dict with a path/stream key is treated as one stream,
        # not as a policy.
        if isinstance(approved_streams, dict):
            policy = approved_streams
            policy_keys = ('approved_streams', 'streams', 'approved',
                           'allowed', 'allow', 'payload', 'copy', 'include')
            if any(key in policy for key in policy_keys):
                found = None
                for key in policy_keys:
                    if key in policy:
                        found = policy[key]
                        break
                approved_streams = found
                if metadata_streams is None:
                    for key in ('metadata_streams', 'metadata',
                                'supporting_metadata'):
                        if key in policy:
                            metadata_streams = policy[key]
                            break
            elif ('path' in policy or 'stream' in policy or
                  'name' in policy or 'components' in policy):
                approved_streams = [policy]
            else:
                approved_streams = []

        def normalise(value, default_role):
            entries = []
            if value is None:
                return entries
            if isinstance(value, dict):
                value = [value]
            elif isinstance(value, (basestring, bytes)):
                value = [value]
            else:
                try:
                    value = list(value)
                except TypeError:
                    value = [value]
            for item in value:
                role = default_role
                requested = item
                if isinstance(item, dict):
                    role = item.get('role', default_role)
                    requested = item.get(
                        'path', item.get(
                            'stream', item.get(
                                'name', item.get('components'))))
                if isinstance(requested, bytes):
                    requested = requested.decode('utf-8', 'replace')
                if isinstance(requested, basestring):
                    components = [part for part in
                                  requested.replace('\\', '/').split('/')
                                  if part != '']
                elif isinstance(requested, (list, tuple)):
                    components = list(requested)
                elif requested is None:
                    components = []
                else:
                    components = [requested]
                if components:
                    entries.append((
                        components,
                        role,
                        self._manifest_path_text(components),
                    ))
            return entries

        requested = (
            normalise(approved_streams, 'stream') +
            normalise(metadata_streams, 'metadata'))

        structural = self._manifest_structural_context()
        directory_chain = structural['directory_chain']
        gaps = []
        approved_items = []
        seen_sids = set()

        for components, role, requested_text in requested:
            entry, ancestors, actual, status = self._manifest_resolve_path(
                components)
            if status == 'not_found':
                ancestor = ancestors[-1] if ancestors else None
                missing_index = len(actual)
                locator = {
                    'kind': 'path',
                    'path': requested_text,
                    'requested_path': requested_text,
                    'resolved_components': list(actual),
                    'missing_component': (
                        components[missing_index]
                        if missing_index < len(components) else None),
                    'file_offset': None,
                    'offset': None,
                    'label': 'path %r (missing after %r)' %
                             (requested_text, actual),
                }
                if ancestor is not None:
                    ancestor_locator = self._manifest_directory_entry_locator(
                        ancestor.sid, directory_chain)
                    locator['ancestor_sid'] = ancestor.sid
                    locator['ancestor_entry'] = ancestor_locator
                    locator['file_offset'] = ancestor_locator.get('file_offset')
                    locator['offset'] = locator['file_offset']
                    locator['label'] = (
                        'path %r missing below SID %d at file offset %s' %
                        (requested_text, ancestor.sid,
                         '0x%X' % locator['file_offset']
                         if locator['file_offset'] is not None
                         else 'unavailable'))
                gap = self._manifest_issue(
                    'stream_not_found',
                    'approved stream was not found in the original file',
                    locator=locator)
                gap.update({
                    'path': requested_text,
                    'requested_path': requested_text,
                    'missing_component': locator['missing_component'],
                })
                gaps.append(gap)
                continue
            if status == 'not_a_stream':
                locator = self._manifest_directory_entry_locator(
                    entry.sid, directory_chain)
                locator = dict(locator)
                locator['path'] = requested_text
                gap = self._manifest_issue(
                    'not_a_stream',
                    'approved path resolves to a storage, not a stream',
                    locator=locator)
                gap.update({
                    'path': requested_text,
                    'requested_path': requested_text,
                    'sid': entry.sid,
                    'entry_type': entry.entry_type,
                })
                gaps.append(gap)
                continue
            if entry.sid in seen_sids:
                continue
            seen_sids.add(entry.sid)
            approved_items.append({
                'entry': entry,
                'ancestors': ancestors,
                'actual_components': actual,
                'path': self._manifest_path_text(actual),
                'requested_path': requested_text,
                'role': role,
            })

        approved_sids = set(item['entry'].sid for item in approved_items)
        all_records = self._manifest_all_user_streams()
        records_by_sid = dict((record['sid'], record)
                              for record in all_records)

        stream_records = []
        for item in approved_items:
            record = records_by_sid.get(item['entry'].sid)
            if record is None:
                entry = item['entry']
                chain, issues = self._manifest_chain_for_entry(entry)
                record = {
                    'sid': entry.sid,
                    'entry': entry,
                    'path_components': list(item['actual_components']),
                    'path': item['path'],
                    'chain': chain,
                    'issues': issues,
                    'unit_kind': (
                        'minisector' if entry.is_minifat else 'sector'),
                }
            record = dict(record)
            record['ancestors'] = item['ancestors']
            stream_record = self._manifest_stream_record(
                record, item['role'], structural)
            stream_record['requested_path'] = item['requested_path']
            stream_records.append(stream_record)

            if stream_record['directory_entry'].get('file_offset') is None:
                locator = dict(stream_record['directory_entry'])
                locator['path'] = item['path']
                locator['sid'] = item['entry'].sid
                gap = self._manifest_issue(
                    'directory_entry_locator_unavailable',
                    'approved stream directory entry cannot be mapped to an '
                    'absolute file offset',
                    locator=locator)
                gap.update({
                    'path': item['path'],
                    'stream': item['path'],
                    'sid': item['entry'].sid,
                })
                gaps.append(gap)

            for unit in stream_record.get('data_units', []):
                if unit.get('file_offset') is not None:
                    continue
                locator = dict(unit)
                locator['path'] = item['path']
                locator['sid'] = item['entry'].sid
                gap = self._manifest_issue(
                    'allocation_unit_locator_unavailable',
                    'approved stream allocation unit cannot be mapped to an '
                    'absolute file offset',
                    locator=locator)
                gap.update({
                    'path': item['path'],
                    'stream': item['path'],
                    'sid': item['entry'].sid,
                    'unit_kind': unit.get('unit_kind'),
                    'unit_index': unit.get('unit_index'),
                    'logical_offset': unit.get('logical_offset'),
                })
                gaps.append(gap)

            for issue in record.get('issues', []):
                gap = dict(issue)
                gap.update({
                    'path': item['path'],
                    'stream': item['path'],
                    'sid': item['entry'].sid,
                })
                gaps.append(gap)

        # Map every allocation unit to its owner(s), including structural
        # streams.  This is a metadata walk only; no stream payload is read.
        owners = {}

        def add_owner(key, owner):
            bucket = owners.setdefault(key, [])
            signature = (owner.get('role'), owner.get('sid'),
                         owner.get('path'))
            for existing in bucket:
                if (existing.get('role'), existing.get('sid'),
                        existing.get('path')) == signature:
                    return
            bucket.append(owner)

        for record in all_records:
            entry = record['entry']
            if entry.entry_type != STGTY_STREAM or entry.size == 0:
                continue
            for unit in record['chain']:
                key = (record['unit_kind'], int(unit))
                add_owner(key, {
                    'role': 'stream',
                    'sid': record['sid'],
                    'path': record['path'],
                    'approved': record['sid'] in approved_sids,
                    'support_metadata': False,
                })

        for sector in structural['directory_chain']:
            add_owner(('sector', int(sector)), {
                'role': 'directory', 'sid': None, 'path': None,
                'approved': False, 'support_metadata': True,
            })
        for sector in structural['minifat_chain']:
            add_owner(('sector', int(sector)), {
                'role': 'minifat', 'sid': None, 'path': None,
                'approved': False, 'support_metadata': True,
            })
        for sector in structural['root_chain']:
            add_owner(('sector', int(sector)), {
                'role': 'ministream', 'sid': None, 'path': None,
                'approved': False, 'support_metadata': True,
            })
        for sector in structural['fat_ids']:
            add_owner(('sector', int(sector)), {
                'role': 'fat', 'sid': None, 'path': None,
                'approved': False, 'support_metadata': True,
            })
        for sector in structural['difat_chain']:
            add_owner(('sector', int(sector)), {
                'role': 'difat', 'sid': None, 'path': None,
                'approved': False, 'support_metadata': True,
            })

        shared_units = []
        for key in sorted(owners.keys()):
            unit_kind, unit_index = key
            owner_list = owners[key]
            if len(owner_list) < 2:
                continue
            approved_owners = [
                owner for owner in owner_list
                if owner['role'] == 'stream' and owner.get('approved')]
            if not approved_owners:
                continue
            stream_owners = [
                owner for owner in owner_list if owner['role'] == 'stream']
            unapproved_owners = [
                owner for owner in stream_owners
                if not owner.get('approved')]
            structural_owners = [
                owner for owner in owner_list if owner['role'] != 'stream']

            if unit_kind == 'minisector':
                unit_locator = self._manifest_mini_data_locator(
                    unit_index, structural['root_chain'])
            else:
                unit_locator = self._manifest_sector_locator(unit_index)
            if unit_locator is None:
                unit_locator = {
                    'kind': unit_kind,
                    'unit_kind': unit_kind,
                    'unit_index': unit_index,
                    'index': unit_index,
                    'file_offset': None,
                    'offset': None,
                    'length': (
                        self.minisectorsize if unit_kind == 'minisector'
                        else self.sectorsize),
                    'label': '%s %d (locator unavailable)' %
                             (unit_kind, unit_index),
                }
            unit_locator = dict(unit_locator)
            unit_locator['unit_kind'] = unit_kind
            unit_locator['unit_index'] = unit_index

            involved_entries = []
            for owner in stream_owners:
                locator = self._manifest_directory_entry_locator(
                    owner['sid'], directory_chain)
                locator = dict(locator)
                locator['path'] = owner['path']
                locator['approved'] = bool(owner.get('approved'))
                involved_entries.append(locator)

            requires_authorization = bool(
                unapproved_owners or structural_owners)
            other_path = (
                unapproved_owners[0]['path'] if unapproved_owners else None)
            other_sid = (
                unapproved_owners[0]['sid'] if unapproved_owners else None)
            if unapproved_owners:
                reason = (
                    'allocation unit is also referenced by unapproved '
                    'stream(s): %s' %
                    ', '.join(owner['path'] for owner in unapproved_owners))
            elif structural_owners:
                reason = (
                    'allocation unit is also used by structural stream(s): %s'
                    % ', '.join(sorted(set(
                        owner['role'] for owner in structural_owners))))
            else:
                reason = 'allocation unit is shared only by approved streams'

            shared = {
                'kind': unit_kind,
                'unit_kind': unit_kind,
                'unit_index': unit_index,
                'index': unit_index,
                'unit': unit_index,
                'file_offset': unit_locator.get('file_offset'),
                'offset': unit_locator.get('file_offset'),
                'length': unit_locator.get('length'),
                'sector': unit_locator.get('sector'),
                'locator': unit_locator,
                'location': unit_locator.get('label'),
                'owners': [
                    {
                        'role': owner['role'],
                        'sid': owner.get('sid'),
                        'path': owner.get('path'),
                        'approved': bool(owner.get('approved')),
                        'support_metadata': bool(
                            owner.get('support_metadata')),
                    }
                    for owner in owner_list],
                'streams': [owner['path'] for owner in stream_owners],
                'approved_streams': [
                    owner['path'] for owner in approved_owners],
                'unapproved_streams': [
                    owner['path'] for owner in unapproved_owners],
                'structural_owners': sorted(set(
                    owner['role'] for owner in structural_owners)),
                'other_path': other_path,
                'other_sid': other_sid,
                'requires_authorization': requires_authorization,
                'authorization_required': requires_authorization,
                'requires_extra_authorization': requires_authorization,
                'needs_extra_authorization': requires_authorization,
                'reason': reason,
                'directory_entries': involved_entries,
                'other_payload_included': False,
                'export_scope_unchanged': True,
            }
            shared_units.append(shared)

            if requires_authorization:
                blocking = not bool(allow_shared_units)
                message = (
                    'shared allocation unit %s %d backs approved stream %s'
                    % (unit_kind, unit_index,
                       approved_owners[0]['path']))
                if other_path:
                    message += ' and unapproved stream %s' % other_path
                if structural_owners:
                    message += ' and structural role(s) %s' % (
                        ', '.join(shared['structural_owners']))
                message += (
                    '; extra authorization is required before export'
                    if blocking else
                    '; shared-unit authorization was acknowledged by the '
                    'caller, but the other stream is still not exported')
                gap = {
                    'code': 'shared_allocation_unit',
                    'type': 'shared_allocation_unit',
                    'message': message,
                    'reason': reason,
                    'severity': 'error' if blocking else 'warning',
                    'blocking': blocking,
                    'requires_authorization': True,
                    'authorization_required': True,
                    'requires_extra_authorization': True,
                    'needs_extra_authorization': True,
                    'path': approved_owners[0]['path'],
                    'stream': approved_owners[0]['path'],
                    'sid': approved_owners[0]['sid'],
                    'other_path': other_path,
                    'other_sid': other_sid,
                    'shared_with': (
                        [owner['path'] for owner in unapproved_owners] or
                        shared['structural_owners']),
                    'unit_kind': unit_kind,
                    'unit_index': unit_index,
                    'sector': unit_locator.get('sector'),
                    'file_offset': unit_locator.get('file_offset'),
                    'offset': unit_locator.get('file_offset'),
                    'length': unit_locator.get('length'),
                    'locator': unit_locator,
                    'location': unit_locator.get('label'),
                    'shared_unit': shared,
                }
                gaps.append(gap)

        # Annotate each approved data unit with the same shared-unit
        # judgement, so a reviewer does not have to join two tables by hand.
        shared_by_key = {}
        for shared in shared_units:
            shared_by_key[(shared['unit_kind'], shared['unit_index'])] = shared
        for record in stream_records:
            record_shares = []
            for unit in record['data_units']:
                key = (unit.get('unit_kind'), unit.get('unit_index'))
                shared = shared_by_key.get(key)
                if shared is None:
                    continue
                unit['shared'] = True
                unit['requires_authorization'] = shared[
                    'requires_authorization']
                unit['shared_with'] = (
                    shared['unapproved_streams'] or
                    shared['structural_owners'])
                unit['other_path'] = shared.get('other_path')
                record_shares.append(shared)
            record['shared_units'] = record_shares

        # Withheld streams are listed for localisation only.  They are never
        # added to the export set and their data is never read.
        withheld_by_sid = {}
        for shared in shared_units:
            for owner in shared['owners']:
                if owner['role'] != 'stream' or owner['approved']:
                    continue
                item = withheld_by_sid.get(owner['sid'])
                if item is None:
                    locator = self._manifest_directory_entry_locator(
                        owner['sid'], directory_chain)
                    item = {
                        'path': owner['path'],
                        'sid': owner['sid'],
                        'reason': (
                            'shares an allocation unit with an approved '
                            'stream; authorization not present'),
                        'directory_entry': locator,
                        'shared_units': [],
                        'exported': False,
                        'exportable': False,
                        'disclosable': False,
                        'authorized': False,
                        'payload_included': False,
                    }
                    withheld_by_sid[owner['sid']] = item
                item['shared_units'].append({
                    'unit_kind': shared['unit_kind'],
                    'unit_index': shared['unit_index'],
                    'file_offset': shared['file_offset'],
                    'sector': shared['sector'],
                    'locator': shared['locator'],
                })
        withheld_streams = sorted(
            withheld_by_sid.values(), key=lambda item: item['sid'])

        needed_entry_sids = set()
        entries_needed = []
        for record in stream_records:
            for locator in record.get('parent_entries', []):
                if locator['sid'] not in needed_entry_sids:
                    needed_entry_sids.add(locator['sid'])
                    entries_needed.append(locator)
        entries_needed.sort(key=lambda locator: locator['sid'])

        directory_entry_sids = set(
            entry.sid for entry in (self.direntries or [])
            if entry is not None and entry.entry_type != STGTY_EMPTY)
        directory_entry_sids.update(
            record['sid'] for record in all_records
            if record.get('unreferenced'))
        unapproved_entry_count = len(
            directory_entry_sids - needed_entry_sids)

        mini_records = [
            record for record in all_records
            if record['entry'].is_minifat and record['entry'].size > 0]
        approved_mini_sids = set(
            record['sid'] for record in mini_records
            if record['sid'] in approved_sids)
        unapproved_mini_records = [
            record for record in mini_records
            if record['sid'] not in approved_mini_sids]

        minifat_entries_needed = []
        seen_minifat_units = set()
        approved_ministream_spans = []
        for record in stream_records:
            if record['storage'] != 'minifat':
                continue
            for entry in record['allocation_table']['entries']:
                if entry['unit'] in seen_minifat_units:
                    continue
                seen_minifat_units.add(entry['unit'])
                minifat_entries_needed.append({
                    'unit': entry['unit'],
                    'next': entry['next'],
                    'locator': entry['locator'],
                })
            for unit in record['data_units']:
                approved_ministream_spans.append({
                    'path': record['path'],
                    'sid': record['sid'],
                    'unit_kind': unit.get('unit_kind'),
                    'unit_index': unit.get('unit_index'),
                    'file_offset': unit.get('file_offset'),
                    'sector': unit.get('sector'),
                    'length': unit.get('length'),
                    'data_length': unit.get('data_length'),
                    'locator': unit,
                })

        directory_dependency = {
            'first_sector': self.first_dir_sector,
            'sectors': list(structural['directory_chain']),
            'ranges': [self._manifest_range(sector)
                       for sector in structural['directory_chain']],
            'entries_needed': entries_needed,
            'entry_count': len(self.direntries or []),
            'unapproved_entry_count': unapproved_entry_count,
            'contains_unapproved_entries': unapproved_entry_count > 0,
            'copy_entire_stream': False,
            'copy_ranges': [
                {'sid': locator['sid'],
                 'file_offset': locator['file_offset'],
                 'length': locator['length']}
                for locator in entries_needed],
            'disclosure_class': 'directory-metadata',
        }
        fat_dependency = {
            'sectors': list(structural['fat_ids']),
            'ranges': [self._manifest_range(sector)
                       for sector in structural['fat_ids']],
            'num_fat_sectors': self.num_fat_sectors,
            'entries_per_sector': self.sectorsize // 4,
            'copy_entire_stream': 'allocation-metadata-only',
            'disclosure_class': 'allocation-metadata',
        }
        difat_dependency = {
            'present': bool(structural['difat_chain']),
            'sectors': list(structural['difat_chain']),
            'ranges': [self._manifest_range(sector)
                       for sector in structural['difat_chain']],
            'disclosure_class': 'allocation-metadata',
        }
        minifat_dependency = {
            'present': bool(structural['minifat_chain']),
            'first_sector': self.first_mini_fat_sector,
            'sectors': list(structural['minifat_chain']),
            'ranges': [self._manifest_range(sector)
                       for sector in structural['minifat_chain']],
            'entries_needed': minifat_entries_needed,
            'copy_entire_stream': False,
            'copy_entries': minifat_entries_needed,
            'disclosure_class': 'allocation-metadata',
        }
        ministream_dependency = {
            'present': bool(self.root is not None and self.root.size),
            'first_sector': (
                self.root.isectStart if self.root is not None else None),
            'size': self.root.size if self.root is not None else 0,
            'sectors': list(structural['root_chain']),
            'ranges': [self._manifest_range(sector)
                       for sector in structural['root_chain']],
            'approved_spans': approved_ministream_spans,
            'contains_unapproved_payload': bool(unapproved_mini_records),
            'unapproved_mini_stream_count': len(unapproved_mini_records),
            'copy_entire_stream': False,
            'copy_ranges': list(approved_ministream_spans),
            'disclosure_class': 'payload-container',
        }

        dependencies = {
            'header': {
                'kind': 'header',
                'file_offset': 0,
                'offset': 0,
                'length': 512,
                'label': 'OLE header at file offset 0x0',
                'disclosure_class': 'structural',
            },
            'directory': directory_dependency,
            'fat': fat_dependency,
            'difat': difat_dependency,
            'minifat': minifat_dependency,
            'ministream': ministream_dependency,
        }

        warnings_list = []
        if unapproved_entry_count:
            warnings_list.append({
                'code': 'directory_stream_contains_unapproved_entries',
                'type': 'directory_stream_contains_unapproved_entries',
                'message': (
                    'The directory stream also contains %d entry/entries '
                    'outside the approved set. Copy only the listed 128-byte '
                    'entry ranges, not the entire directory stream.'
                    % unapproved_entry_count),
                'severity': 'warning',
                'blocking': False,
                'requires_authorization': False,
                'unapproved_entry_count': unapproved_entry_count,
                'entries_needed': [locator['sid'] for locator in entries_needed],
                'copy_entire_stream': False,
                'locator': (
                    self._manifest_range(self.first_dir_sector)
                    if self.first_dir_sector not in (
                        ENDOFCHAIN, FREESECT) else None),
                'disclosure_class': 'directory-metadata',
            })
        if unapproved_mini_records:
            warnings_list.append({
                'code': 'ministream_contains_unapproved_payload',
                'type': 'ministream_contains_unapproved_payload',
                'message': (
                    'The MiniStream container also holds %d unapproved '
                    'mini-stream(s). Copy only the approved mini-sector '
                    'spans listed in dependencies.ministream.approved_spans; '
                    'do not copy the whole MiniStream.'
                    % len(unapproved_mini_records)),
                'severity': 'warning',
                'blocking': False,
                'requires_authorization': False,
                'unapproved_mini_stream_count': len(unapproved_mini_records),
                'approved_spans': approved_ministream_spans,
                'copy_entire_stream': False,
                'locator': (
                    self._manifest_range(self.root.isectStart)
                    if self.root is not None and self.root.size else None),
                'disclosure_class': 'payload-container',
            })

        export_streams = []
        for record in stream_records:
            if record['path'] not in export_streams:
                export_streams.append(record['path'])
        payload_streams = [
            record['path'] for record in stream_records
            if record['role'] != 'metadata']
        metadata_stream_paths = [
            record['path'] for record in stream_records
            if record['role'] == 'metadata']
        streams_by_path = dict(
            (record['path'], record) for record in stream_records)

        blocking_gaps = [gap for gap in gaps if gap.get('blocking')]
        ok = not blocking_gaps
        requires_extra_authorization = any(
            shared.get('requires_authorization')
            for shared in shared_units)

        copy_streams = []
        for record in stream_records:
            data_ranges = []
            for unit in record['data_units']:
                data_ranges.append({
                    'file_offset': unit.get('file_offset'),
                    'length': unit.get('data_length', unit.get('length')),
                    'unit_kind': unit.get('unit_kind'),
                    'unit_index': unit.get('unit_index'),
                    'locator': unit,
                })
            copy_streams.append({
                'path': record['path'],
                'sid': record['sid'],
                'data_ranges': data_ranges,
                'directory_entry': record['directory_entry'],
                'allocation_entries': record['allocation_table']['entries'],
            })
        copy_plan = {
            'policy': 'minimal-ranges-only',
            'streams': copy_streams,
            'directory_entries': entries_needed,
            'header': {'file_offset': 0, 'length': 512},
            'fat_entries': [
                entry for record in stream_records
                if record['storage'] == 'fat'
                for entry in record['allocation_table']['entries']],
            'allocation_entries': [
                entry for record in stream_records
                for entry in record['allocation_table']['entries']],
            'minifat_entries': minifat_entries_needed,
            'ministream_spans': approved_ministream_spans,
            'excluded': {
                'entire_directory_stream': True,
                'entire_ministream': True,
                'entire_fat_or_minifat_stream': True,
                'unapproved_stream_payloads': True,
            },
        }

        manifest = OleExportManifest({
            'version': 1,
            'policy': 'explicit-approval-only',
            'ok': ok,
            'status': 'ok' if ok else 'gap',
            'export_allowed': ok,
            'requires_extra_authorization': requires_extra_authorization,
            'authorization_required': requires_extra_authorization,
            'content_included': False,
            'payload_bytes_in_manifest': False,
            'approved_streams': [
                item['requested_path'] for item in approved_items],
            'export_streams': export_streams,
            'payload_streams': payload_streams,
            'metadata_streams': metadata_stream_paths,
            'streams': stream_records,
            'streams_by_path': streams_by_path,
            'dependencies': dependencies,
            'copy_plan': copy_plan,
            'checklist': copy_plan,
            'shared_units': shared_units,
            'withheld_streams': withheld_streams,
            'gaps': gaps,
            'blocking_gaps': blocking_gaps,
            'gap': (blocking_gaps[0] if blocking_gaps
                    else (gaps[0] if gaps else None)),
            'warnings': warnings_list,
            'scope': {
                'policy': 'explicit-approval-only',
                'requested_streams': [
                    text for _, _, text in requested],
                'approved_streams': [
                    item['path'] for item in approved_items],
                'export_streams': list(export_streams),
                'payload_streams': list(payload_streams),
                'metadata_streams': list(metadata_stream_paths),
                'structural_metadata_included': True,
                'payload_bytes_in_manifest': False,
                'unapproved_payload_included': False,
                'widens_disclosure': False,
                'copy_entire_container_streams': False,
            },
            'source': {
                'filesize': self._filesize,
                'sector_size': self.sectorsize,
                'mini_sector_size': self.minisectorsize,
                'mini_stream_cutoff': self.minisectorcutoff,
                'first_dir_sector': self.first_dir_sector,
                'first_mini_fat_sector': self.first_mini_fat_sector,
            },
            'summary': {
                'approved_stream_count': len(stream_records),
                'export_stream_count': len(export_streams),
                'shared_unit_count': len(shared_units),
                'withheld_stream_count': len(withheld_streams),
                'gap_count': len(gaps),
                'blocking_gap_count': len(blocking_gaps),
            },
        })
        manifest["requires_authorization"] = manifest["requires_extra_authorization"]
        manifest["shared"] = manifest["shared_units"]
        manifest["withheld"] = manifest["withheld_streams"]
        manifest["stream"] = (stream_records[0] if len(stream_records) == 1 else None)
        manifest["exportable_streams"] = list(export_streams)
        manifest["disclosable_streams"] = list(export_streams)
        manifest["exportable"] = list(export_streams)
        manifest["disclosable"] = list(export_streams)
        manifest["approved"] = list(manifest["approved_streams"])
        for target in manifest["gaps"]:
            if target.get("code") == "shared_allocation_unit":
                target["unapproved_stream"] = target.get("other_path")
                target["underlying_stream"] = target.get("other_path")
                target["requires_additional_authorization"] = target.get(
                    "requires_authorization")
                target["locator_text"] = target.get("location")
                locator = target.get("locator")
                if isinstance(locator, dict):
                    locator.setdefault("sid", target.get("sid"))
                    locator["other_sid"] = target.get("other_sid")
                    locator["path"] = target.get("path")
                    locator["stream_path"] = target.get("path")
                    locator["other_path"] = target.get("other_path")
                    locator["directory_entries"] = target.get(
                        "shared_unit", {}).get("directory_entries", [])
        return manifest

    def forensic_manifest(self, *args, **kwargs):
        """Alias for :meth:`OleFileIO.export_manifest`."""
        return self.export_manifest(*args, **kwargs)

    def pre_export_checklist(self, *args, **kwargs):
        """Alias for :meth:`OleFileIO.export_manifest`."""
        return self.export_manifest(*args, **kwargs)

    def export_checklist(self, *args, **kwargs):
        """Alias for :meth:`OleFileIO.export_manifest`."""
        return self.export_manifest(*args, **kwargs)

    def build_export_manifest(self, *args, **kwargs):
        """Alias for :meth:`OleFileIO.export_manifest`."""
        return self.export_manifest(*args, **kwargs)

    def _write_mini_stream(self, entry, data_to_write):
        if not entry.sect_chain:
            entry.build_sect_chain(self)
        nb_sectors = len(entry.sect_chain)

        if not self.root.sect_chain:
            self.root.build_sect_chain(self)
        block_size = self.sector_size // self.mini_sector_size
        for idx, sect in enumerate(entry.sect_chain):
            sect_base = sect // block_size
            sect_offset = sect % block_size
            fp_pos = (self.root.sect_chain[sect_base] + 1)*self.sector_size + sect_offset*self.mini_sector_size
            if idx < (nb_sectors - 1):
                data_per_sector = data_to_write[idx * self.mini_sector_size: (idx + 1) * self.mini_sector_size]
            else:
                data_per_sector = data_to_write[idx * self.mini_sector_size:]
            self._write_mini_sect(fp_pos, data_per_sector)

    def write_stream(self, stream_name, data):
        """
        Write a stream to disk. For now, it is only possible to replace an
        existing stream by data of the same size.

        :param stream_name: path of stream in storage tree (except root entry), either:

            - a string using Unix path syntax, for example:
              'storage_1/storage_1.2/stream'
            - or a list of storage filenames, path to the desired stream/storage.
              Example: ['storage_1', 'storage_1.2', 'stream']

        :param data: bytes, data to be written, must be the same size as the original
            stream.
        """
        if not isinstance(data, bytes):
            raise TypeError("write_stream: data must be a bytes string")
        sid = self._find(stream_name)
        entry = self.direntries[sid]
        if entry.entry_type != STGTY_STREAM:
            raise IOError("this is not a stream")
        size = entry.size
        if size != len(data):
            raise ValueError("write_stream: data must be the same size as the existing stream")
        if size < self.minisectorcutoff and entry.entry_type != STGTY_ROOT:
            return self._write_mini_stream(entry = entry, data_to_write = data)

        sect = entry.isectStart
        # number of sectors to write
        nb_sectors = (size + (self.sectorsize-1)) // self.sectorsize
        log.debug('nb_sectors = %d' % nb_sectors)
        for i in range(nb_sectors):
            # try:
            #     self.fp.seek(offset + self.sectorsize * sect)
            # except Exception:
            #     log.debug('sect=%d, seek=%d' %
            #         (sect, offset+self.sectorsize*sect))
            #     raise IOError('OLE sector index out of range')
            # extract one sector from data, the last one being smaller:
            if i<(nb_sectors-1):
                data_sector = data [i*self.sectorsize : (i+1)*self.sectorsize]
                # TODO: comment this if it works
                assert(len(data_sector)==self.sectorsize)
            else:
                data_sector = data [i*self.sectorsize:]
                # TODO: comment this if it works
                log.debug('write_stream: size=%d sectorsize=%d data_sector=%Xh size%%sectorsize=%d'
                    % (size, self.sectorsize, len(data_sector), size % self.sectorsize))
                assert(len(data_sector) % self.sectorsize==size % self.sectorsize)
            self.write_sect(sect, data_sector)
            # self.fp.write(data_sector)
            # jump to next sector in the FAT:
            try:
                sect = self.fat[sect]
            except IndexError:
                # [PL] if pointer is out of the FAT an exception is raised
                raise IOError('incorrect OLE FAT, sector index out of range')
        # [PL] Last sector should be a "end of chain" marker:
        if sect != ENDOFCHAIN:
            raise IOError('incorrect last sector index in OLE stream')

    def get_type(self, filename):
        """
        Test if given filename exists as a stream or a storage in the OLE
        container, and return its type.

        :param filename: path of stream in storage tree. (see openstream for syntax)
        :returns: False if object does not exist, its entry type (>0) otherwise:

            - STGTY_STREAM: a stream
            - STGTY_STORAGE: a storage
            - STGTY_ROOT: the root entry
        """
        try:
            sid = self._find(filename)
            entry = self.direntries[sid]
            return entry.entry_type
        except Exception:
            return False

    def getclsid(self, filename):
        """
        Return clsid of a stream/storage.

        :param filename: path of stream/storage in storage tree. (see openstream for
            syntax)
        :returns: Empty string if clsid is null, a printable representation of the clsid otherwise

        new in version 0.44
        """
        sid = self._find(filename)
        entry = self.direntries[sid]
        return entry.clsid

    def getmtime(self, filename):
        """
        Return modification time of a stream/storage.

        :param filename: path of stream/storage in storage tree. (see openstream for
            syntax)
        :returns: None if modification time is null, a python datetime object
            otherwise (UTC timezone)

        new in version 0.26
        """
        sid = self._find(filename)
        entry = self.direntries[sid]
        return entry.getmtime()

    def getctime(self, filename):
        """
        Return creation time of a stream/storage.

        :param filename: path of stream/storage in storage tree. (see openstream for
            syntax)
        :returns: None if creation time is null, a python datetime object
            otherwise (UTC timezone)

        new in version 0.26
        """
        sid = self._find(filename)
        entry = self.direntries[sid]
        return entry.getctime()

    def exists(self, filename):
        """
        Test if given filename exists as a stream or a storage in the OLE
        container.
        Note: filename is case-insensitive.

        :param filename: path of stream in storage tree. (see openstream for syntax)
        :returns: True if object exist, else False.
        """
        try:
            sid = self._find(filename)
            return True
        except Exception:
            return False

    def get_size(self, filename):
        """
        Return size of a stream in the OLE container, in bytes.

        :param filename: path of stream in storage tree (see openstream for syntax)
        :returns: size in bytes (long integer)
        :exception IOError: if file not found
        :exception TypeError: if this is not a stream.
        """
        sid = self._find(filename)
        entry = self.direntries[sid]
        if entry.entry_type != STGTY_STREAM:
            # TODO: Should it return zero instead of raising an exception ?
            raise TypeError('object is not an OLE stream')
        return entry.size

    def get_rootentry_name(self):
        """
        Return root entry name. Should usually be 'Root Entry' or 'R' in most
        implementations.
        """
        return self.root.name

    def getproperties(self, filename, convert_time=False, no_conversion=None):
        """
        Return properties described in substream.

        :param filename: path of stream in storage tree (see openstream for syntax)
        :param convert_time: bool, if True timestamps will be converted to Python datetime
        :param no_conversion: None or list of int, timestamps not to be converted
            (for example total editing time is not a real timestamp)

        :returns: a dictionary of values indexed by id (integer)
        """
        #REFERENCE: [MS-OLEPS] https://msdn.microsoft.com/en-us/library/dd942421.aspx
        # make sure no_conversion is a list, just to simplify code below:
        if no_conversion == None:
            no_conversion = []
        # stream path as a string to report exceptions:
        streampath = filename
        if not isinstance(streampath, str):
            streampath = '/'.join(streampath)
        fp = self.openstream(filename)
        data = {}
        try:
            # header
            s = fp.read(28)
            clsid = _clsid(s[8:24])
            # format id
            s = fp.read(20)
            fmtid = _clsid(s[:16])
            fp.seek(i32(s, 16))
            # get section
            s = b"****" + fp.read(i32(fp.read(4))-4)
            # number of properties:
            num_props = i32(s, 4)
        except BaseException as exc:
            # catch exception while parsing property header, and only raise
            # a DEFECT_INCORRECT then return an empty dict, because this is not
            # a fatal error when parsing the whole file
            msg = 'Error while parsing properties header in stream {}: {}'.format(
                repr(streampath), exc)
            self._raise_defect(DEFECT_INCORRECT, msg, type(exc))
            return data
        # clamp num_props based on the data length
        num_props = min(num_props, int(len(s) / 8))
        for i in iterrange(num_props):
            property_id = 0 # just in case of an exception
            try:
                property_id = i32(s, 8+i*8)
                offset = i32(s, 12+i*8)
                property_type = i32(s, offset)

                vt_name = VT.get(property_type, 'UNKNOWN')
                log.debug('property id=%d: type=%d/%s offset=%X' % (property_id, property_type, vt_name, offset))

                value = self._parse_property(s, offset+4, property_id, property_type, convert_time, no_conversion)
                data[property_id] = value
            except BaseException as exc:
                # catch exception while parsing each property, and only raise
                # a DEFECT_INCORRECT, because parsing can go on
                msg = 'Error while parsing property id %d in stream %s: %s' % (
                    property_id, repr(streampath), exc)
                self._raise_defect(DEFECT_INCORRECT, msg, type(exc))

        return data

    def _parse_property(self, s, offset, property_id, property_type, convert_time, no_conversion):
        v = None
        if property_type <= VT_BLOB or property_type in (VT_CLSID, VT_CF):
            v, _ = self._parse_property_basic(s, offset, property_id, property_type, convert_time, no_conversion)
        elif property_type == VT_VECTOR | VT_VARIANT:
            log.debug('property_type == VT_VECTOR | VT_VARIANT')
            off = 4
            count = i32(s, offset)
            values = []
            for _ in range(count):
                property_type = i32(s, offset + off)
                v, sz  = self._parse_property_basic(s, offset + off + 4, property_id, property_type, convert_time, no_conversion)
                values.append(v)
                off += sz + 4
            v = values

        elif property_type & VT_VECTOR:
            property_type_base = property_type & ~VT_VECTOR
            log.debug('property_type == VT_VECTOR | %s' % VT.get(property_type_base, 'UNKNOWN'))
            off = 4
            count = i32(s, offset)
            values = []
            for _ in range(count):
                v, sz = self._parse_property_basic(s, offset + off, property_id, property_type & ~VT_VECTOR, convert_time, no_conversion)
                values.append(v)
                off += sz
            v = values
        else:
            log.debug('property id=%d: type=%d not implemented in parser yet' % (property_id, property_type))
        return v

    def _parse_property_basic(self, s, offset, property_id, property_type, convert_time, no_conversion):
            value = None
            size = 0
            # test for common types first (should perhaps use
            # a dictionary instead?)

            if property_type == VT_I2: # 16-bit signed integer
                value = i16(s, offset)
                if value >= 32768:
                    value = value - 65536
                size = 2
            elif property_type == VT_UI2: # 2-byte unsigned integer
                value = i16(s, offset)
                size = 2
            elif property_type in (VT_I4, VT_INT, VT_ERROR):
                # VT_I4: 32-bit signed integer
                # VT_ERROR: HRESULT, similar to 32-bit signed integer,
                # see https://msdn.microsoft.com/en-us/library/cc230330.aspx
                value = i32(s, offset)
                size = 4
            elif property_type in (VT_UI4, VT_UINT): # 4-byte unsigned integer
                value = i32(s, offset) # FIXME
                size = 4
            elif property_type in (VT_BSTR, VT_LPSTR):
                # CodePageString, see https://msdn.microsoft.com/en-us/library/dd942354.aspx
                # size is a 32 bits integer, including the null terminator, and
                # possibly trailing or embedded null chars
                #TODO: if codepage is unicode, the string should be converted as such
                count = i32(s, offset)
                value = s[offset+4:offset+4+count-1]
                # remove all null chars:
                value = value.replace(b'\x00', b'')
                size = 4 + count
            elif property_type == VT_BLOB:
                # binary large object (BLOB)
                # see https://msdn.microsoft.com/en-us/library/dd942282.aspx
                count = i32(s, offset)
                value = s[offset+4:offset+4+count]
                size = 4 + count
            elif property_type == VT_LPWSTR:
                # UnicodeString
                # see https://msdn.microsoft.com/en-us/library/dd942313.aspx
                # "the string should NOT contain embedded or additional trailing
                # null characters."
                count = i32(s, offset+4)
                value = self._decode_utf16_str(s[offset+4:offset+4+count*2])
                size = 4 + count * 2
            elif property_type == VT_FILETIME:
                value = long(i32(s, offset)) + (long(i32(s, offset+4))<<32)
                # FILETIME is a 64-bit int: "number of 100ns periods
                # since Jan 1,1601".
                if convert_time and property_id not in no_conversion:
                    log.debug('Converting property #%d to python datetime, value=%d=%fs'
                            %(property_id, value, float(value)/10000000))
                    # convert FILETIME to Python datetime.datetime
                    # inspired from https://code.activestate.com/recipes/511425-filetime-to-datetime/
                    _FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)
                    log.debug('timedelta days=%d' % (value//(10*1000000*3600*24)))
                    value = _FILETIME_null_date + datetime.timedelta(microseconds=value//10)
                else:
                    # legacy code kept for backward compatibility: returns a
                    # number of seconds since Jan 1,1601
                    value = value // 10000000 # seconds
                size = 8
            elif property_type == VT_UI1: # 1-byte unsigned integer
                value = i8(s[offset])
                size = 1
            elif property_type == VT_CLSID:
                value = _clsid(s[offset:offset+16])
                size = 16
            elif property_type == VT_CF:
                # PropertyIdentifier or ClipboardData??
                # see https://msdn.microsoft.com/en-us/library/dd941945.aspx
                count = i32(s, offset)
                value = s[offset+4:offset+4+count]
                size = 4 + count
            elif property_type == VT_BOOL:
                # VARIANT_BOOL, 16 bits bool, 0x0000=Fals, 0xFFFF=True
                # see https://msdn.microsoft.com/en-us/library/cc237864.aspx
                value = bool(i16(s, offset))
                size = 2
            else:
                value = None # everything else yields "None"
                log.debug('property id=%d: type=%d not implemented in parser yet' % (property_id, property_type))

                # missing: VT_EMPTY, VT_NULL, VT_R4, VT_R8, VT_CY, VT_DATE,
                # VT_DECIMAL, VT_I1, VT_I8, VT_UI8,
                # see https://msdn.microsoft.com/en-us/library/dd942033.aspx

                #print("%08x" % property_id, repr(value), end=" ")
                #print("(%s)" % VT[i32(s, offset) & 0xFFF])
            return value, size


    def get_metadata(self):
        """
        Parse standard properties streams, return an OleMetadata object
        containing all the available metadata.
        (also stored in the metadata attribute of the OleFileIO object)

        new in version 0.25
        """
        self.metadata = OleMetadata()
        self.metadata.parse_properties(self)
        return self.metadata

    def get_userdefined_properties(self, filename, convert_time=False, no_conversion=None):
        """
        Return properties described in substream.

        :param filename: path of stream in storage tree (see openstream for syntax)
        :param convert_time: bool, if True timestamps will be converted to Python datetime
        :param no_conversion: None or list of int, timestamps not to be converted
            (for example total editing time is not a real timestamp)

        :returns: a dictionary of values indexed by id (integer)
        """
        # REFERENCE: [MS-OLEPS] https://msdn.microsoft.com/en-us/library/dd942421.aspx
        # REFERENCE: https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/2ea8be67-a4a0-4e2e-b42f-49a182645562
        #'D5CDD502-2E9C-101B-9397-08002B2CF9AE'
        # TODO: testing the code more rigorously
        # TODO: adding exception handeling
        FMTID_USERDEFINED_PROPERTIES = _clsid(b'\x05\xD5\xCD\xD5\x9C\x2E\x1B\x10\x93\x97\x08\x00\x2B\x2C\xF9\xAE')

        # make sure no_conversion is a list, just to simplify code below:
        if no_conversion == None:
            no_conversion = []
        # stream path as a string to report exceptions:
        streampath = filename
        if not isinstance(streampath, str):
            streampath = '/'.join(streampath)

        fp = self.openstream(filename)

        data = []

        # header
        s = fp.read(28)
        clsid = _clsid(s[8:24])

        # PropertySetStream.cSections (4 bytes starts at 1c): number of property sets in this stream
        sections_count = i32(s, 24)

        section_file_pointers = []

        try:
            for i in range(sections_count):
                # format id
                s = fp.read(20)
                fmtid = _clsid(s[:16])

                if fmtid == FMTID_USERDEFINED_PROPERTIES:
                    file_pointer = i32(s, 16)
                    fp.seek(file_pointer)
                    # read saved sections
                    s = b"****" + fp.read(i32(fp.read(4)) - 4)
                    # number of properties:
                    num_props = i32(s, 4)

                    PropertyIdentifierAndOffset = s[8: 8+8*num_props]

                    # property names (dictionary)
                    # ref: https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-OLEPS/99127b7f-c440-4697-91a4-c853086d6b33
                    index = 8+8*num_props
                    entry_count = i32(s[index: index+4])
                    index += 4
                    for i in range(entry_count):
                        identifier = s[index: index +4]
                        str_size = i32(s[index+4: index + 8])
                        string = s[index+8: index+8+str_size].decode('utf_8').strip('\0')
                        data.append({'property_name':string, 'value':None})
                        index = index+8+str_size
                    # clamp num_props based on the data length
                    num_props = min(num_props, int(len(s) / 8))

                    # property values
                    # ref: https://docs.microsoft.com/en-us/openspecs/windows_protocols/MS-OLEPS/f122b9d7-e5cf-4484-8466-83f6fd94b3cc
                    for i in iterrange(2, num_props):
                        property_id = 0  # just in case of an exception
                        try:
                            property_id = i32(s, 8 + i * 8)
                            offset = i32(s, 12 + i * 8)
                            property_type = i32(s, offset)

                            vt_name = VT.get(property_type, 'UNKNOWN')
                            log.debug('property id=%d: type=%d/%s offset=%X' % (property_id, property_type, vt_name, offset))

                            # test for common types first (should perhaps use
                            # a dictionary instead?)

                            if property_type == VT_I2:  # 16-bit signed integer
                                value = i16(s, offset + 4)
                                if value >= 32768:
                                    value = value - 65536
                            elif property_type == 1:
                                # supposed to be VT_NULL but seems it is not NULL
                                str_size = i32(s, offset + 8)
                                value = s[offset + 12:offset + 12 + str_size - 1]

                            elif property_type == VT_UI2:  # 2-byte unsigned integer
                                value = i16(s, offset + 4)
                            elif property_type in (VT_I4, VT_INT, VT_ERROR):
                                # VT_I4: 32-bit signed integer
                                # VT_ERROR: HRESULT, similar to 32-bit signed integer,
                                # see https://msdn.microsoft.com/en-us/library/cc230330.aspx
                                value = i32(s, offset + 4)
                            elif property_type in (VT_UI4, VT_UINT):  # 4-byte unsigned integer
                                value = i32(s, offset + 4)  # FIXME
                            elif property_type in (VT_BSTR, VT_LPSTR):
                                # CodePageString, see https://msdn.microsoft.com/en-us/library/dd942354.aspx
                                # size is a 32 bits integer, including the null terminator, and
                                # possibly trailing or embedded null chars
                                # TODO: if codepage is unicode, the string should be converted as such
                                count = i32(s, offset + 4)
                                value = s[offset + 8:offset + 8 + count - 1]
                                # remove all null chars:
                                value = value.replace(b'\x00', b'')
                            elif property_type == VT_BLOB:
                                # binary large object (BLOB)
                                # see https://msdn.microsoft.com/en-us/library/dd942282.aspx
                                count = i32(s, offset + 4)
                                value = s[offset + 8:offset + 8 + count]
                            elif property_type == VT_LPWSTR:
                                # UnicodeString
                                # see https://msdn.microsoft.com/en-us/library/dd942313.aspx
                                # "the string should NOT contain embedded or additional trailing
                                # null characters."
                                count = i32(s, offset + 4)
                                value = self._decode_utf16_str(s[offset + 8:offset + 8 + count * 2])
                            elif property_type == VT_FILETIME:
                                value = long(i32(s, offset + 4)) + (long(i32(s, offset + 8)) << 32)
                                # FILETIME is a 64-bit int: "number of 100ns periods
                                # since Jan 1,1601".
                                if convert_time and property_id not in no_conversion:
                                    log.debug('Converting property #%d to python datetime, value=%d=%fs'
                                              % (property_id, value, float(value) / 10000000))
                                    # convert FILETIME to Python datetime.datetime
                                    # inspired from https://code.activestate.com/recipes/511425-filetime-to-datetime/
                                    _FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)
                                    log.debug('timedelta days=%d' % (value // (10 * 1000000 * 3600 * 24)))
                                    value = _FILETIME_null_date + datetime.timedelta(microseconds=value // 10)
                                else:
                                    # legacy code kept for backward compatibility: returns a
                                    # number of seconds since Jan 1,1601
                                    value = value // 10000000  # seconds
                            elif property_type == VT_UI1:  # 1-byte unsigned integer
                                value = i8(s[offset + 4])
                            elif property_type == VT_CLSID:
                                value = _clsid(s[offset + 4:offset + 20])
                            elif property_type == VT_CF:
                                # PropertyIdentifier or ClipboardData??
                                # see https://msdn.microsoft.com/en-us/library/dd941945.aspx
                                count = i32(s, offset + 4)
                                value = s[offset + 8:offset + 8 + count]
                            elif property_type == VT_BOOL:
                                # VARIANT_BOOL, 16 bits bool, 0x0000=Fals, 0xFFFF=True
                                # see https://msdn.microsoft.com/en-us/library/cc237864.aspx
                                value = bool(i16(s, offset + 4))
                            else:
                                value = None  # everything else yields "None"
                                log.debug(
                                    'property id=%d: type=%d not implemented in parser yet' % (property_id, property_type))

                            # missing: VT_EMPTY, VT_NULL, VT_R4, VT_R8, VT_CY, VT_DATE,
                            # VT_DECIMAL, VT_I1, VT_I8, VT_UI8,
                            # see https://msdn.microsoft.com/en-us/library/dd942033.aspx

                            # FIXME: add support for VT_VECTOR
                            # VT_VECTOR is a 32 uint giving the number of items, followed by
                            # the items in sequence. The VT_VECTOR value is combined with the
                            # type of items, e.g. VT_VECTOR|VT_BSTR
                            # see https://msdn.microsoft.com/en-us/library/dd942011.aspx

                            # print("%08x" % property_id, repr(value), end=" ")
                            # print("(%s)" % VT[i32(s, offset) & 0xFFF])

                            data[i-2]['value']=value
                        except BaseException as exc:
                            # catch exception while parsing each property, and only raise
                            # a DEFECT_INCORRECT, because parsing can go on
                            msg = 'Error while parsing property id %d in stream %s: %s' % (
                                property_id, repr(streampath), exc)
                            self._raise_defect(DEFECT_INCORRECT, msg, type(exc))

        except BaseException as exc:
            # catch exception while parsing property header, and only raise
            # a DEFECT_INCORRECT then return an empty dict, because this is not
            # a fatal error when parsing the whole file
            msg = 'Error while parsing properties header in stream %s: %s' % (
                repr(streampath), exc)
            self._raise_defect(DEFECT_INCORRECT, msg, type(exc))
            return data

        return data


# --------------------------------------------------------------------
# Public helpers for the pre-export forensic manifest

def build_export_manifest(ole, approved_streams=None, **kwargs):
    """
    Build a pre-export forensic manifest for an already-opened OleFileIO.

    This is a convenience wrapper around :meth:`OleFileIO.export_manifest`.
    No stream payload bytes are read, and ``export_streams`` contains only
    explicitly approved streams.
    """
    if isinstance(ole, OleFileIO):
        return ole.export_manifest(approved_streams, **kwargs)
    opened = OleFileIO(ole)
    try:
        return opened.export_manifest(approved_streams, **kwargs)
    finally:
        opened.close()


def forensic_manifest(ole, approved_streams=None, **kwargs):
    """Alias for :func:`build_export_manifest`."""
    return build_export_manifest(ole, approved_streams, **kwargs)


# Additional method aliases.  They all point to the same explicit-approval
# implementation; none of them changes the disclosure scope.
OleFileIO.pre_export_manifest = OleFileIO.export_manifest
OleFileIO.forensic_export_manifest = OleFileIO.export_manifest
OleFileIO.forensic_checklist = OleFileIO.export_manifest
OleFileIO.disclosure_manifest = OleFileIO.export_manifest
OleFileIO.export_preflight = OleFileIO.export_manifest
OleFileIO.build_export_checklist = OleFileIO.export_manifest
OleFileIO.forensic_export_checklist = OleFileIO.export_manifest
OleFileIO.disclosure_checklist = OleFileIO.export_manifest
OleFileIO.manifest = OleFileIO.export_manifest


# Module-level aliases for callers that do not use the OleFileIO method.
export_manifest = build_export_manifest
forensic_checklist = build_export_manifest
build_export_checklist = build_export_manifest
pre_export_checklist = build_export_manifest
forensic_export_manifest = build_export_manifest


# Convenience helpers on the manifest result object.
OleExportManifest.to_dict = lambda self: dict(self)
OleExportManifest.as_dict = OleExportManifest.to_dict


# --------------------------------------------------------------------
# This script can be used to dump the directory of any OLE2 structured
# storage file.

def main():
    """
    Main function when olefile is runs as a script from the command line.
    This will open an OLE2 file and display its structure and properties
    :return: nothing
    """
    import sys, optparse

    DEFAULT_LOG_LEVEL = "warning" # Default log level
    LOG_LEVELS = {
        'debug':    logging.DEBUG,
        'info':     logging.INFO,
        'warning':  logging.WARNING,
        'error':    logging.ERROR,
        'critical': logging.CRITICAL
        }

    usage = 'usage: %prog [options] <filename> [filename2 ...]'
    parser = optparse.OptionParser(usage=usage)

    parser.add_option("-c", action="store_true", dest="check_streams",
        help='check all streams (for debugging purposes)')
    parser.add_option("-p", action="store_true", dest="extract_customprop",
                      help='extract all user-defined propertires')
    parser.add_option("-d", action="store_true", dest="debug_mode",
        help='debug mode, shortcut for -l debug (displays a lot of debug information, for developers only)')
    parser.add_option('-l', '--loglevel', dest="loglevel", action="store", default=DEFAULT_LOG_LEVEL,
                            help="logging level debug/info/warning/error/critical (default=%default)")

    (options, args) = parser.parse_args()

    print('olefile version {} {} - https://www.decalage.info/en/olefile\n'.format(__version__, __date__))

    # Print help if no arguments are passed
    if len(args) == 0:
        print(__doc__)
        parser.print_help()
        sys.exit()

    if options.debug_mode:
        options.loglevel = 'debug'

    # setup logging to the console
    logging.basicConfig(level=LOG_LEVELS[options.loglevel], format='%(levelname)-8s %(message)s')

    # also enable the module's logger:
    enable_logging()

    for filename in args:
        try:
            ole = OleFileIO(filename)#, raise_defects=DEFECT_INCORRECT)
            print("-" * 68)
            print(filename)
            print("-" * 68)
            ole.dumpdirectory()
            for streamname in ole.listdir():
                if streamname[-1][0] == "\005":
                    print("%r: properties" % streamname)
                    try:
                        props = ole.getproperties(streamname, convert_time=True)
                        props = sorted(props.items())
                        for k, v in props:
                            # [PL]: avoid to display too large or binary values:
                            if isinstance(v, (basestring, bytes)):
                                if len(v) > 50:
                                    v = v[:50]
                            if isinstance(v, bytes):
                                # quick and dirty binary check:
                                for c in (1,2,3,4,5,6,7,11,12,14,15,16,17,18,19,20,
                                          21,22,23,24,25,26,27,28,29,30,31):
                                    if c in bytearray(v):
                                        v = '(binary data)'
                                        break
                            print("   ", k, v)
                    except Exception:
                        log.exception('Error while parsing property stream %r' % streamname)

                    try:
                        if options.extract_customprop:
                            variables = ole.get_userdefined_properties(streamname, convert_time=True)
                            if len(variables):
                                print("%r: user-defined properties" % streamname)
                                for index, variable in enumerate(variables):
                                    print('\t{} {}: {}'.format(index, variable['property_name'],variable['value']))

                    except:
                        log.exception('Error while parsing user-defined property stream %r' % streamname)


            if options.check_streams:
                # Read all streams to check if there are errors:
                print('\nChecking streams...')
                for streamname in ole.listdir():
                    # print name using repr() to convert binary chars to \xNN:
                    print('-', repr('/'.join(streamname)),'-', end=' ')
                    st_type = ole.get_type(streamname)
                    if st_type == STGTY_STREAM:
                        print('size %d' % ole.get_size(streamname))
                        # just try to read stream in memory:
                        ole.openstream(streamname)
                    else:
                        print('NOT a stream : type=%d' % st_type)
                print()

            # for streamname in ole.listdir():
            #     # print name using repr() to convert binary chars to \xNN:
            #     print('-', repr('/'.join(streamname)),'-', end=' ')
            #     print(ole.getmtime(streamname))
            # print()

            print('Modification/Creation times of all directory entries:')
            for entry in ole.direntries:
                if entry is not None:
                    print('- {}: mtime={} ctime={}'.format(entry.name,
                        entry.getmtime(), entry.getctime()))
            print()

            # parse and display metadata:
            try:
                meta = ole.get_metadata()
                meta.dump()
            except Exception:
                log.exception('Error while parsing metadata')
            print()
            # [PL] Test a few new methods:
            root = ole.get_rootentry_name()
            print('Root entry name: "%s"' % root)
            if ole.exists('worddocument'):
                print("This is a Word document.")
                print("type of stream 'WordDocument':", ole.get_type('worddocument'))
                print("size :", ole.get_size('worddocument'))
                if ole.exists('macros/vba'):
                    print("This document may contain VBA macros.")

            # print parsing issues:
            print('\nNon-fatal issues raised during parsing:')
            if ole.parsing_issues:
                for exctype, msg in ole.parsing_issues:
                    print('- {}: {}'.format(exctype.__name__, msg))
            else:
                print('None')
            ole.close()
        except Exception:
            log.exception('Error while parsing file %r' % filename)


if __name__ == "__main__":
    main()

# this code was developed while listening to The Wedding Present "Sea Monsters"
