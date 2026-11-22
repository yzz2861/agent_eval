"""
pypdf is a free and open-source pure-python PDF library capable of splitting,
merging, cropping, and transforming the pages of PDF files. It can also add
custom data, viewing options, and passwords to PDF files. pypdf can retrieve
text and metadata from PDFs as well.

You can read the full docs at https://pypdf.readthedocs.io/.
"""

from ._configuration import Configuration, apply_configuration, get_configuration, overwrite_configuration
from ._crypt_providers import crypt_provider
from ._doc_common import DocumentInformation
from ._encryption import PasswordType
from ._page import PageObject, Transformation
from ._reader import PdfReader
from ._text_extraction import mult
from ._version import __version__
from ._writer import ObjectDeletionFlag, PdfWriter
from .constants import ImageType
from .navigation import (
    DuplicateNameGroup,
    NamedDestinationEntry,
    NavigationChain,
    NavigationFinding,
    NavigationForensics,
    NavigationHop,
    NavigationReport,
    Source,
    analyze_navigation,
    audit_navigation,
    collect_navigation_evidence,
    inspect_navigation,
    navigation_forensics,
)
from .pagerange import PageRange, parse_filename_page_ranges
from .papersizes import PaperSize

try:
    import PIL

    pil_version = PIL.__version__
except ImportError:
    pil_version = "none"

_debug_versions = (
    f"pypdf=={__version__}, {crypt_provider=}, PIL={pil_version}"
)

__all__ = [
    "Configuration",
    "DocumentInformation",
    "DuplicateNameGroup",
    "ImageType",
    "NamedDestinationEntry",
    "NavigationChain",
    "NavigationFinding",
    "NavigationForensics",
    "NavigationHop",
    "NavigationReport",
    "ObjectDeletionFlag",
    "PageObject",
    "PageRange",
    "PaperSize",
    "PasswordType",
    "PdfReader",
    "PdfWriter",
    "Source",
    "Transformation",
    "__version__",
    "_debug_versions",
    "analyze_navigation",
    "apply_configuration",
    "audit_navigation",
    "collect_navigation_evidence",
    "get_configuration",
    "inspect_navigation",
    "mult",
    "navigation_forensics",
    "overwrite_configuration",
    "parse_filename_page_ranges",
]
