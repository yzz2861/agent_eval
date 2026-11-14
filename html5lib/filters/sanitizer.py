"""Deprecated from html5lib 1.1.

See `here <https://github.com/html5lib/html5lib-python/issues/443>`_ for
information about its deprecation; `Bleach <https://github.com/mozilla/bleach>`_
is recommended as a replacement. Please let us know in the aforementioned issue
if Bleach is unsuitable for your needs.

"""
from __future__ import absolute_import, division, unicode_literals

import re
import warnings
from xml.sax.saxutils import escape, unescape

from six import text_type
from six.moves import urllib_parse as urlparse

from . import base
from ..constants import namespaces, prefixes

__all__ = ["Filter", "TreeSanitizer", "Diagnostic", "sanitize_tree",
           "executable_elements"]


_deprecation_msg = (
    "html5lib's sanitizer is deprecated; see " +
    "https://github.com/html5lib/html5lib-python/issues/443 and please let " +
    "us know if Bleach is unsuitable for your needs"
)

warnings.warn(_deprecation_msg, DeprecationWarning)

allowed_elements = frozenset((
    (namespaces['html'], 'a'),
    (namespaces['html'], 'abbr'),
    (namespaces['html'], 'acronym'),
    (namespaces['html'], 'address'),
    (namespaces['html'], 'area'),
    (namespaces['html'], 'article'),
    (namespaces['html'], 'aside'),
    (namespaces['html'], 'audio'),
    (namespaces['html'], 'b'),
    (namespaces['html'], 'big'),
    (namespaces['html'], 'blockquote'),
    (namespaces['html'], 'br'),
    (namespaces['html'], 'button'),
    (namespaces['html'], 'canvas'),
    (namespaces['html'], 'caption'),
    (namespaces['html'], 'center'),
    (namespaces['html'], 'cite'),
    (namespaces['html'], 'code'),
    (namespaces['html'], 'col'),
    (namespaces['html'], 'colgroup'),
    (namespaces['html'], 'command'),
    (namespaces['html'], 'datagrid'),
    (namespaces['html'], 'datalist'),
    (namespaces['html'], 'dd'),
    (namespaces['html'], 'del'),
    (namespaces['html'], 'details'),
    (namespaces['html'], 'dfn'),
    (namespaces['html'], 'dialog'),
    (namespaces['html'], 'dir'),
    (namespaces['html'], 'div'),
    (namespaces['html'], 'dl'),
    (namespaces['html'], 'dt'),
    (namespaces['html'], 'em'),
    (namespaces['html'], 'event-source'),
    (namespaces['html'], 'fieldset'),
    (namespaces['html'], 'figcaption'),
    (namespaces['html'], 'figure'),
    (namespaces['html'], 'footer'),
    (namespaces['html'], 'font'),
    (namespaces['html'], 'form'),
    (namespaces['html'], 'header'),
    (namespaces['html'], 'h1'),
    (namespaces['html'], 'h2'),
    (namespaces['html'], 'h3'),
    (namespaces['html'], 'h4'),
    (namespaces['html'], 'h5'),
    (namespaces['html'], 'h6'),
    (namespaces['html'], 'hr'),
    (namespaces['html'], 'i'),
    (namespaces['html'], 'img'),
    (namespaces['html'], 'input'),
    (namespaces['html'], 'ins'),
    (namespaces['html'], 'keygen'),
    (namespaces['html'], 'kbd'),
    (namespaces['html'], 'label'),
    (namespaces['html'], 'legend'),
    (namespaces['html'], 'li'),
    (namespaces['html'], 'm'),
    (namespaces['html'], 'map'),
    (namespaces['html'], 'menu'),
    (namespaces['html'], 'meter'),
    (namespaces['html'], 'multicol'),
    (namespaces['html'], 'nav'),
    (namespaces['html'], 'nextid'),
    (namespaces['html'], 'ol'),
    (namespaces['html'], 'output'),
    (namespaces['html'], 'optgroup'),
    (namespaces['html'], 'option'),
    (namespaces['html'], 'p'),
    (namespaces['html'], 'pre'),
    (namespaces['html'], 'progress'),
    (namespaces['html'], 'q'),
    (namespaces['html'], 's'),
    (namespaces['html'], 'samp'),
    (namespaces['html'], 'section'),
    (namespaces['html'], 'select'),
    (namespaces['html'], 'small'),
    (namespaces['html'], 'sound'),
    (namespaces['html'], 'source'),
    (namespaces['html'], 'spacer'),
    (namespaces['html'], 'span'),
    (namespaces['html'], 'strike'),
    (namespaces['html'], 'strong'),
    (namespaces['html'], 'sub'),
    (namespaces['html'], 'summary'),
    (namespaces['html'], 'sup'),
    (namespaces['html'], 'table'),
    (namespaces['html'], 'tbody'),
    (namespaces['html'], 'td'),
    (namespaces['html'], 'textarea'),
    (namespaces['html'], 'time'),
    (namespaces['html'], 'tfoot'),
    (namespaces['html'], 'th'),
    (namespaces['html'], 'thead'),
    (namespaces['html'], 'tr'),
    (namespaces['html'], 'tt'),
    (namespaces['html'], 'u'),
    (namespaces['html'], 'ul'),
    (namespaces['html'], 'var'),
    (namespaces['html'], 'video'),
    (namespaces['html'], 'wbr'),
    (namespaces['mathml'], 'maction'),
    (namespaces['mathml'], 'math'),
    (namespaces['mathml'], 'merror'),
    (namespaces['mathml'], 'mfrac'),
    (namespaces['mathml'], 'mi'),
    (namespaces['mathml'], 'mmultiscripts'),
    (namespaces['mathml'], 'mn'),
    (namespaces['mathml'], 'mo'),
    (namespaces['mathml'], 'mover'),
    (namespaces['mathml'], 'mpadded'),
    (namespaces['mathml'], 'mphantom'),
    (namespaces['mathml'], 'mprescripts'),
    (namespaces['mathml'], 'mroot'),
    (namespaces['mathml'], 'mrow'),
    (namespaces['mathml'], 'mspace'),
    (namespaces['mathml'], 'msqrt'),
    (namespaces['mathml'], 'mstyle'),
    (namespaces['mathml'], 'msub'),
    (namespaces['mathml'], 'msubsup'),
    (namespaces['mathml'], 'msup'),
    (namespaces['mathml'], 'mtable'),
    (namespaces['mathml'], 'mtd'),
    (namespaces['mathml'], 'mtext'),
    (namespaces['mathml'], 'mtr'),
    (namespaces['mathml'], 'munder'),
    (namespaces['mathml'], 'munderover'),
    (namespaces['mathml'], 'none'),
    (namespaces['svg'], 'a'),
    (namespaces['svg'], 'animate'),
    (namespaces['svg'], 'animateColor'),
    (namespaces['svg'], 'animateMotion'),
    (namespaces['svg'], 'animateTransform'),
    (namespaces['svg'], 'clipPath'),
    (namespaces['svg'], 'circle'),
    (namespaces['svg'], 'defs'),
    (namespaces['svg'], 'desc'),
    (namespaces['svg'], 'ellipse'),
    (namespaces['svg'], 'font-face'),
    (namespaces['svg'], 'font-face-name'),
    (namespaces['svg'], 'font-face-src'),
    (namespaces['svg'], 'g'),
    (namespaces['svg'], 'glyph'),
    (namespaces['svg'], 'hkern'),
    (namespaces['svg'], 'linearGradient'),
    (namespaces['svg'], 'line'),
    (namespaces['svg'], 'marker'),
    (namespaces['svg'], 'metadata'),
    (namespaces['svg'], 'missing-glyph'),
    (namespaces['svg'], 'mpath'),
    (namespaces['svg'], 'path'),
    (namespaces['svg'], 'polygon'),
    (namespaces['svg'], 'polyline'),
    (namespaces['svg'], 'radialGradient'),
    (namespaces['svg'], 'rect'),
    (namespaces['svg'], 'set'),
    (namespaces['svg'], 'stop'),
    (namespaces['svg'], 'svg'),
    (namespaces['svg'], 'switch'),
    (namespaces['svg'], 'text'),
    (namespaces['svg'], 'title'),
    (namespaces['svg'], 'tspan'),
    (namespaces['svg'], 'use'),
))

allowed_attributes = frozenset((
    # HTML attributes
    (None, 'abbr'),
    (None, 'accept'),
    (None, 'accept-charset'),
    (None, 'accesskey'),
    (None, 'action'),
    (None, 'align'),
    (None, 'alt'),
    (None, 'autocomplete'),
    (None, 'autofocus'),
    (None, 'axis'),
    (None, 'background'),
    (None, 'balance'),
    (None, 'bgcolor'),
    (None, 'bgproperties'),
    (None, 'border'),
    (None, 'bordercolor'),
    (None, 'bordercolordark'),
    (None, 'bordercolorlight'),
    (None, 'bottompadding'),
    (None, 'cellpadding'),
    (None, 'cellspacing'),
    (None, 'ch'),
    (None, 'challenge'),
    (None, 'char'),
    (None, 'charoff'),
    (None, 'choff'),
    (None, 'charset'),
    (None, 'checked'),
    (None, 'cite'),
    (None, 'class'),
    (None, 'clear'),
    (None, 'color'),
    (None, 'cols'),
    (None, 'colspan'),
    (None, 'compact'),
    (None, 'contenteditable'),
    (None, 'controls'),
    (None, 'coords'),
    (None, 'data'),
    (None, 'datafld'),
    (None, 'datapagesize'),
    (None, 'datasrc'),
    (None, 'datetime'),
    (None, 'default'),
    (None, 'delay'),
    (None, 'dir'),
    (None, 'disabled'),
    (None, 'draggable'),
    (None, 'dynsrc'),
    (None, 'enctype'),
    (None, 'end'),
    (None, 'face'),
    (None, 'for'),
    (None, 'form'),
    (None, 'frame'),
    (None, 'galleryimg'),
    (None, 'gutter'),
    (None, 'headers'),
    (None, 'height'),
    (None, 'hidefocus'),
    (None, 'hidden'),
    (None, 'high'),
    (None, 'href'),
    (None, 'hreflang'),
    (None, 'hspace'),
    (None, 'icon'),
    (None, 'id'),
    (None, 'inputmode'),
    (None, 'ismap'),
    (None, 'keytype'),
    (None, 'label'),
    (None, 'leftspacing'),
    (None, 'lang'),
    (None, 'list'),
    (None, 'longdesc'),
    (None, 'loop'),
    (None, 'loopcount'),
    (None, 'loopend'),
    (None, 'loopstart'),
    (None, 'low'),
    (None, 'lowsrc'),
    (None, 'max'),
    (None, 'maxlength'),
    (None, 'media'),
    (None, 'method'),
    (None, 'min'),
    (None, 'multiple'),
    (None, 'name'),
    (None, 'nohref'),
    (None, 'noshade'),
    (None, 'nowrap'),
    (None, 'open'),
    (None, 'optimum'),
    (None, 'pattern'),
    (None, 'ping'),
    (None, 'point-size'),
    (None, 'poster'),
    (None, 'pqg'),
    (None, 'preload'),
    (None, 'prompt'),
    (None, 'radiogroup'),
    (None, 'readonly'),
    (None, 'rel'),
    (None, 'repeat-max'),
    (None, 'repeat-min'),
    (None, 'replace'),
    (None, 'required'),
    (None, 'rev'),
    (None, 'rightspacing'),
    (None, 'rows'),
    (None, 'rowspan'),
    (None, 'rules'),
    (None, 'scope'),
    (None, 'selected'),
    (None, 'shape'),
    (None, 'size'),
    (None, 'span'),
    (None, 'src'),
    (None, 'start'),
    (None, 'step'),
    (None, 'style'),
    (None, 'summary'),
    (None, 'suppress'),
    (None, 'tabindex'),
    (None, 'target'),
    (None, 'template'),
    (None, 'title'),
    (None, 'toppadding'),
    (None, 'type'),
    (None, 'unselectable'),
    (None, 'usemap'),
    (None, 'urn'),
    (None, 'valign'),
    (None, 'value'),
    (None, 'variable'),
    (None, 'volume'),
    (None, 'vspace'),
    (None, 'vrml'),
    (None, 'width'),
    (None, 'wrap'),
    (namespaces['xml'], 'lang'),
    # MathML attributes
    (None, 'actiontype'),
    (None, 'align'),
    (None, 'columnalign'),
    (None, 'columnalign'),
    (None, 'columnalign'),
    (None, 'columnlines'),
    (None, 'columnspacing'),
    (None, 'columnspan'),
    (None, 'depth'),
    (None, 'display'),
    (None, 'displaystyle'),
    (None, 'equalcolumns'),
    (None, 'equalrows'),
    (None, 'fence'),
    (None, 'fontstyle'),
    (None, 'fontweight'),
    (None, 'frame'),
    (None, 'height'),
    (None, 'linethickness'),
    (None, 'lspace'),
    (None, 'mathbackground'),
    (None, 'mathcolor'),
    (None, 'mathvariant'),
    (None, 'mathvariant'),
    (None, 'maxsize'),
    (None, 'minsize'),
    (None, 'other'),
    (None, 'reversed'),
    (None, 'rowalign'),
    (None, 'rowalign'),
    (None, 'rowalign'),
    (None, 'rowlines'),
    (None, 'rowspacing'),
    (None, 'rowspan'),
    (None, 'rspace'),
    (None, 'scriptlevel'),
    (None, 'selection'),
    (None, 'separator'),
    (None, 'start'),
    (None, 'stretchy'),
    (None, 'width'),
    (None, 'width'),
    (namespaces['xlink'], 'href'),
    (namespaces['xlink'], 'show'),
    (namespaces['xlink'], 'type'),
    # SVG attributes
    (None, 'accent-height'),
    (None, 'accumulate'),
    (None, 'additive'),
    (None, 'alphabetic'),
    (None, 'arabic-form'),
    (None, 'ascent'),
    (None, 'attributeName'),
    (None, 'attributeType'),
    (None, 'baseProfile'),
    (None, 'bbox'),
    (None, 'begin'),
    (None, 'by'),
    (None, 'calcMode'),
    (None, 'cap-height'),
    (None, 'class'),
    (None, 'clip-path'),
    (None, 'color'),
    (None, 'color-rendering'),
    (None, 'content'),
    (None, 'cx'),
    (None, 'cy'),
    (None, 'd'),
    (None, 'dx'),
    (None, 'dy'),
    (None, 'descent'),
    (None, 'display'),
    (None, 'dur'),
    (None, 'end'),
    (None, 'fill'),
    (None, 'fill-opacity'),
    (None, 'fill-rule'),
    (None, 'font-family'),
    (None, 'font-size'),
    (None, 'font-stretch'),
    (None, 'font-style'),
    (None, 'font-variant'),
    (None, 'font-weight'),
    (None, 'from'),
    (None, 'fx'),
    (None, 'fy'),
    (None, 'g1'),
    (None, 'g2'),
    (None, 'glyph-name'),
    (None, 'gradientUnits'),
    (None, 'hanging'),
    (None, 'height'),
    (None, 'horiz-adv-x'),
    (None, 'horiz-origin-x'),
    (None, 'id'),
    (None, 'ideographic'),
    (None, 'k'),
    (None, 'keyPoints'),
    (None, 'keySplines'),
    (None, 'keyTimes'),
    (None, 'lang'),
    (None, 'marker-end'),
    (None, 'marker-mid'),
    (None, 'marker-start'),
    (None, 'markerHeight'),
    (None, 'markerUnits'),
    (None, 'markerWidth'),
    (None, 'mathematical'),
    (None, 'max'),
    (None, 'min'),
    (None, 'name'),
    (None, 'offset'),
    (None, 'opacity'),
    (None, 'orient'),
    (None, 'origin'),
    (None, 'overline-position'),
    (None, 'overline-thickness'),
    (None, 'panose-1'),
    (None, 'path'),
    (None, 'pathLength'),
    (None, 'points'),
    (None, 'preserveAspectRatio'),
    (None, 'r'),
    (None, 'refX'),
    (None, 'refY'),
    (None, 'repeatCount'),
    (None, 'repeatDur'),
    (None, 'requiredExtensions'),
    (None, 'requiredFeatures'),
    (None, 'restart'),
    (None, 'rotate'),
    (None, 'rx'),
    (None, 'ry'),
    (None, 'slope'),
    (None, 'stemh'),
    (None, 'stemv'),
    (None, 'stop-color'),
    (None, 'stop-opacity'),
    (None, 'strikethrough-position'),
    (None, 'strikethrough-thickness'),
    (None, 'stroke'),
    (None, 'stroke-dasharray'),
    (None, 'stroke-dashoffset'),
    (None, 'stroke-linecap'),
    (None, 'stroke-linejoin'),
    (None, 'stroke-miterlimit'),
    (None, 'stroke-opacity'),
    (None, 'stroke-width'),
    (None, 'systemLanguage'),
    (None, 'target'),
    (None, 'text-anchor'),
    (None, 'to'),
    (None, 'transform'),
    (None, 'type'),
    (None, 'u1'),
    (None, 'u2'),
    (None, 'underline-position'),
    (None, 'underline-thickness'),
    (None, 'unicode'),
    (None, 'unicode-range'),
    (None, 'units-per-em'),
    (None, 'values'),
    (None, 'version'),
    (None, 'viewBox'),
    (None, 'visibility'),
    (None, 'width'),
    (None, 'widths'),
    (None, 'x'),
    (None, 'x-height'),
    (None, 'x1'),
    (None, 'x2'),
    (namespaces['xlink'], 'actuate'),
    (namespaces['xlink'], 'arcrole'),
    (namespaces['xlink'], 'href'),
    (namespaces['xlink'], 'role'),
    (namespaces['xlink'], 'show'),
    (namespaces['xlink'], 'title'),
    (namespaces['xlink'], 'type'),
    (namespaces['xml'], 'base'),
    (namespaces['xml'], 'lang'),
    (namespaces['xml'], 'space'),
    (None, 'y'),
    (None, 'y1'),
    (None, 'y2'),
    (None, 'zoomAndPan'),
))

attr_val_is_uri = frozenset((
    (None, 'href'),
    (None, 'src'),
    (None, 'cite'),
    (None, 'action'),
    (None, 'longdesc'),
    (None, 'poster'),
    (None, 'background'),
    (None, 'datasrc'),
    (None, 'dynsrc'),
    (None, 'lowsrc'),
    (None, 'ping'),
    (namespaces['xlink'], 'href'),
    (namespaces['xml'], 'base'),
))

svg_attr_val_allows_ref = frozenset((
    (None, 'clip-path'),
    (None, 'color-profile'),
    (None, 'cursor'),
    (None, 'fill'),
    (None, 'filter'),
    (None, 'marker'),
    (None, 'marker-start'),
    (None, 'marker-mid'),
    (None, 'marker-end'),
    (None, 'mask'),
    (None, 'stroke'),
))

svg_allow_local_href = frozenset((
    (None, 'altGlyph'),
    (None, 'animate'),
    (None, 'animateColor'),
    (None, 'animateMotion'),
    (None, 'animateTransform'),
    (None, 'cursor'),
    (None, 'feImage'),
    (None, 'filter'),
    (None, 'linearGradient'),
    (None, 'pattern'),
    (None, 'radialGradient'),
    (None, 'textpath'),
    (None, 'tref'),
    (None, 'set'),
    (None, 'use')
))

allowed_css_properties = frozenset((
    'azimuth',
    'background-color',
    'border-bottom-color',
    'border-collapse',
    'border-color',
    'border-left-color',
    'border-right-color',
    'border-top-color',
    'clear',
    'color',
    'cursor',
    'direction',
    'display',
    'elevation',
    'float',
    'font',
    'font-family',
    'font-size',
    'font-style',
    'font-variant',
    'font-weight',
    'height',
    'letter-spacing',
    'line-height',
    'max-height',
    'min-height',
    'max-width',
    'min-width',
    'overflow',
    'pause',
    'pause-after',
    'pause-before',
    'pitch',
    'pitch-range',
    'richness',
    'speak',
    'speak-header',
    'speak-numeral',
    'speak-punctuation',
    'speech-rate',
    'stress',
    'text-align',
    'text-decoration',
    'text-indent',
    'unicode-bidi',
    'vertical-align',
    'voice-family',
    'volume',
    'white-space',
    'width',
))

allowed_css_keywords = frozenset((
    'auto',
    'aqua',
    'black',
    'block',
    'blue',
    'bold',
    'both',
    'bottom',
    'brown',
    'center',
    'collapse',
    'dashed',
    'dotted',
    'fuchsia',
    'gray',
    'green',
    '!important',
    'italic',
    'left',
    'lime',
    'maroon',
    'medium',
    'none',
    'navy',
    'normal',
    'nowrap',
    'olive',
    'pointer',
    'purple',
    'red',
    'right',
    'solid',
    'silver',
    'teal',
    'top',
    'transparent',
    'underline',
    'white',
    'yellow',
))

allowed_svg_properties = frozenset((
    'fill',
    'fill-opacity',
    'fill-rule',
    'stroke',
    'stroke-width',
    'stroke-linecap',
    'stroke-linejoin',
    'stroke-opacity',
))

allowed_protocols = frozenset((
    'ed2k',
    'ftp',
    'http',
    'https',
    'irc',
    'mailto',
    'news',
    'gopher',
    'nntp',
    'telnet',
    'webcal',
    'xmpp',
    'callto',
    'feed',
    'urn',
    'aim',
    'rsync',
    'tag',
    'ssh',
    'sftp',
    'rtsp',
    'afs',
    'data',
))

allowed_content_types = frozenset((
    'image/png',
    'image/jpeg',
    'image/gif',
    'image/webp',
    'image/bmp',
    'text/plain',
))


#: Elements that are active content: if they end up in an executable
#: context in the final tree they must be removed outright. Escaping them
#: on the token stream is not enough, because the parser may have moved
#: them (foster parenting, head/body relocation, foreign content) to a
#: position the token-level policy never saw.
executable_elements = frozenset((
    (namespaces['html'], 'script'),
    (namespaces['html'], 'style'),
    (namespaces['html'], 'iframe'),
    (namespaces['html'], 'object'),
    (namespaces['html'], 'embed'),
    (namespaces['html'], 'applet'),
    (namespaces['html'], 'base'),
    (namespaces['html'], 'meta'),
    (namespaces['html'], 'link'),
    (namespaces['html'], 'frame'),
    (namespaces['html'], 'frameset'),
    (namespaces['html'], 'noscript'),
    (namespaces['svg'], 'script'),
    (namespaces['svg'], 'style'),
))

#: Elements that establish table scope; content found directly in these
#: (not inside a cell or caption) is subject to foster parenting.
table_scope_elements = frozenset((
    'table',
    'tbody',
    'thead',
    'tfoot',
    'tr',
))

#: Table elements inside which normal flow content (and the normal
#: policy) applies.
table_cell_elements = frozenset((
    'td',
    'th',
    'caption',
))

#: Relocation reasons recorded by the parser that move an existing node.
moved_reasons = frozenset((
    'foster-parented',
    'foster-parented-text',
    'relocated-to-head',
))

#: Relocation reasons recorded by the parser for implicitly created
#: table structure.
inserted_reasons = frozenset((
    'implicit-tbody',
    'implicit-tr',
    'implicit-colgroup',
))

#: Tag names of container roots that are not real elements and should
#: not appear in diagnostic paths.
container_tags = frozenset((
    'DOCUMENT_FRAGMENT',
    'DOCUMENT_ROOT',
))


data_content_type = re.compile(r'''
                                ^
                                # Match a content type <application>/<type>
                                (?P<content_type>[-a-zA-Z0-9.]+/[-a-zA-Z0-9.]+)
                                # Match any character set and encoding
                                (?:(?:;charset=(?:[-a-zA-Z0-9]+)(?:;(?:base64))?)
                                  |(?:;(?:base64))?(?:;charset=(?:[-a-zA-Z0-9]+))?)
                                # Assume the rest is data
                                ,.*
                                $
                                ''',
                               re.VERBOSE)


class Filter(base.Filter):
    """Sanitizes token stream of XHTML+MathML+SVG and of inline style attributes"""
    def __init__(self,
                 source,
                 allowed_elements=allowed_elements,
                 allowed_attributes=allowed_attributes,
                 allowed_css_properties=allowed_css_properties,
                 allowed_css_keywords=allowed_css_keywords,
                 allowed_svg_properties=allowed_svg_properties,
                 allowed_protocols=allowed_protocols,
                 allowed_content_types=allowed_content_types,
                 attr_val_is_uri=attr_val_is_uri,
                 svg_attr_val_allows_ref=svg_attr_val_allows_ref,
                 svg_allow_local_href=svg_allow_local_href):
        """Creates a Filter

        :arg allowed_elements: set of elements to allow--everything else will
            be escaped

        :arg allowed_attributes: set of attributes to allow in
            elements--everything else will be stripped

        :arg allowed_css_properties: set of CSS properties to allow--everything
            else will be stripped

        :arg allowed_css_keywords: set of CSS keywords to allow--everything
            else will be stripped

        :arg allowed_svg_properties: set of SVG properties to allow--everything
            else will be removed

        :arg allowed_protocols: set of allowed protocols for URIs

        :arg allowed_content_types: set of allowed content types for ``data`` URIs.

        :arg attr_val_is_uri: set of attributes that have URI values--values
            that have a scheme not listed in ``allowed_protocols`` are removed

        :arg svg_attr_val_allows_ref: set of SVG attributes that can have
            references

        :arg svg_allow_local_href: set of SVG elements that can have local
            hrefs--these are removed

        """
        super(Filter, self).__init__(source)

        warnings.warn(_deprecation_msg, DeprecationWarning)

        self.allowed_elements = allowed_elements
        self.allowed_attributes = allowed_attributes
        self.allowed_css_properties = allowed_css_properties
        self.allowed_css_keywords = allowed_css_keywords
        self.allowed_svg_properties = allowed_svg_properties
        self.allowed_protocols = allowed_protocols
        self.allowed_content_types = allowed_content_types
        self.attr_val_is_uri = attr_val_is_uri
        self.svg_attr_val_allows_ref = svg_attr_val_allows_ref
        self.svg_allow_local_href = svg_allow_local_href

    def __iter__(self):
        for token in base.Filter.__iter__(self):
            token = self.sanitize_token(token)
            if token:
                yield token

    # Sanitize the +html+, escaping all elements not in ALLOWED_ELEMENTS, and
    # stripping out all attributes not in ALLOWED_ATTRIBUTES. Style attributes
    # are parsed, and a restricted set, specified by ALLOWED_CSS_PROPERTIES and
    # ALLOWED_CSS_KEYWORDS, are allowed through. attributes in ATTR_VAL_IS_URI
    # are scanned, and only URI schemes specified in ALLOWED_PROTOCOLS are
    # allowed.
    #
    #   sanitize_html('<script> do_nasty_stuff() </script>')
    #    => &lt;script> do_nasty_stuff() &lt;/script>
    #   sanitize_html('<a href="javascript: sucker();">Click here for $100</a>')
    #    => <a>Click here for $100</a>
    def sanitize_token(self, token):

        # accommodate filters which use token_type differently
        token_type = token["type"]
        if token_type in ("StartTag", "EndTag", "EmptyTag"):
            name = token["name"]
            namespace = token["namespace"]
            if ((namespace, name) in self.allowed_elements or
                (namespace is None and
                 (namespaces["html"], name) in self.allowed_elements)):
                return self.allowed_token(token)
            else:
                return self.disallowed_token(token)
        elif token_type == "Comment":
            pass
        else:
            return token

    def allowed_token(self, token):
        if "data" in token:
            attrs = token["data"]
            attr_names = set(attrs.keys())

            # Remove forbidden attributes
            for to_remove in (attr_names - self.allowed_attributes):
                del token["data"][to_remove]
                attr_names.remove(to_remove)

            # Remove attributes with disallowed URL values
            for attr in (attr_names & self.attr_val_is_uri):
                assert attr in attrs
                # I don't have a clue where this regexp comes from or why it matches those
                # characters, nor why we call unescape. I just know it's always been here.
                # Should you be worried by this comment in a sanitizer? Yes. On the other hand, all
                # this will do is remove *more* than it otherwise would.
                val_unescaped = re.sub("[`\x00-\x20\x7f-\xa0\\s]+", '',
                                       unescape(attrs[attr])).lower()
                # remove replacement characters from unescaped characters
                val_unescaped = val_unescaped.replace("\ufffd", "")
                try:
                    uri = urlparse.urlparse(val_unescaped)
                except ValueError:
                    uri = None
                    del attrs[attr]
                if uri and uri.scheme:
                    if uri.scheme not in self.allowed_protocols:
                        del attrs[attr]
                    if uri.scheme == 'data':
                        m = data_content_type.match(uri.path)
                        if not m:
                            del attrs[attr]
                        elif m.group('content_type') not in self.allowed_content_types:
                            del attrs[attr]

            for attr in self.svg_attr_val_allows_ref:
                if attr in attrs:
                    attrs[attr] = re.sub(r'url\s*\(\s*[^#\s][^)]+?\)',
                                         ' ',
                                         unescape(attrs[attr]))
            if (token["name"] in self.svg_allow_local_href and
                (namespaces['xlink'], 'href') in attrs and re.search(r'^\s*[^#\s].*',
                                                                     attrs[(namespaces['xlink'], 'href')])):
                del attrs[(namespaces['xlink'], 'href')]
            if (None, 'style') in attrs:
                attrs[(None, 'style')] = self.sanitize_css(attrs[(None, 'style')])
            token["data"] = attrs
        return token

    def disallowed_token(self, token):
        token_type = token["type"]
        if token_type == "EndTag":
            token["data"] = "</%s>" % token["name"]
        elif token["data"]:
            assert token_type in ("StartTag", "EmptyTag")
            attrs = []
            for (ns, name), v in token["data"].items():
                attrs.append(' %s="%s"' % (name if ns is None else "%s:%s" % (prefixes[ns], name), escape(v)))
            token["data"] = "<%s%s>" % (token["name"], ''.join(attrs))
        else:
            token["data"] = "<%s>" % token["name"]
        if token.get("selfClosing"):
            token["data"] = token["data"][:-1] + "/>"

        token["type"] = "Characters"

        del token["name"]
        return token

    def sanitize_css(self, style):
        # disallow urls
        style = re.compile(r'url\s*\(\s*[^\s)]+?\s*\)\s*').sub(' ', style)

        # gauntlet
        if not re.match(r"""^([:,;#%.\sa-zA-Z0-9!]|\w-\w|'[\s\w]+'|"[\s\w]+"|\([\d,\s]+\))*$""", style):
            return ''
        if not re.match(r"^\s*([-\w]+\s*:[^:;]*(;\s*|$))*$", style):
            return ''

        clean = []
        for prop, value in re.findall(r"([-\w]+)\s*:\s*([^:;]*)", style):
            if not value:
                continue
            if prop.lower() in self.allowed_css_properties:
                clean.append(prop + ': ' + value + ';')
            elif prop.split('-')[0].lower() in ['background', 'border', 'margin',
                                                'padding']:
                for keyword in value.split():
                    if keyword not in self.allowed_css_keywords and \
                            not re.match(r"^(#[0-9a-fA-F]+|rgb\(\d+%?,\d*%?,?\d*%?\)?|\d{0,2}\.?\d{0,2}(cm|em|ex|in|mm|pc|pt|px|%|,|\))?)$", keyword):  # noqa
                        break
                else:
                    clean.append(prop + ': ' + value + ';')
            elif prop.lower() in self.allowed_svg_properties:
                clean.append(prop + ': ' + value + ';')

        return ' '.join(clean)


def _split_tag(tag):
    """Split an ElementTree tag into a (namespace, local name) pair."""
    if tag.startswith("{"):
        namespace, _, name = tag[1:].partition("}")
        return namespace, name
    return None, tag


def _unwrap_node(node):
    """Get the underlying DOM/ElementTree node from a treebuilder node."""
    for attribute in ("_element", "element"):
        element = getattr(node, attribute, None)
        if element is not None:
            return element
    return None


class Diagnostic(object):
    """A single, content-free record of a sanitizer or parser action.

    Diagnostics deliberately contain only tag names, namespaces, machine
    readable reasons and structural paths: never text content or
    attribute values, so reporting them cannot leak payload data (e.g.
    the body of a removed script element).
    """

    __slots__ = ("action", "reason", "name", "namespace", "path")

    def __init__(self, action, reason, name, namespace, path):
        self.action = action
        self.reason = reason
        self.name = name
        self.namespace = namespace
        self.path = tuple(path)

    def __repr__(self):
        return ("Diagnostic(action=%r, reason=%r, name=%r, namespace=%r, "
                "path=%r)" % (self.action, self.reason, self.name,
                              self.namespace, self.path))

    def __eq__(self, other):
        if not isinstance(other, Diagnostic):
            return NotImplemented
        return (self.action == other.action and
                self.reason == other.reason and
                self.name == other.name and
                self.namespace == other.namespace and
                self.path == other.path)

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def as_dict(self):
        return {"action": self.action,
                "reason": self.reason,
                "name": self.name,
                "namespace": self.namespace,
                "path": list(self.path)}


class TreeSanitizer(object):
    """Post-parse sanitizer that judges nodes by their final position.

    The token-level Filter runs on the serialization stream and cannot
    see where the parser finally placed a node: foster parenting moves
    content out of tables, tbody/tr elements are created implicitly,
    content is relocated between head and body, and foreign content
    (SVG/MathML) switches namespaces. This pass walks the fully built
    tree and removes active-content elements (see executable_elements)
    that ended up in an executable context, unless the policy explicitly
    allows them.

    Everything else is left in place for the streaming token filter, so
    legitimate table structure and explicitly allowed (scoped) styles
    are preserved.
    """

    def __init__(self,
                 allowed_elements=allowed_elements,
                 executable_elements=executable_elements):
        """Creates a TreeSanitizer

        :arg allowed_elements: elements the policy allows; allowed
            elements are never removed by this pass

        :arg executable_elements: elements considered active content

        """
        self.allowed_elements = allowed_elements
        self.executable_elements = executable_elements

    def sanitize_tree(self, tree, relocations=None):
        """Sanitize a fully parsed ElementTree in place.

        :arg tree: the root Element of a parsed document or fragment

        :arg relocations: optional parser relocation log (a list of
            (reason, node) pairs, see TreeBuilder.relocations) used to
            explain why nodes ended up where they did

        :returns: a list of Diagnostic records describing every removal
            and every parser relocation that affected the tree

        """
        relocated = {}
        if relocations:
            for reason, node in relocations:
                element = _unwrap_node(node)
                if element is not None:
                    relocated.setdefault(id(element), []).append(reason)

        paths = {}
        removals = []
        removed_ids = set()

        # Document-order walk; removals are applied afterwards so the
        # walk itself is not disturbed. Each stack entry is
        # (element, parent, ancestor names, ancestor ids).
        stack = [(tree, None, (), ())]
        while stack:
            element, parent, ancestor_names, ancestor_ids = stack.pop()
            tag = element.tag
            if not isinstance(tag, text_type):
                # Comments and similar non-element nodes carry no tag.
                continue
            namespace, name = _split_tag(tag)
            if namespace is None:
                namespace = namespaces["html"]
            paths[id(element)] = tuple(
                ancestor for ancestor in ancestor_names
                if ancestor not in container_tags)
            child_names = ancestor_names + (name,)
            child_ids = ancestor_ids + (id(element),)
            for child in reversed(list(element)):
                stack.append((child, element, child_names, child_ids))

            # Ancestors are always visited before their descendants, so
            # this also covers nodes inside an already removed subtree.
            gone = any(ancestor_id in removed_ids
                       for ancestor_id in ancestor_ids)

            if (parent is None or gone or
                    (namespace, name) not in self.executable_elements or
                    (namespace, name) in self.allowed_elements):
                continue

            reason = self._removal_reason(element, namespace, name,
                                          ancestor_names, ancestor_ids,
                                          relocated)
            removals.append((element, parent,
                             Diagnostic("removed", reason, name, namespace,
                                        paths[id(element)])))
            removed_ids.add(id(element))

        diagnostics = []
        for element, parent, diagnostic in removals:
            if any(child is element for child in parent):
                self._remove_element(parent, element)
                diagnostics.append(diagnostic)

        if relocations:
            diagnostics.extend(
                self._relocation_diagnostics(relocations, paths, removed_ids))

        return diagnostics

    def _removal_reason(self, element, namespace, name, ancestor_names,
                        ancestor_ids, relocated):
        for node_id in (id(element),) + ancestor_ids:
            node_reasons = relocated.get(node_id, ())
            if "foster-parented" in node_reasons:
                return "foster-parented-into-executable-context"
            if "relocated-to-head" in node_reasons:
                return "relocated-to-head-executable-content"
        context = self._context(namespace, ancestor_names)
        return {
            "table-scope": "executable-content-in-table-scope",
            "head": "executable-content-in-head",
            "foreign-content": "executable-content-in-foreign-content",
            "body": "executable-content-in-body",
        }[context]

    def _context(self, namespace, ancestor_names):
        if namespace != namespaces["html"]:
            return "foreign-content"
        for ancestor in reversed(ancestor_names):
            if ancestor in table_cell_elements:
                break
            if ancestor in table_scope_elements:
                return "table-scope"
            if ancestor == "head":
                return "head"
        return "body"

    def _remove_element(self, parent, element):
        # Preserve the tail text so legitimate content after the removed
        # element is not lost; the element's own subtree (which may hold
        # payload content) is dropped entirely.
        tail = element.tail
        if tail:
            siblings = list(parent)
            index = siblings.index(element)
            if index > 0:
                previous = siblings[index - 1]
                previous.tail = (previous.tail or "") + tail
            else:
                parent.text = (parent.text or "") + tail
        parent.remove(element)

    def _relocation_diagnostics(self, relocations, paths, removed_ids):
        diagnostics = []
        seen = set()
        for reason, node in relocations:
            element = _unwrap_node(node)
            if element is None or id(element) in removed_ids:
                continue
            path = paths.get(id(element))
            if path is None:
                if reason != "foster-parented-text":
                    continue
                # The foster parent of misnested table text can be the
                # fragment context element, which is replaced by the
                # final fragment root; the move still happened.
                path = ()
            if reason == "foster-parented-text":
                name, namespace = "#text", None
            else:
                namespace, name = _split_tag(element.tag)
            action = "moved" if reason in moved_reasons else "inserted"
            key = (action, reason, name, id(element))
            if key in seen:
                continue
            seen.add(key)
            diagnostics.append(Diagnostic(action, reason, name, namespace,
                                          path))
        return diagnostics


def sanitize_tree(tree, relocations=None,
                  allowed_elements=allowed_elements,
                  executable_elements=executable_elements):
    """Sanitize a fully parsed tree by final node positions.

    Convenience wrapper around TreeSanitizer; returns the list of
    Diagnostic records. See TreeSanitizer.sanitize_tree for details.
    """
    return TreeSanitizer(
        allowed_elements=allowed_elements,
        executable_elements=executable_elements).sanitize_tree(
            tree, relocations=relocations)
