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

from six.moves import urllib_parse as urlparse

from . import base
from ..constants import (namespaces, prefixes, spaceCharacters,
                         htmlIntegrationPointElements,
                         mathmlTextIntegrationPointElements,
                         foreignContentBreakoutElements,
                         scopingElements, specialElements, headingElements)

__all__ = ["Filter"]


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


# Elements that must never survive sanitizing, in any namespace: they
# execute script, load active external content, or switch the parser into
# a raw-text or integration-point mode that would let the sanitized output
# mutate into executable content when it is re-parsed (mutation XSS).
# foreignObject and annotation-xml are HTML integration points: their
# children are parsed as HTML, so keeping the children while removing the
# element would relocate them in the re-parsed tree.
disallowed_elements = frozenset(
    (namespace, name)
    for namespace in (namespaces["html"], namespaces["svg"],
                      namespaces["mathml"])
    for name in ("script", "style", "iframe", "object", "embed", "applet",
                 "base", "link", "meta", "xmp", "noembed", "noframes",
                 "noscript", "plaintext", "template", "frame", "frameset",
                 "foreignobject", "foreignObject", "annotation-xml")
)

# HTML elements in whose content the parser foster-parents character data
# (moves it in front of the table).  Character tokens emitted directly
# inside these contexts would not survive a serialize/re-parse round-trip
# in place, so the sanitizer drops them (and audits the drop) instead of
# emitting output whose tree mutates when re-parsed.
foster_parenting_elements = frozenset(
    (namespaces["html"], name)
    for name in ("table", "tbody", "thead", "tfoot", "tr", "colgroup")
)

# Elements the parser keeps directly inside the table contexts above
# without relocating them (foster parenting, implying tbody/tr, popping
# colgroup, ...).  Anything else emitted directly inside one of these
# contexts would be relocated when the output is re-parsed.
table_structure_elements = {
    (namespaces["html"], "table"): frozenset(
        (namespaces["html"], name)
        for name in ("caption", "colgroup", "col", "tbody", "thead",
                     "tfoot", "input", "form")),
    (namespaces["html"], "tbody"): frozenset([(namespaces["html"], "tr")]),
    (namespaces["html"], "thead"): frozenset([(namespaces["html"], "tr")]),
    (namespaces["html"], "tfoot"): frozenset([(namespaces["html"], "tr")]),
    (namespaces["html"], "tr"): frozenset(
        [(namespaces["html"], "td"), (namespaces["html"], "th")]),
    (namespaces["html"], "colgroup"): frozenset([(namespaces["html"], "col")]),
}

# Table structure elements are only reproduced by the parser when their
# required ancestor is the current node; anywhere else they are ignored
# or trigger implied elements.  Maps element name to the set of required
# parent element names.
required_table_ancestors = {
    "caption": frozenset(["table"]),
    "colgroup": frozenset(["table"]),
    "tbody": frozenset(["table"]),
    "thead": frozenset(["table"]),
    "tfoot": frozenset(["table"]),
    "tr": frozenset(["tbody", "thead", "tfoot"]),
    "td": frozenset(["tr"]),
    "th": frozenset(["tr"]),
    "col": frozenset(["colgroup"]),
}

# SVG animation elements: they can animate a *target* attribute of their
# parent, so both the target attribute name and the animated values have
# to be checked the way the target attribute itself would be.
svg_animation_elements = frozenset(
    ("set", "animate", "animateColor", "animateMotion", "animateTransform")
)

# Attributes on SVG animation elements that hold the animated value(s).
svg_animation_value_attributes = frozenset(
    (None, name) for name in ("to", "from", "values", "by")
)


# HTML elements whose start tag closes an open <p> element in button
# scope (mirrors the parser's in-body rules; html5lib.html5parser).
p_closing_elements = frozenset([
    "address", "article", "aside", "blockquote", "center", "details",
    "dir", "div", "dl", "fieldset", "figcaption", "figure", "footer",
    "header", "hgroup", "main", "menu", "nav", "ol", "p", "section",
    "summary", "ul",
    "pre", "listing",
    "form",
    "li", "dd", "dt",
    "plaintext",
    "hr",
    "table",
    "xmp",
]) | frozenset(headingElements)

# Elements after which the parser places a marker on the list of active
# formatting elements; an <a> before the marker does not trigger the
# adoption agency algorithm for a later <a>.
afe_marker_elements = frozenset(
    (namespaces["html"], name)
    for name in ("applet", "caption", "marquee", "object", "td", "th")
)


# Elements whose content is parsed as text (RCDATA): no child element can
# ever be reproduced by re-parsing, so any element token emitted directly
# inside them is escaped.  (Element children only ever appear there
# through parser quirks such as formatting-element reconstruction.)
rcdata_text_elements = frozenset([
    (namespaces["html"], "textarea"),
    (namespaces["html"], "title"),
])


class Filter(base.Filter):
    """Sanitizes token stream of XHTML+MathML+SVG and of inline style attributes

    All decisions are made on the parsed (namespace, localName, attributes)
    of each token, never on the raw source text.  The filter tracks the
    element stack it emits and applies the same foreign-content and
    integration-point rules as the HTML parser (sharing the policy tables
    in html5lib.constants with html5lib.html5parser), so that serializing
    the filtered stream and re-parsing it yields the same safe tree:
    sanitizing is idempotent and no mutation XSS can occur.

    Every dropped element, attribute or character run is recorded in
    self.audit_log as (reason, subject, detail) tuples; the audit trail
    never alters the user-visible output.
    """
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
                 svg_allow_local_href=svg_allow_local_href,
                 disallowed_elements=disallowed_elements,
                 svg_animation_elements=svg_animation_elements,
                 audit_log=None):
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

        :arg disallowed_elements: set of elements that are never allowed,
            whatever the namespace--they are escaped even if also present
            in allowed_elements

        :arg svg_animation_elements: set of SVG elements that can animate a
            target attribute--their attributeName/to/from/values/by
            attributes are checked like the target attribute would be

        :arg audit_log: optional list that will be filled with
            (reason, subject, detail) tuples describing every dropped or
            escaped item; a new list is created when omitted

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
        self.disallowed_elements = disallowed_elements
        self.svg_animation_elements = svg_animation_elements
        self.audit_log = audit_log if audit_log is not None else []
        # Stack of (namespace, name, emitted) for open elements; used to
        # reproduce the parser's content-model decisions for the output.
        self._element_stack = []

    def __iter__(self):
        del self._element_stack[:]
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
        if token_type in ("StartTag", "EmptyTag"):
            return self.sanitize_start_tag(token)
        elif token_type == "EndTag":
            return self.sanitize_end_tag(token)
        elif token_type == "Comment":
            self.audit_log.append(("comment-dropped", None, None))
            return None
        elif token_type in ("Characters", "SpaceCharacters"):
            if (self._in_foster_parenting_context() and
                    token["data"].strip("".join(spaceCharacters))):
                # Character data directly inside a table context is
                # foster-parented by the parser; emitting it here would
                # make the re-parsed tree mutate.  Drop and audit it.
                self.audit_log.append(
                    ("characters-dropped", "foster-parenting-context",
                     token["data"]))
                return None
            # The input stream of any HTML parser normalizes CR to LF;
            # apply the same normalization so the output is a fixed
            # point of parsing (a literal CR can otherwise only appear
            # through character references)
            if "\r" in token["data"]:
                token["data"] = token["data"].replace("\r\n", "\n")
                token["data"] = token["data"].replace("\r", "\n")
            return token
        else:
            return token

    def sanitize_start_tag(self, token):
        namespace = token["namespace"] or namespaces["html"]
        name = token["name"]
        if (namespace, name) in self.disallowed_elements:
            return self.escape_element(token, "disallowed-element")
        if (namespace, name) not in self.allowed_elements:
            return self.escape_element(token, "element-not-allowed")
        if not self._stable_in_context(namespace, name, token.get("data")):
            # The parser would relocate this element or put it in another
            # namespace when re-parsing the output: escape it so the
            # serialized tree is a fixed point of parsing.
            return self.escape_element(token, "unstable-context")
        token = self.allowed_token(token)
        if token["type"] == "StartTag" and not token.get("selfClosing"):
            self._element_stack.append((namespace, name, True))
        return token

    def sanitize_end_tag(self, token):
        namespace = token["namespace"] or namespaces["html"]
        name = token["name"]
        if (self._element_stack and
                self._element_stack[-1][0:2] == (namespace, name)):
            emitted = self._element_stack.pop()[2]
            if emitted:
                return token
            return self.escape_element(token, "disallowed-element")
        # Unmatched end tag: html5lib's tree builders never produce these,
        # but other token sources might.  Re-emitting it could create an
        # element on re-parse (e.g. </p> creates an empty <p>), so escape
        # it to keep the output a fixed point of parsing.
        return self.escape_element(token, "unmatched-end-tag")

    def escape_element(self, token, reason):
        namespace = token["namespace"] or namespaces["html"]
        name = token["name"]
        self.audit_log.append((reason, (namespace, name), None))
        if token["type"] == "StartTag" and not token.get("selfClosing"):
            self._element_stack.append((namespace, name, False))
        if self._in_foster_parenting_context():
            # The escaped source text would be foster-parented out of the
            # table on re-parse; drop it (audited) to keep the tree stable.
            self.audit_log.append(
                ("characters-dropped", "foster-parenting-context",
                 token.get("data")))
            return None
        return self.disallowed_token(token)

    def _nearest_emitted_element(self):
        for namespace, name, emitted in reversed(self._element_stack):
            if emitted:
                return namespace, name
        return None

    def _in_html_content(self, tag_name):
        # Mirrors HTMLParser.mainLoop: would a start tag token seen now be
        # processed by the HTML ("in body") rules rather than the foreign
        # content rules?
        current = self._nearest_emitted_element()
        if current is None:
            return True
        namespace, name = current
        if namespace == namespaces["html"]:
            return True
        if (current in mathmlTextIntegrationPointElements and
                tag_name not in ("mglyph", "malignmark")):
            return True
        if current in htmlIntegrationPointElements:
            return True
        return False

    def _stable_in_context(self, namespace, name, attrs):
        # Would the parser, re-parsing the serialized output, place this
        # element right here with the same (namespace, name)?
        current = self._nearest_emitted_element()
        if current in rcdata_text_elements:
            # RCDATA content is text; child elements never re-parse
            return False
        if (current in foster_parenting_elements and
                (namespace, name) not in table_structure_elements[current]):
            # The parser would foster-parent or otherwise relocate this
            # element out of the table context
            return False
        if (namespace == namespaces["html"] and
                name in required_table_ancestors and
                (current is None or
                 current[0] != namespaces["html"] or
                 current[1] not in required_table_ancestors[name])):
            # Table structure elements are ignored (or relocated) unless
            # their required ancestor is the current node
            return False
        if self._in_html_content(name):
            if namespace == namespaces["html"]:
                # <svg> and <math> start tags always switch to their
                # foreign content namespace when parsed as HTML
                if name in ("svg", "math"):
                    return False
                return self._html_start_tag_stable(name)
            return (namespace, name) in ((namespaces["svg"], "svg"),
                                         (namespaces["mathml"], "math"))
        foreign_namespace = self._nearest_emitted_element()[0]
        if namespace != foreign_namespace:
            # Re-parsing would insert the element in the surrounding
            # foreign content namespace instead
            return False
        if name in foreignContentBreakoutElements:
            # Re-parsing would pop out of foreign content
            return False
        if (name == "font" and attrs and
                set(attrs) & {(None, "color"), (None, "face"),
                              (None, "size")}):
            return False
        return True

    def _html_start_tag_stable(self, name):
        # Mirror the parser's in-body start tag handlers: would anything
        # be implicitly closed, popped or ignored before this element is
        # inserted?  If so, emitting it here would change the tree when
        # the output is re-parsed.
        if name in p_closing_elements and self._element_in_scope("p", "button"):
            return False
        if (name in headingElements and
                self._top_emitted_name() in headingElements):
            return False
        if name in ("li", "dd", "dt"):
            stop_names = ("li",) if name == "li" else ("dd", "dt")
            if self._list_item_would_close(stop_names):
                return False
        if name in ("option", "optgroup") and self._top_emitted_name() == "option":
            return False
        if name == "a" and self._formatting_element_active("a"):
            return False
        if name == "button" and self._element_in_scope("button"):
            return False
        if name == "form" and self._emitted_html_element_open("form"):
            # The parser ignores a <form> start tag while another form is
            # still open (the form element pointer is only reset by a
            # </form> end tag)
            return False
        return True

    def _top_emitted_name(self):
        current = self._nearest_emitted_element()
        return current[1] if current else None

    def _element_in_scope(self, name, variant=None):
        # Mirrors treebuilders.base.Tree.elementInScope
        if variant == "button":
            boundaries = scopingElements | {(namespaces["html"], "button")}
        else:
            boundaries = scopingElements
        target = (namespaces["html"], name)
        for namespace, elem_name, emitted in reversed(self._element_stack):
            if not emitted:
                continue
            if (namespace, elem_name) == target:
                return True
            if (namespace, elem_name) in boundaries:
                return False
        return False

    def _list_item_would_close(self, stop_names):
        # Mirrors InBodyPhase.startTagListItem
        for namespace, elem_name, emitted in reversed(self._element_stack):
            if not emitted:
                continue
            if elem_name in stop_names:
                return True
            if ((namespace, elem_name) in specialElements and
                    elem_name not in ("address", "div", "p")):
                return False
        return False

    def _formatting_element_active(self, name):
        # Mirrors Tree.elementInActiveFormattingElements for the emitted
        # element stack
        for namespace, elem_name, emitted in reversed(self._element_stack):
            if not emitted:
                continue
            if (namespace, elem_name) == (namespaces["html"], name):
                return True
            if (namespace, elem_name) in afe_marker_elements:
                return False
        return False

    def _emitted_html_element_open(self, name):
        return any(emitted and namespace == namespaces["html"] and
                   elem_name == name
                   for namespace, elem_name, emitted in self._element_stack)

    def _in_foster_parenting_context(self):
        return self._nearest_emitted_element() in foster_parenting_elements

    def allowed_token(self, token):
        if "data" not in token:
            return token
        namespace = token["namespace"] or namespaces["html"]
        name = token["name"]
        attrs = token["data"]

        # Remove forbidden attributes; event handler content attributes
        # (on*) are removed even if a custom allowlist would keep them
        for attr in list(attrs):
            if self._is_event_attribute(attr):
                del attrs[attr]
                self.audit_log.append(
                    ("event-attribute-dropped", (namespace, name), attr))
            elif attr not in self.allowed_attributes:
                del attrs[attr]
                self.audit_log.append(
                    ("attribute-dropped", (namespace, name), attr))

        # Remove attributes with disallowed URL values
        for attr in (set(attrs) & self.attr_val_is_uri):
            assert attr in attrs
            # I don't have a clue where this regexp comes from or why it matches those
            # characters, nor why we call unescape. I just know it's always been here.
            # Should you be worried by this comment in a sanitizer? Yes. On the other hand, all
            # this will do is remove *more* than it otherwise would.
            val_unescaped = re.sub("[\x60\x00-\x20\x7f-\xa0\\s]+", '',
                                   unescape(attrs[attr])).lower()
            # remove replacement characters from unescaped characters
            val_unescaped = val_unescaped.replace("\ufffd", "")
            try:
                uri = urlparse.urlparse(val_unescaped)
            except ValueError:
                uri = None
            if uri is None:
                del attrs[attr]
                self.audit_log.append(
                    ("attribute-value-dropped", (namespace, name), attr))
            elif uri.scheme:
                if uri.scheme not in self.allowed_protocols:
                    del attrs[attr]
                    self.audit_log.append(
                        ("attribute-value-dropped", (namespace, name), attr))
                elif uri.scheme == 'data':
                    m = data_content_type.match(uri.path)
                    if (not m or
                            m.group('content_type') not in
                            self.allowed_content_types):
                        del attrs[attr]
                        self.audit_log.append(
                            ("attribute-value-dropped", (namespace, name),
                             attr))

        for attr in self.svg_attr_val_allows_ref:
            if attr in attrs:
                attrs[attr] = re.sub(r'url\s*\(\s*[^#\s][^)]+?\)',
                                     ' ',
                                     unescape(attrs[attr]))

        # Some SVG elements may only link inside the document; strip
        # non-local hrefs (both xlink:href and plain href)
        if (namespace == namespaces["svg"] and
                (name in self.svg_allow_local_href or
                 (None, name) in self.svg_allow_local_href)):
            for href_attr in ((namespaces['xlink'], 'href'), (None, 'href')):
                if (href_attr in attrs and
                        re.search(r'^\s*[^#\s].*', attrs[href_attr])):
                    del attrs[href_attr]
                    self.audit_log.append(
                        ("attribute-value-dropped", (namespace, name),
                         href_attr))

        if (namespace == namespaces["svg"] and
                name in self.svg_animation_elements):
            self._sanitize_animation_attributes(namespace, name, attrs)

        if (None, 'style') in attrs:
            attrs[(None, 'style')] = self.sanitize_css(attrs[(None, 'style')])
        for attr, value in list(attrs.items()):
            # CR is normalized to LF by the input stream of any HTML
            # parser; keep the output a fixed point of parsing
            if "\r" in value:
                attrs[attr] = value.replace("\r\n", "\n").replace("\r", "\n")
        token["data"] = attrs
        return token

    def _is_event_attribute(self, attr):
        # Event handler content attributes start with "on"; the check is
        # against the module-level allowlist so that legitimate allowed
        # attributes such as "open" are never affected, even when the
        # filter is configured with a custom allowlist.
        namespace, local = attr
        return (local.lower().startswith("on") and
                attr not in allowed_attributes and
                (namespace, local.lower()) not in allowed_attributes)

    def _sanitize_animation_attributes(self, namespace, name, attrs):
        # SVG animation elements can set an arbitrary attribute of their
        # target; make sure they cannot animate event handlers or smuggle
        # dangerous URL schemes into URL attributes.
        attribute_name_attr = (None, "attributeName")
        if attribute_name_attr not in attrs:
            return
        target_local = attrs[attribute_name_attr].strip().split(":")[-1]
        target_local = target_local.lower()
        if target_local.startswith("on"):
            del attrs[attribute_name_attr]
            self.audit_log.append(
                ("event-attribute-dropped", (namespace, name),
                 attribute_name_attr))
            return
        uri_attributes = set(local for (ns, local) in self.attr_val_is_uri)
        if target_local in uri_attributes:
            for value_attr in svg_animation_value_attributes:
                if (value_attr in attrs and
                        not self._animation_value_is_safe(attrs[value_attr])):
                    del attrs[value_attr]
                    self.audit_log.append(
                        ("attribute-value-dropped", (namespace, name),
                         value_attr))

    def _animation_value_is_safe(self, value):
        for part in value.split(";"):
            val_unescaped = re.sub("[\x60\x00-\x20\x7f-\xa0\\s]+", '',
                                   unescape(part)).lower()
            val_unescaped = val_unescaped.replace("\ufffd", "")
            if not val_unescaped:
                continue
            try:
                uri = urlparse.urlparse(val_unescaped)
            except ValueError:
                return False
            if uri.scheme and uri.scheme not in self.allowed_protocols:
                return False
        return True

    def disallowed_token(self, token):
        token_type = token["type"]
        if token_type == "EndTag":
            token["data"] = "</%s>" % token["name"]
        elif token["data"]:
            assert token_type in ("StartTag", "EmptyTag")
            attrs = []
            for (ns, name), v in token["data"].items():
                attrs.append(' %s="%s"' % (name if ns is None else "%s:%s" % (prefixes.get(ns, ns), name), escape(v)))
            token["data"] = "<%s%s>" % (token["name"], ''.join(attrs))
        else:
            token["data"] = "<%s>" % token["name"]
        if token.get("selfClosing"):
            token["data"] = token["data"][:-1] + "/>"

        if "\r" in token["data"]:
            token["data"] = token["data"].replace("\r\n", "\n")
            token["data"] = token["data"].replace("\r", "\n")

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
