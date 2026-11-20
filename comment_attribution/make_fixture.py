#!/usr/bin/env python3
"""构造最小 docx 测试件，覆盖三种取证情形：

- 同名作者：批注 0 与批注 1 的 w:author 都是 "张伟"（initials 不同），
  用于验证"局部 ID 不跨部件认人、同名不合并"。
- 断开引用：document.xml 中存在 id=99 的批注锚点，
  但 comments.xml 中没有 id=99 的批注，不能给出肯定归属。
- 已删对象：comments.xml 中存在 id=3 的批注，
  但 document.xml 中没有对应锚点，标记为历史证据。
另外批注 2 通过 commentsExtended.xml 的 paraIdParent 回复批注 0。
"""

import os
from zipfile import ZipFile, ZIP_DEFLATED

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "fixtures", "sample_comments.docx")

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W14 = "http://schemas.microsoft.com/office/word/2010/wordml"
W15 = "http://schemas.microsoft.com/office/word/2012/wordml"
W16CID = "http://schemas.microsoft.com/office/word/2016/wordml/cid"

NSMAP_DOC = (
    'xmlns:w="{w}" xmlns:w14="{w14}" xmlns:w15="{w15}" xmlns:w16cid="{w16cid}"'
).format(w=W, w14=W14, w15=W15, w16cid=W16CID)

CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>
  <Override PartName="/word/commentsExtended.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.commentsExtended+xml"/>
  <Override PartName="/word/commentsIds.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.commentsIds+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>
"""

RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>
"""

DOC_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/commentsExtended" Target="commentsExtended.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/commentsIds" Target="commentsIds.xml"/>
</Relationships>
"""


def _anchored_paragraph(cid, text):
    return (
        "<w:p>"
        '<w:commentRangeStart w:id="{0}"/>'
        "<w:r><w:t>{1}</w:t></w:r>"
        '<w:commentRangeEnd w:id="{0}"/>'
        "<w:r>"
        '<w:rPr><w:rStyle w:val="CommentReference"/></w:rPr>'
        '<w:commentReference w:id="{0}"/>'
        "</w:r>"
        "</w:p>"
    ).format(cid, text)


DOCUMENT = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    "<w:document {ns}><w:body>"
    + _anchored_paragraph(0, "第一段正文（锚点 0）")
    + _anchored_paragraph(1, "第二段正文（锚点 1）")
    + _anchored_paragraph(2, "第三段正文（锚点 2）")
    + _anchored_paragraph(99, "第四段正文（锚点 99，引用已断开）")
    + "<w:sectPr/></w:body></w:document>"
).format(ns=NSMAP_DOC)


def _comment(cid, author, initials, date, para_id, text):
    return (
        '<w:comment w:id="{cid}" w:author="{author}" w:initials="{ini}" '
        'w:date="{date}">'
        '<w:p w14:paraId="{pid}">'
        '<w:pPr><w:pStyle w:val="CommentText"/></w:pPr>'
        "<w:r><w:t>{text}</w:t></w:r></w:p></w:comment>"
    ).format(cid=cid, author=author, ini=initials, date=date, pid=para_id,
             text=text)


COMMENTS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    "<w:comments {ns}>"
    + _comment(0, "张伟", "ZW", "2026-11-18T09:30:00Z", "0000000A",
               "这里的口径需要复核。")
    + _comment(1, "张伟", "ZW2", "2026-11-18T10:05:00Z", "0000000B",
               "同名另一位：建议删掉这句。")
    + _comment(2, "李四", "LS", "2026-11-18T11:20:00Z", "0000000C",
               "同意，已按意见修改。")
    + _comment(3, "王五", "WW", "2026-11-17T16:40:00Z", "0000000D",
               "（此批注的正文锚点已被删除）")
    + "</w:comments>"
).format(ns=NSMAP_DOC)


def _comment_ex(para_id, parent=None):
    parent_attr = ' w15:paraIdParent="{0}"'.format(parent) if parent else ""
    return ('<w15:commentEx w15:paraId="{0}"{1} w15:done="0"/>'
            .format(para_id, parent_attr))


COMMENTS_EXTENDED = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    "<w15:commentsEx {ns}>"
    + _comment_ex("0000000A")
    + _comment_ex("0000000B")
    + _comment_ex("0000000C", parent="0000000A")
    + _comment_ex("0000000D")
    + "</w15:commentsEx>"
).format(ns=NSMAP_DOC)


def _comment_id(para_id, durable_id):
    return ('<w16cid:commentId w16cid:paraId="{0}" '
            'w16cid:durableId="{1}"/>').format(para_id, durable_id)


COMMENTS_IDS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    "<w16cid:commentsIds {ns}>"
    + _comment_id("0000000A", "1A2B3C4D")
    + _comment_id("0000000B", "5E6F7A8B")
    + _comment_id("0000000C", "9C0D1E2F")
    + "</w16cid:commentsIds>"
).format(ns=NSMAP_DOC)

CORE = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:creator>张伟</dc:creator>
  <cp:lastModifiedBy>李四</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">2026-11-17T08:00:00Z</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">2026-11-18T12:00:00Z</dcterms:modified>
</cp:coreProperties>
"""

APP = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office Word</Application>
</Properties>
"""

PARTS = {
    "[Content_Types].xml": CONTENT_TYPES,
    "_rels/.rels": RELS,
    "word/_rels/document.xml.rels": DOC_RELS,
    "word/document.xml": DOCUMENT,
    "word/comments.xml": COMMENTS,
    "word/commentsExtended.xml": COMMENTS_EXTENDED,
    "word/commentsIds.xml": COMMENTS_IDS,
    "docProps/core.xml": CORE,
    "docProps/app.xml": APP,
}


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with ZipFile(OUT, "w", ZIP_DEFLATED) as zf:
        for name, data in PARTS.items():
            zf.writestr(name, data)
    print("written: {0}".format(OUT))


if __name__ == "__main__":
    main()
