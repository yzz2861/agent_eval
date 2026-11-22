import zipfile
from xml.sax.saxutils import escape

CT_DOCX="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
CT_OLE="application/vnd.openxmlformats-officedocument.oleObject"
CT_REL="application/vnd.openxmlformats-package.relationships+xml"
CT_CORE="application/vnd.openxmlformats-package.core-properties+xml"
CT_APP="application/vnd.openxmlformats-officedocument.extended-properties+xml"
CT_CUSTOM="application/vnd.openxmlformats-officedocument.custom-properties+xml"
CT_SETTINGS="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"

def _core(meta):
    return ("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
      "<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" " 
      "xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" " 
      "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
      "<dc:creator>%s</dc:creator><cp:lastModifiedBy>%s</cp:lastModifiedBy>"
      "<dcterms:created xsi:type=\"dcterms:W3CDTF\">%s</dcterms:created>"
      "<dcterms:modified xsi:type=\"dcterms:W3CDTF\">%s</dcterms:modified></cp:coreProperties>") % (
      escape(meta.get("creator","")),escape(meta.get("last_modified_by","")),
      escape(meta.get("created","")),escape(meta.get("modified","")))

def _app(meta):
    return ("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
      "<Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\" " 
      "xmlns:vt=\"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes\">"
      "<Application>%s</Application><AppVersion>%s</AppVersion><DocSecurity>%d</DocSecurity>"
      "<Company>%s</Company></Properties>") % (
      escape(meta.get("application","")),escape(meta.get("app_version","")),
      int(meta.get("doc_security",0)),escape(meta.get("company","")))

def _custom(props):
    rows=[]
    for i,(name,value) in enumerate(props, start=2):
        rows.append("<property fmtid=\"{D5CDD505-2E9C-101B-9397-08002B2CF9AE}\" pid=\"%d\" name=\"%s\">" 
          "<vt:lpwstr>%s</vt:lpwstr></property>" % (i,escape(name),escape(value)))
    return ("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
      "<Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/custom-properties\" " 
      "xmlns:vt=\"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes\">" + "".join(rows) + "</Properties>")

def _settings(mark_final):
    mf="<w:writeProtection/><w:documentProtection w:edit=\"readOnly\"/>" if mark_final else ""
    return ("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
      "<w:settings xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">%s</w:settings>") % mf

DOC_REL_BASE="http://schemas.openxmlformats.org/officeDocument/2006/relationships"

def _document(ole_count):
    parts=["<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"]
    parts.append("<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>")
    for i in range(ole_count):
        rid="rIdOle%d"%i
        parts.append("<w:p><w:r><w:object w:dxaOrig=\"100\" w:dyaOrig=\"100\">"
          "<o:OLEObject Type=\"Embed\" ProgID=\"Word.Document.12\" ShapeID=\"%d\" r:id=\"%s\" " 
          "xmlns:o=\"urn:schemas-microsoft-com:office:office\" " 
          "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"/></w:object></w:r></w:p>" % (i,rid))
    parts.append("</w:body></w:document>")
    return "".join(parts)

def _doc_rels(ole_count):
    parts=["<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>",
      "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"]
    for i in range(ole_count):
        parts.append("<Relationship Id=\"rIdOle%d\" Type=\"%s/oleObject\" Target=\"embeddings/oleObject%d.bin\"/>" % (i,DOC_REL_BASE,i+1))
    parts.append("</Relationships>")
    return "".join(parts)

def _root_rels():
    return ("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
      "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
      "<Relationship Id=\"rId1\" Type=\"%s/document\" Target=\"word/document.xml\"/>" % DOC_REL_BASE +
      "<Relationship Id=\"rId2\" Type=\"%s/metadata/core-properties\" Target=\"docProps/core.xml\"/>" % "http://schemas.openxmlformats.org/package/2006/relationships" +
      "<Relationship Id=\"rId3\" Type=\"%s/extended-properties\" Target=\"docProps/app.xml\"/>" % DOC_REL_BASE +
      "<Relationship Id=\"rId4\" Type=\"%s/custom-properties\" Target=\"docProps/custom.xml\"/></Relationships>") % DOC_REL_BASE

def _content_types(ole_count, has_custom=True):
    parts=["<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>",
      "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">",
      "<Default Extension=\"rels\" ContentType=\"%s\"/>" % CT_REL,
      "<Default Extension=\"xml\" ContentType=\"application/xml\"/>",
      "<Default Extension=\"bin\" ContentType=\"application/vnd.openxmlformats-officedocument.oleObject\"/>",
      "<Override PartName=\"/word/document.xml\" ContentType=\"%s\"/>" % CT_DOCX,
      "<Override PartName=\"/word/settings.xml\" ContentType=\"%s\"/>" % CT_SETTINGS,
      "<Override PartName=\"/docProps/core.xml\" ContentType=\"%s\"/>" % CT_CORE,
      "<Override PartName=\"/docProps/app.xml\" ContentType=\"%s\"/>" % CT_APP]
    if has_custom:
        parts.append("<Override PartName=\"/docProps/custom.xml\" ContentType=\"%s\"/>" % CT_CUSTOM)
    parts.append("</Types>")
    return "".join(parts)

def build_docx(path, core_meta, app_meta, custom_props, embeddings, mark_final=False, generator_note=None):
    files={}
    files["[Content_Types].xml"]=_content_types(len(embeddings), bool(custom_props))
    files["_rels/.rels"]=_root_rels()
    files["word/document.xml"]=_document(len(embeddings))
    files["word/_rels/document.xml.rels"]=_doc_rels(len(embeddings))
    files["word/settings.xml"]=_settings(mark_final)
    files["docProps/core.xml"]=_core(core_meta)
    files["docProps/app.xml"]=_app(app_meta)
    if custom_props:
        files["docProps/custom.xml"]=_custom(custom_props)
    if generator_note:
        files["docProps/generator-residue.txt"]=generator_note
    for i,blob in enumerate(embeddings):
        files["word/embeddings/oleObject%d.bin"%(i+1)]=blob
    with zipfile.ZipFile(path,"w",zipfile.ZIP_DEFLATED) as z:
        for name,data in files.items():
            if isinstance(data,str): data=data.encode("utf-8")
            z.writestr(name,data)
    return path
