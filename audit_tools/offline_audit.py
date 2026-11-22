import io, os, sys, json, zipfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import olefile
from xml.etree import ElementTree as ET

NS={
 "cp":"http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
 "dc":"http://purl.org/dc/elements/1.1/",
 "w":"http://schemas.openxmlformats.org/wordprocessingml/2006/main",
 "ep":"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
 "ct":"http://schemas.openxmlformats.org/package/2006/content-types"}

def _text(root, path):
    el=root.find(path, NS)
    if el is None: return None
    txt=(el.text or "").strip()
    return txt or None

def audit_ooxml(z):
    layer={"layer":"ooxml_outer","entries":{},"findings":[]}
    names=set(z.namelist())
    core=app=custom=settings=None
    if "docProps/core.xml" in names:
        core=ET.fromstring(z.read("docProps/core.xml"))
    if "docProps/app.xml" in names: app=ET.fromstring(z.read("docProps/app.xml"))
    if "docProps/custom.xml" in names: custom=ET.fromstring(z.read("docProps/custom.xml"))
    if "word/settings.xml" in names: settings=ET.fromstring(z.read("word/settings.xml"))
    layer["entries"]["core.xml"]=core is not None
    layer["entries"]["app.xml"]=app is not None
    layer["entries"]["custom.xml"]=custom is not None
    layer["entries"]["settings.xml"]=settings is not None
    out={}
    if core is not None:
        out["creator"]=_text(core,"dc:creator")
        out["last_modified_by"]=_text(core,"cp:lastModifiedBy")
    if app is not None:
        ael=app.find("ep:Application",NS)
        vel=app.find("ep:AppVersion",NS)
        out["application"]=ael.text.strip() if ael is not None and ael.text else None
        out["app_version"]=vel.text.strip() if vel is not None and vel.text else None
    readonly=False; ro_evidence=[]
    if settings is not None and settings.find("w:documentProtection",NS) is not None:
        dp=settings.find("w:documentProtection",NS)
        if dp.get("{%s}edit"%NS["w"])=="readOnly":
            readonly=True; ro_evidence.append("settings.xml:documentProtection@edit=readOnly")
    if custom is not None:
        for prop in custom:
            nm=prop.get("name","")
            if nm in ("_MarkAsFinal","ReadModeEnforced"):
                readonly=True; ro_evidence.append("custom.xml:%s"%nm)
    out["readonly_claim"]=readonly
    out["readonly_evidence"]=ro_evidence
    out["generator_residue"]=sorted(n for n in names if "residue" in n)
    layer["values"]=out
    return layer

PID_TITLE=2; PID_AUTHOR=4; PID_LASTSAVED=18; PID_COMPANY=15

def _norm(v):
    if isinstance(v,bytes):
        try: return v.decode("cp1252")
        except Exception: return v.decode("utf-8","replace")
    return v

def audit_embedded(blob, member):
    rec={"member":member,"layer":"ole_embedded","parseable":False,"signature_ok":blob[:8]==olefile.MAGIC,
         "streams":[],"properties":{},"error":None}
    if not olefile.isOleFile(io.BytesIO(blob)):
        rec["error"]="not_a_compound_file_signature"
        return rec
    try:
        ole=olefile.OleFileIO(io.BytesIO(blob))
    except Exception as ex:
        rec["error"]="ole_open_failed:%s"%type(ex).__name__
        return rec
    try:
        rec["parseable"]=True
        rec["streams"]=["/".join(p) for p in ole.listdir(streams=True,storages=False)]
        if ole.exists("\\x05SummaryInformation"):
            for pid,val in ole.getproperties("\\x05SummaryInformation").items():
                rec["properties"]["SI:%d"%pid]=_norm(val)
        if ole.exists("\\x05DocumentSummaryInformation"):
            for pid,val in ole.getproperties("\\x05DocumentSummaryInformation").items():
                rec["properties"]["DSI:%d"%pid]=_norm(val)
        rec["has_summary"]=ole.exists("\\x05SummaryInformation")
        rec["has_dsi"]=ole.exists("\\x05DocumentSummaryInformation")
        rec["has_package"]=ole.exists("package")
        rec["has_native"]=ole.exists("Ole10Native")
        rec["has_compobj"]=ole.exists("\\x01CompObj")
    except Exception as ex:
        rec["error"]="ole_parse_failed:%s"%type(ex).__name__
    finally:
        ole.close()
    return rec

def audit_file(path):
    result={"file":os.path.basename(path),"zip_ok":False,"outer":None,"embedded":[],"errors":[]}
    try:
        z=zipfile.ZipFile(path)
        result["zip_ok"]=True
    except Exception as ex:
        result["errors"].append("zip_open_failed:%s"%type(ex).__name__)
        return result
    result["outer"]=audit_ooxml(z)
    for n in z.namelist():
        if n.startswith("word/embeddings/") and n.endswith(".bin"):
        # placeholder indentation fixed below
            result["embedded"].append(audit_embedded(z.read(n),n))
    z.close()
    return result

def classify(audit):
    rows=[]
    outer=audit.get("outer") or {}
    ov=(outer.get("values") or {})
    emb=audit["embedded"][0] if audit.get("embedded") else None
    props=emb["properties"] if emb else {}
    def add(attr_id, scope, claim, status, evidence, observed=None):
        rows.append({"attribute":attr_id,"scope":scope,"claim":claim,"status":status,
                     "evidence":evidence,"observed":observed})
    add("OUT-CREATOR","ooxml_outer","外层作者",
        "supported" if ov.get("creator") else "unparsable",
        "docProps/core.xml dc:creator", ov.get("creator"))
    add("OUT-MODIFIEDBY","ooxml_outer","外层最后保存者",
        "supported" if ov.get("last_modified_by") else "unparsable",
        "docProps/core.xml cp:lastModifiedBy", ov.get("last_modified_by"))
    add("OUT-READONLY","ooxml_outer","只供阅读/标记最终",
        "supported" if ov.get("readonly_claim") else "packaging_only",
        "; ".join(ov.get("readonly_evidence") or []) or "no structural read-only enforcement", True)
    add("OUT-APP","package_residue","生成应用/版本",
        "packaging_only" if (ov.get("application") or ov.get("app_version")) else "unparsable",
        "docProps/app.xml self-reported tool", (ov.get("application"),ov.get("app_version")))
    add("OUT-GENRESIDUE","package_residue","打包工具残留",
        "packaging_only" if ov.get("generator_residue") else "unparsable",
        "non-semantic residue part", ov.get("generator_residue"))
    if emb is None:
        for aid,claim in (("OLE-TITLE","内嵌标题"),("OLE-AUTHOR","内嵌作者"),("OLE-LASTSAVED","内嵌保存者"),("OLE-COMPANY","内嵌单位"),("OLE-PACKAGE","内嵌载荷")):
            add(aid,"ole_embedded",claim,"unparsable","no embedded bin present",None)
    elif not emb.get("parseable"):
        for aid,claim in (("OLE-TITLE","内嵌标题"),("OLE-AUTHOR","内嵌作者"),("OLE-LASTSAVED","内嵌保存者"),("OLE-COMPANY","内嵌单位"),("OLE-PACKAGE","内嵌载荷")):
            add(aid,"ole_embedded",claim,"unparsable",emb.get("error") or "cfb not parseable",None)
    else:
        mapping=[("OLE-TITLE","内嵌标题","SI:2"),("OLE-AUTHOR","内嵌作者","SI:4"),
                 ("OLE-LASTSAVED","内嵌保存者","SI:18"),("OLE-COMPANY","内嵌单位","DSI:15")]
        for aid,claim,key in mapping:
            val=props.get(key)
            add(aid,"ole_embedded",claim,"supported" if val not in (None,"") else "unparsable",
                "CFB property %s"%key, val)
        pkg_ok=emb.get("has_package") or emb.get("has_native")
        add("OLE-PACKAGE","ole_embedded","独立内嵌载荷",
            "supported" if pkg_ok else "unparsable",
            "package/Ole10Native stream", emb.get("streams"))
    return rows

def run(paths, report_path):
    report=[]
    for p in paths:
        audit=audit_file(p)
        audit["classifications"]=classify(audit)
        report.append(audit)
    with open(report_path,"w",encoding="utf-8") as fh:
        json.dump(report,fh,ensure_ascii=False,indent=2)
    return report

def main():
    here=os.path.dirname(os.path.abspath(__file__))
    base=os.path.abspath(os.path.join(here,"..","fixtures"))
    paths=sorted(os.path.join(base,f) for f in os.listdir(base) if f.endswith(".docx"))
    rep=os.path.abspath(os.path.join(here,"..","reports","audit_report.json"))
    os.makedirs(os.path.dirname(rep),exist_ok=True)
    run(paths,rep)
    print("report:",rep)

if __name__=="__main__":
    main()
