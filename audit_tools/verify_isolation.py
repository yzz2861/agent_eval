import io, os, sys, zipfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import olefile, offline_audit

def main():
    path=os.path.abspath(os.path.join(os.path.dirname(__file__),"..","fixtures","normal_embedded.docx"))
    audit=offline_audit.audit_file(path)
    audit["classifications"]=offline_audit.classify(audit)
    rows={c["attribute"]:c for c in offline_audit.classify(audit)}
    outer=audit["outer"]["values"]
    emb=audit["embedded"][0]
    checks=[]
    # 1. outer read-only claim present and structurally evidenced
    checks.append(("outer readonly claim supported", rows["OUT-READONLY"]["status"]=="supported"))
    # 2. inner has its own independent descriptive properties
    checks.append(("inner title supported", rows["OLE-TITLE"]["status"]=="supported"))
    checks.append(("inner author supported", rows["OLE-AUTHOR"]["status"]=="supported"))
    # 3. inner and outer values differ -> no overwrite
    inner_author=emb["properties"].get("SI:4")
    outer_author=outer.get("creator")
    checks.append(("inner author != outer creator", inner_author != outer_author))
    inner_company=emb["properties"].get("DSI:15")
    # outer app.xml company vs inner DSI company
    z=zipfile.ZipFile(path)
    from xml.etree import ElementTree as ET
    app=ET.fromstring(z.read("docProps/app.xml"))
    oc=app.find("ep:Company",offline_audit.NS)
    outer_company=oc.text.strip() if oc is not None and oc.text else None
    checks.append(("inner company != outer company", inner_company != outer_company))
    # 4. scopes are distinct keys, no attribute appears in two scopes
    scopes={}
    for c in audit["classifications"]:
        scopes.setdefault(c["scope"],[]).append(c["attribute"])
    allids=[i for v in scopes.values() for i in v]
    checks.append(("attribute ids unique across scopes", len(allids)==len(set(allids))))
    # 5. embedded CFB parses independently of outer
    raw=z.read("word/embeddings/oleObject1.bin")
    ole=olefile.OleFileIO(io.BytesIO(raw))
    independent=ole.getproperties("\\x05SummaryInformation").get(4)
    ole.close()
    checks.append(("embedded CFB independently parseable", independent is not None))
    ok=all(p for _,p in checks)
    for name,res in checks: print(("PASS" if res else "FAIL"), name)
    print("outer creator=%r | inner author=%r"%(outer_author,inner_author))
    print("outer company=%r | inner company=%r"%(outer_company,inner_company))
    print("OVERALL", "PASS" if ok else "FAIL")
    return ok

if __name__=="__main__":
    sys.exit(0 if main() else 1)
