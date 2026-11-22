import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import cfb, ooxml

OUT=os.path.join(os.path.dirname(__file__), "..", "fixtures")
OUT=os.path.abspath(OUT)
os.makedirs(OUT, exist_ok=True)

def inner_package(label):
    return ("PK\x03\x04 embedded OOXML package payload for %s (independent inner material)") % label

def normal_embedded_cfb():
    si=cfb.property_set_stream(cfb.FMTID_SI,[
        (2, "Inner Evidence Title"),
        (4, "Inner Evidence Author"),
        (18, "Inner Saved By")])
    dsi=cfb.property_set_stream(cfb.FMTID_DSI,[(15, "Inner Org Company")])
    co=cfb.compobj_stream(bytes(16), "embedded_inner.docx", "Word.Document.12")
    return cfb.build_cfb({
        "\\x05SummaryInformation": si,
        "\\x05DocumentSummaryInformation": dsi,
        "\\x01CompObj": co,
        "package": inner_package("normal").encode("utf-8")})

def packaging_only_cfb():
    # Ole10Native Package shell: no SummaryInformation/DocumentSummaryInformation,
    # only tool wrapper stream -> packaging residue, no document-layer descriptive evidence.
    native=b"PACKAGED_BY=Contoso SaveAs Converter 7.0\r\nORIGINAL=claim_readonly.docx\r\n"
    return cfb.build_cfb({"Ole10Native": native, "\x01CompObj": cfb.compobj_stream(bytes(16), "wrapped.bin", "Package")})

def corrupt_cfb():
    good=normal_embedded_cfb()
    # truncate mid-stream and corrupt signature so OLE parsing must fail
    return b"NOT_OLE"+good[8:len(good)//2]

def main():
    ole_blob=normal_embedded_cfb()
    ooxml.build_docx(os.path.join(OUT,"normal_embedded.docx"),
        core_meta={"creator":"Outer Reviewer","last_modified_by":"Outer SaveAs Tool",
                   "created":"2026-11-20T01:00:00Z","modified":"2026-11-21T02:00:00Z"},
        app_meta={"application":"Contoso SaveAs Converter","app_version":"7.0",
                  "doc_security":0,"company":"Outer Packaging Corp"},
        custom_props=[("ReadModeEnforced","true"),("_MarkAsFinal","true")],
        embeddings=[ole_blob], mark_final=True,
        generator_note="generator=Contoso SaveAs Converter; build=7.0; residue-only marker")
    ooxml.build_docx(os.path.join(OUT,"packaging_only.docx"),
        core_meta={"creator":"","last_modified_by":"SaveAs Converter",
                   "created":"2026-11-20T01:00:00Z","modified":"2026-11-21T02:00:00Z"},
        app_meta={"application":"Contoso SaveAs Converter","app_version":"7.0",
                  "doc_security":0,"company":""},
        custom_props=[("ReadModeEnforced","true")],
        embeddings=[packaging_only_cfb()], mark_final=True,
        generator_note="generator=Contoso SaveAs Converter; build=7.0; no document-layer evidence")
    ooxml.build_docx(os.path.join(OUT,"unparsable_embed.docx"),
        core_meta={"creator":"Outer Reviewer","last_modified_by":"Outer SaveAs Tool",
                   "created":"2026-11-20T01:00:00Z","modified":"2026-11-21T02:00:00Z"},
        app_meta={"application":"Contoso SaveAs Converter","app_version":"7.0",
                  "doc_security":0,"company":"Outer Packaging Corp"},
        custom_props=[("_MarkAsFinal","true")],
        embeddings=[corrupt_cfb()], mark_final=True)
    print("wrote fixtures to", OUT)

if __name__=="__main__":
    main()
