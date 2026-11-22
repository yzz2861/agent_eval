import json, os

HERE=os.path.dirname(os.path.abspath(__file__))
SRC=os.path.abspath(os.path.join(HERE,"..","reports","audit_report.json"))
DST=os.path.abspath(os.path.join(HERE,"..","reports","audit_report.md"))

def main():
    report=json.load(open(SRC,encoding="utf-8"))
    lines=["# 离线分层核对报告","",
      "本报告仅基于 OLE 属性（olefile）与 OOXML 结构入口离线生成，未打开任何 Office 应用。",""]
    for a in report:
        lines.append("## %s"%a["file"])
        lines.append("ZIP/OPC 容器可解析：%s"%("是" if a["zip_ok"] else "否"))
        for e in a["embedded"]:
            lines.append("- 内嵌 `%s`：CFB 可解析=%s；签名正确=%s；错误=%s"
              %(e["member"],e["parseable"],e["signature_ok"],e.get("error")))
        lines.append("")
        lines.append("| 属性 | 作用域 | 判定 | 支持证据 | 观测值 |")
        lines.append("|---|---|---|---|---|")
        for c in a["classifications"]:
            obs=c.get("observed")
            obs="-" if obs is None else str(obs).replace("|","/")
            lines.append("| %s | %s | %s | %s | %s |"%(
              c["attribute"],c["scope"],c["status"],c["evidence"].replace("|","/"),obs))
        lines.append("")
    open(DST,"w",encoding="utf-8").write("\n".join(lines))
    print("wrote",DST)

if __name__=="__main__":
    main()
