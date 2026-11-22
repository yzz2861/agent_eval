import json, os
attrs=[
 {"id":"OUT-CREATOR","scope":"ooxml_outer","entry":"docProps/core.xml","xpath":"dc:creator",
  "claim":"外层作者说明","required_evidence":"core.xml 中 dc:creator 元素存在且有非空文本",
  "classification_if_absent":"unparsable","note":"文档层语义，需元素级证据"},
 {"id":"OUT-MODIFIEDBY","scope":"ooxml_outer","entry":"docProps/core.xml","xpath":"cp:lastModifiedBy",
  "claim":"外层最后保存者","required_evidence":"core.xml 中 cp:lastModifiedBy 元素非空",
  "classification_if_absent":"unparsable"},
 {"id":"OUT-READONLY","scope":"ooxml_outer","entry":"word/settings.xml + docProps/custom.xml",
  "xpath":"w:documentProtection[@w:edit=readOnly] / custom _MarkAsFinal",
  "claim":"声称只供阅读/标记为最终","required_evidence":"settings.xml 只读保护或 custom.xml 标记最终属性，二者至少其一",
  "classification_if_absent":"packaging_only","note":"仅声明而无文档层强制时降级"},
 {"id":"OUT-APP","scope":"package_residue","entry":"docProps/app.xml","xpath":"Application/AppVersion",
  "claim":"生成应用与版本","required_evidence":"app.xml Application/AppVersion；属工具自报，非文档内容证据",
  "classification_if_absent":"packaging_only"},
 {"id":"OUT-GENRESIDUE","scope":"package_residue","entry":"docProps/generator-residue.txt","xpath":"文件存在",
  "claim":"打包/另存工具残留","required_evidence":"非 OPC 标准语义部件，仅证明打包工具经过",
  "classification_if_absent":"packaging_only"},
 {"id":"OLE-TITLE","scope":"ole_embedded","entry":"SummaryInformation PID 2","xpath":"PIDSI_TITLE",
  "claim":"内嵌材料标题","required_evidence":"内嵌 CFB 的 \\x05SummaryInformation 可被 olefile 解析且 PID2 有值",
  "classification_if_absent":"unparsable"},
 {"id":"OLE-AUTHOR","scope":"ole_embedded","entry":"SummaryInformation PID 4","xpath":"PIDSI_AUTHOR",
  "claim":"内嵌材料作者","required_evidence":"\\x05SummaryInformation PID4 有值","classification_if_absent":"unparsable"},
 {"id":"OLE-LASTSAVED","scope":"ole_embedded","entry":"SummaryInformation PID 18","xpath":"PIDSI_LASTSAVEDBY",
  "claim":"内嵌材料最后保存者","required_evidence":"\\x05SummaryInformation PID18 有值","classification_if_absent":"unparsable"},
 {"id":"OLE-COMPANY","scope":"ole_embedded","entry":"DocumentSummaryInformation PID 15","xpath":"PIDDSI_COMPANY",
  "claim":"内嵌材料单位","required_evidence":"\\x05DocumentSummaryInformation PID15 有值","classification_if_absent":"unparsable"},
 {"id":"OLE-PACKAGE","scope":"ole_embedded","entry":"CFB package/Ole10Native/CompObj 流",
  "xpath":"stream presence","claim":"独立内嵌载荷存在性","required_evidence":"CFB 内存在 package 或 Ole10Native 流且可读",
  "classification_if_absent":"unparsable"}
]
spec={"version":"1.0","attributes":attrs}
path=os.path.join(os.path.dirname(__file__),"audit_spec.json")
open(path,"w",encoding="utf-8").write(json.dumps(spec,ensure_ascii=False,indent=2))
print("wrote",path,len(attrs),"attributes")
