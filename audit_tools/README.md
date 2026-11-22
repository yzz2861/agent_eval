# 离线分层核对方法说明（不打开 Office）

## 目标
对“另存”得到的 Office 档案，按真实文档层区分：哪些说明有可确认的内容证据，哪些只是打包/另存工具留下的痕迹，并记录原属性作用域、独立内嵌材料与无法解析的部分。

## 两个文档层（作用域严格隔离，互不覆盖）
- ooxml_outer：外层 OOXML（ZIP/OPC）。结构入口为 docProps/core.xml、docProps/app.xml、docProps/custom.xml、word/settings.xml，以及 word/embeddings/*.bin 的关系登记。
- ole_embedded：word/embeddings/*.bin 是独立 CFB（复合二进制）。入口为 \\x05SummaryInformation（SI）、\\x05DocumentSummaryInformation（DSI）、\\x01CompObj、package/Ole10Native 流，使用 olefile 读取 OLE 属性。
- package_residue：打包工具自报或非语义部件（app.xml 的 Application/AppVersion、generator-residue.txt），无文档层语义内容支撑。

## 判定口径
- supported：在该作用域的指定结构入口中找到非空、可解析的支持证据。
- packaging_only：仅工具自报/残留，缺少文档层语义证据。
- unparsable：部件缺失、签名不是 CFB（魔数 D0CF11E0…）或 olefile 无法打开，无法确认内容。
内层 CFB 独立解析，外层“只供阅读/标记最终”声称不会覆盖或改写内层 SI/DSI 说明，反之亦然。

## 文件清单
- cfb.py：纯 Python 最小 CFB 写入器（头部/FAT/DIFAT/MiniFAT/目录/SI/DSI/CompObj），不依赖 Office。
- ooxml.py：OOXML docx 包构建器（core/app/custom/settings/关系/Content_Types/embeddings）。
- make_fixtures.py：生成三类夹具到 fixtures/。
- gen_spec.py：生成调用方审核规格 audit_spec.json（属性→作用域→必需证据）。
- offline_audit.py：离线核对器，输出 reports/audit_report.json。
- render_report.py：渲染人类可读 reports/audit_report.md。
- verify_isolation.py：断言正常嵌入夹具中外层声称与内层说明并存且互不覆盖。

## 夹具（fixtures/）
- normal_embedded.docx：正常嵌入。外层标记只读；内层 CFB 含独立 SI/DSI 说明与 package 载荷，二者值不同。
- packaging_only.docx：内嵌仅 Ole10Native/CompObj 包装，无 SI/DSI 文档层说明，体现打包痕迹。
- unparsable_embed.docx：内嵌魔数被破坏，CFB 无法解析，相关属性判 unparsable。

## 复现步骤
1. python audit_tools/make_fixtures.py
2. python audit_tools/offline_audit.py
3. python audit_tools/render_report.py
4. python audit_tools/verify_isolation.py

## 交叉验证
oletools 的 ooxml.XmlParser 接受全部夹具为合法 OOXML；oleobj.find_ole 在两个有效 CFB 上各检出 1 个嵌入对象，在损坏夹具上检出 0，与本核对器的 unparsable 判定一致。
