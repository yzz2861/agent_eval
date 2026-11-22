# 离线分层核对报告

本报告仅基于 OLE 属性（olefile）与 OOXML 结构入口离线生成，未打开任何 Office 应用。

## normal_embedded.docx
ZIP/OPC 容器可解析：是
- 内嵌 `word/embeddings/oleObject1.bin`：CFB 可解析=True；签名正确=True；错误=None

| 属性 | 作用域 | 判定 | 支持证据 | 观测值 |
|---|---|---|---|---|
| OUT-CREATOR | ooxml_outer | supported | docProps/core.xml dc:creator | Outer Reviewer |
| OUT-MODIFIEDBY | ooxml_outer | supported | docProps/core.xml cp:lastModifiedBy | Outer SaveAs Tool |
| OUT-READONLY | ooxml_outer | supported | settings.xml:documentProtection@edit=readOnly; custom.xml:ReadModeEnforced; custom.xml:_MarkAsFinal | True |
| OUT-APP | package_residue | packaging_only | docProps/app.xml self-reported tool | ['Contoso SaveAs Converter', '7.0'] |
| OUT-GENRESIDUE | package_residue | packaging_only | non-semantic residue part | ['docProps/generator-residue.txt'] |
| OLE-TITLE | ole_embedded | supported | CFB property SI:2 | Inner Evidence Title |
| OLE-AUTHOR | ole_embedded | supported | CFB property SI:4 | Inner Evidence Author |
| OLE-LASTSAVED | ole_embedded | supported | CFB property SI:18 | Inner Saved By |
| OLE-COMPANY | ole_embedded | supported | CFB property DSI:15 | Inner Org Company |
| OLE-PACKAGE | ole_embedded | supported | package/Ole10Native stream | ['\\x01CompObj', '\\x05DocumentSummaryInformation', '\\x05SummaryInformation', 'package'] |

## packaging_only.docx
ZIP/OPC 容器可解析：是
- 内嵌 `word/embeddings/oleObject1.bin`：CFB 可解析=True；签名正确=True；错误=None

| 属性 | 作用域 | 判定 | 支持证据 | 观测值 |
|---|---|---|---|---|
| OUT-CREATOR | ooxml_outer | unparsable | docProps/core.xml dc:creator | - |
| OUT-MODIFIEDBY | ooxml_outer | supported | docProps/core.xml cp:lastModifiedBy | SaveAs Converter |
| OUT-READONLY | ooxml_outer | supported | settings.xml:documentProtection@edit=readOnly; custom.xml:ReadModeEnforced | True |
| OUT-APP | package_residue | packaging_only | docProps/app.xml self-reported tool | ['Contoso SaveAs Converter', '7.0'] |
| OUT-GENRESIDUE | package_residue | packaging_only | non-semantic residue part | ['docProps/generator-residue.txt'] |
| OLE-TITLE | ole_embedded | unparsable | CFB property SI:2 | - |
| OLE-AUTHOR | ole_embedded | unparsable | CFB property SI:4 | - |
| OLE-LASTSAVED | ole_embedded | unparsable | CFB property SI:18 | - |
| OLE-COMPANY | ole_embedded | unparsable | CFB property DSI:15 | - |
| OLE-PACKAGE | ole_embedded | supported | package/Ole10Native stream | ['\x01CompObj', 'Ole10Native'] |

## unparsable_embed.docx
ZIP/OPC 容器可解析：是
- 内嵌 `word/embeddings/oleObject1.bin`：CFB 可解析=False；签名正确=False；错误=not_a_compound_file_signature

| 属性 | 作用域 | 判定 | 支持证据 | 观测值 |
|---|---|---|---|---|
| OUT-CREATOR | ooxml_outer | supported | docProps/core.xml dc:creator | Outer Reviewer |
| OUT-MODIFIEDBY | ooxml_outer | supported | docProps/core.xml cp:lastModifiedBy | Outer SaveAs Tool |
| OUT-READONLY | ooxml_outer | supported | settings.xml:documentProtection@edit=readOnly; custom.xml:_MarkAsFinal | True |
| OUT-APP | package_residue | packaging_only | docProps/app.xml self-reported tool | ['Contoso SaveAs Converter', '7.0'] |
| OUT-GENRESIDUE | package_residue | unparsable | non-semantic residue part | [] |
| OLE-TITLE | ole_embedded | unparsable | not_a_compound_file_signature | - |
| OLE-AUTHOR | ole_embedded | unparsable | not_a_compound_file_signature | - |
| OLE-LASTSAVED | ole_embedded | unparsable | not_a_compound_file_signature | - |
| OLE-COMPANY | ole_embedded | unparsable | not_a_compound_file_signature | - |
| OLE-PACKAGE | ole_embedded | unparsable | not_a_compound_file_signature | - |
