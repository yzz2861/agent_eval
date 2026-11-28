# Python 后端安全评测题索引

2026 年 11 月 28 日上午批次。100 道题覆盖 25 个 Python 项目，困难 20 道，地狱 80 道。

| 题号 | 任务 | 初始快照 | 难度 |
| --- | --- | --- | --- |
| ds20261128-am-agent-eval-py-001 | 用 SBOM 准备撤回批次 | [sbom](https://github.com/yzz2861/agent_eval/commit/c4de5869fe108f6699f10f44db25b86de5095353) | 地狱 |
| ds20261128-am-agent-eval-py-002 | 给分批恢复做一致快照对账 | [tuf](https://github.com/yzz2861/agent_eval/commit/081c0b45cb817a251aface93b7e27d5303bb4297) | 地狱 |
| ds20261128-am-agent-eval-py-003 | 识别分批签收中的同源见证 | [intoto](https://github.com/yzz2861/agent_eval/commit/25740b30d883120fd8f17c4720325754d4d9a5cf) | 地狱 |
| ds20261128-am-agent-eval-py-004 | 识别审计时已标记的不同保管责任 | [detect-secrets](https://github.com/yzz2861/agent_eval/commit/390173c10e4a65ce7c45302cdf5323f705647aa7) | 困难 |
| ds20261128-am-agent-eval-py-005 | 审计自动检查的告警升级配额 | [bandit](https://github.com/yzz2861/agent_eval/commit/5287ab350cf7857871394efba480a5f2f8c26f66) | 地狱 |
| ds20261128-am-agent-eval-py-006 | 检测换班后告警的重复计数 | [sigma](https://github.com/yzz2861/agent_eval/commit/894082fc4f0208ab225d7996f1ff7b72073a4047) | 地狱 |
| ds20261128-am-agent-eval-py-007 | 计算离线注册表修改的可见范围 | [python-registry](https://github.com/yzz2861/agent_eval/commit/da1b6d1383bccfef424a1d5ffad9ba7e854c47ad) | 地狱 |
| ds20261128-am-agent-eval-py-008 | 把事件 XML 的证物导出成受控索引 | [python-evtx](https://github.com/yzz2861/agent_eval/commit/755df184315291740eb5d40ebe7558a37ead8abc) | 地狱 |
| ds20261128-am-agent-eval-py-009 | 识别例外控制流里实际未做完的安全检查 | [dlint](https://github.com/yzz2861/agent_eval/commit/30253a77f489f5935ceecd1f2acf4c187780879b) | 地狱 |
| ds20261128-am-agent-eval-py-010 | 对 PE 叠加区的原始留存声明进行独立验证 | [pefile](https://github.com/yzz2861/agent_eval/commit/478df89f273ac771ee39b04c09a84e844c25a0d0) | 地狱 |
| ds20261128-am-agent-eval-py-011 | 把共享调试类型的来源钉到可交接制品 | [pyelftools](https://github.com/yzz2861/agent_eval/commit/6ee04900bb7f4eb083d702b593bd8b821cca96ac) | 地狱 |
| ds20261128-am-agent-eval-py-012 | 核对程序集历史中的资源转交 | [dnfile](https://github.com/yzz2861/agent_eval/commit/d8cd2e454ada12ecb88dca4b19977cb68424f3b1) | 地狱 |
| ds20261128-am-agent-eval-py-013 | 把存储树根的存档权限传给流证据 | [olefile](https://github.com/yzz2861/agent_eval/commit/784bf7e89fc1fa7d2ed4fc089a7fae50ba4a3d12) | 地狱 |
| ds20261128-am-agent-eval-py-014 | 确认 PDF 档案分层声明互不冒充 | [pypdf](https://github.com/yzz2861/agent_eval/commit/3686e0dab1b22c2b080f990991b61265550f522f) | 地狱 |
| ds20261128-am-agent-eval-py-015 | 把尚未发布的纠正按受影响订阅方拆分 | [stix](https://github.com/yzz2861/agent_eval/commit/1d728a51ccd3b00e08f539e91f02738ea30a22cb) | 地狱 |
| ds20261128-am-agent-eval-py-016 | 确保可信 SAX 分派遵循字段用途合同 | [defusedxml](https://github.com/yzz2861/agent_eval/commit/04dd6a033df12e9d471c378619ab67bd836021b3) | 地狱 |
| ds20261128-am-agent-eval-py-017 | 为证书归档建立可重复的公开字段裁剪 | [asn1crypto](https://github.com/yzz2861/agent_eval/commit/b6068a92fa99d4ad0893a07654a7ac008cb42c29) | 地狱 |
| ds20261128-am-agent-eval-py-018 | 为隔离附件选最低成本的足够复核方案 | [filetype](https://github.com/yzz2861/agent_eval/commit/78554c95c446860896976e223ba027263ef190bc) | 地狱 |
| ds20261128-am-agent-eval-py-019 | 签收被裁剪的采集注释而保留责任归属 | [pcapng](https://github.com/yzz2861/agent_eval/commit/de3f7e77b482e1e013586cb54d9615f04c05ef26) | 地狱 |
| ds20261128-am-agent-eval-py-020 | 对结构证物的定点掩蔽保留验收依据 | [dissect-cstruct](https://github.com/yzz2861/agent_eval/commit/a9b2d1227839e526d1b4672c6e98e9f4dcbf7429) | 地狱 |
| ds20261128-am-agent-eval-py-021 | 核对保全查询为何只得到索引的一侧 | [dissect.database](https://github.com/yzz2861/agent_eval/commit/f9d15e6b7e3120f39f18d504063a82f1db592447) | 地狱 |
| ds20261128-am-agent-eval-py-022 | 重审被临时法律保留的证物到期与撤销记录 | [dfdatetime](https://github.com/yzz2861/agent_eval/commit/49323cee9a30c62a8c49ead14abcaef3c8790ba4) | 地狱 |
| ds20261128-am-agent-eval-py-023 | 核对不同资产层级对同一组件的风险承担 | [cpe](https://github.com/yzz2861/agent_eval/commit/21e80ae2238f56e45d58d5c2a2884eb330d935b3) | 地狱 |
| ds20261128-am-agent-eval-py-024 | 证明多方重复验证仍有独立的签收保障 | [signxml](https://github.com/yzz2861/agent_eval/commit/0a57444d4c23fb31d1e1db41d1881235f29490b0) | 地狱 |
| ds20261128-am-agent-eval-py-025 | 审核清洗政策合并时每个来源可保留的元素 | [html-sanitizer](https://github.com/yzz2861/agent_eval/commit/526ae9d4a3134b88599cf5e177807e0af72c8aba) | 地狱 |
| ds20261128-am-agent-eval-py-026 | 按供应商信任域封存许可及风险引用 | [sbom](https://github.com/yzz2861/agent_eval/commit/c4de5869fe108f6699f10f44db25b86de5095353) | 地狱 |
| ds20261128-am-agent-eval-py-027 | 冻结一次多目标验证的交接证据 | [tuf](https://github.com/yzz2861/agent_eval/commit/081c0b45cb817a251aface93b7e27d5303bb4297) | 困难 |
| ds20261128-am-agent-eval-py-028 | 按观察范围核对外包构建设备的交付单 | [intoto](https://github.com/yzz2861/agent_eval/commit/25740b30d883120fd8f17c4720325754d4d9a5cf) | 困难 |
| ds20261128-am-agent-eval-py-029 | 撤销过期审核豁免后自动补查 | [detect-secrets](https://github.com/yzz2861/agent_eval/commit/390173c10e4a65ce7c45302cdf5323f705647aa7) | 地狱 |
| ds20261128-am-agent-eval-py-030 | 给按来源治理的告警做证据有效期检查 | [bandit](https://github.com/yzz2861/agent_eval/commit/5287ab350cf7857871394efba480a5f2f8c26f66) | 困难 |
| ds20261128-am-agent-eval-py-031 | 评审管道处理优先级带来的安全规则漂移 | [sigma](https://github.com/yzz2861/agent_eval/commit/894082fc4f0208ab225d7996f1ff7b72073a4047) | 困难 |
| ds20261128-am-agent-eval-py-032 | 区分值不存在与历史版本断层 | [python-registry](https://github.com/yzz2861/agent_eval/commit/da1b6d1383bccfef424a1d5ffad9ba7e854c47ad) | 困难 |
| ds20261128-am-agent-eval-py-033 | 在离线调查中标出模板内容证明差异 | [python-evtx](https://github.com/yzz2861/agent_eval/commit/755df184315291740eb5d40ebe7558a37ead8abc) | 困难 |
| ds20261128-am-agent-eval-py-034 | 把语法版本引起的规则覆盖缺口暴露出来 | [dlint](https://github.com/yzz2861/agent_eval/commit/30253a77f489f5935ceecd1f2acf4c187780879b) | 困难 |
| ds20261128-am-agent-eval-py-035 | 判断静态依赖绑定能否解释历史交付记录 | [pefile](https://github.com/yzz2861/agent_eval/commit/478df89f273ac771ee39b04c09a84e844c25a0d0) | 地狱 |
| ds20261128-am-agent-eval-py-036 | 合并现场记录与展开规则的有效地址段 | [pyelftools](https://github.com/yzz2861/agent_eval/commit/6ee04900bb7f4eb083d702b593bd8b821cca96ac) | 困难 |
| ds20261128-am-agent-eval-py-037 | 对离线扫描清单核实元数据所有权 | [dnfile](https://github.com/yzz2861/agent_eval/commit/d8cd2e454ada12ecb88dca4b19977cb68424f3b1) | 困难 |
| ds20261128-am-agent-eval-py-038 | 比较保留摘要是否足以验证复合文档重新封存 | [olefile](https://github.com/yzz2861/agent_eval/commit/784bf7e89fc1fa7d2ed4fc089a7fae50ba4a3d12) | 地狱 |
| ds20261128-am-agent-eval-py-039 | 验证导出后文档修订仍满足可见范围承诺 | [pypdf](https://github.com/yzz2861/agent_eval/commit/3686e0dab1b22c2b080f990991b61265550f522f) | 困难 |
| ds20261128-am-agent-eval-py-040 | 限制情报等价判断跨组织的错误合并 | [stix](https://github.com/yzz2861/agent_eval/commit/1d728a51ccd3b00e08f539e91f02738ea30a22cb) | 困难 |
| ds20261128-am-agent-eval-py-041 | 验证解析适配器的防护承诺不会随版本丢失 | [defusedxml](https://github.com/yzz2861/agent_eval/commit/04dd6a033df12e9d471c378619ab67bd836021b3) | 困难 |
| ds20261128-am-agent-eval-py-042 | 核定回收时两类公开处置承诺的业务影响 | [asn1crypto](https://github.com/yzz2861/agent_eval/commit/b6068a92fa99d4ad0893a07654a7ac008cb42c29) | 地狱 |
| ds20261128-am-agent-eval-py-043 | 核准格式识别配置改动的隔离队列影响 | [filetype](https://github.com/yzz2861/agent_eval/commit/78554c95c446860896976e223ba027263ef190bc) | 困难 |
| ds20261128-am-agent-eval-py-044 | 给未知采集块的独立抽样开证物回执 | [pcapng](https://github.com/yzz2861/agent_eval/commit/de3f7e77b482e1e013586cb54d9615f04c05ef26) | 困难 |
| ds20261128-am-agent-eval-py-045 | 给二进制结构的联合类型采样建立可复验归属 | [dissect-cstruct](https://github.com/yzz2861/agent_eval/commit/a9b2d1227839e526d1b4672c6e98e9f4dcbf7429) | 地狱 |
| ds20261128-am-agent-eval-py-046 | 为 ESE 的空列记录加明确的保留证明 | [dissect.database](https://github.com/yzz2861/agent_eval/commit/f9d15e6b7e3120f39f18d504063a82f1db592447) | 困难 |
| ds20261128-am-agent-eval-py-047 | 按最低集体披露约束发布事故时间统计 | [dfdatetime](https://github.com/yzz2861/agent_eval/commit/49323cee9a30c62a8c49ead14abcaef3c8790ba4) | 地狱 |
| ds20261128-am-agent-eval-py-048 | 保留会影响风险分派的格式迁移差异 | [cpe](https://github.com/yzz2861/agent_eval/commit/21e80ae2238f56e45d58d5c2a2884eb330d935b3) | 困难 |
| ds20261128-am-agent-eval-py-049 | 验证签收端升级不会放宽批准的算法组合 | [signxml](https://github.com/yzz2861/agent_eval/commit/0a57444d4c23fb31d1e1db41d1881235f29490b0) | 困难 |
| ds20261128-am-agent-eval-py-050 | 证明安全清洗后的受控字段没有经摘要暴露 | [html-sanitizer](https://github.com/yzz2861/agent_eval/commit/526ae9d4a3134b88599cf5e177807e0af72c8aba) | 地狱 |
| ds20261128-am-agent-eval-py-051 | 给生命周期安全声明做增量回归 | [sbom](https://github.com/yzz2861/agent_eval/commit/c4de5869fe108f6699f10f44db25b86de5095353) | 困难 |
| ds20261128-am-agent-eval-py-052 | 检查轮换审批是否存在不可满足的先决条件 | [tuf](https://github.com/yzz2861/agent_eval/commit/081c0b45cb817a251aface93b7e27d5303bb4297) | 地狱 |
| ds20261128-am-agent-eval-py-053 | 核对分批物料的时序是否满足构建合约 | [intoto](https://github.com/yzz2861/agent_eval/commit/25740b30d883120fd8f17c4720325754d4d9a5cf) | 地狱 |
| ds20261128-am-agent-eval-py-054 | 按文本来源约束共享扫描结论 | [detect-secrets](https://github.com/yzz2861/agent_eval/commit/390173c10e4a65ce7c45302cdf5323f705647aa7) | 地狱 |
| ds20261128-am-agent-eval-py-055 | 找出安全检查配置的覆盖退化 | [bandit](https://github.com/yzz2861/agent_eval/commit/5287ab350cf7857871394efba480a5f2f8c26f66) | 地狱 |
| ds20261128-am-agent-eval-py-056 | 把规则并行试运行的分歧分给对的维护方 | [sigma](https://github.com/yzz2861/agent_eval/commit/894082fc4f0208ab225d7996f1ff7b72073a4047) | 地狱 |
| ds20261128-am-agent-eval-py-057 | 以本地变更窗口审计键时钟异常 | [python-registry](https://github.com/yzz2861/agent_eval/commit/da1b6d1383bccfef424a1d5ffad9ba7e854c47ad) | 地狱 |
| ds20261128-am-agent-eval-py-058 | 按调查保留规则核定归档缺口 | [python-evtx](https://github.com/yzz2861/agent_eval/commit/755df184315291740eb5d40ebe7558a37ead8abc) | 地狱 |
| ds20261128-am-agent-eval-py-059 | 限定审计规则配置的豁免传递范围 | [dlint](https://github.com/yzz2861/agent_eval/commit/30253a77f489f5935ceecd1f2acf4c187780879b) | 地狱 |
| ds20261128-am-agent-eval-py-060 | 解释异常处理目录对现场函数归属的影响 | [pefile](https://github.com/yzz2861/agent_eval/commit/478df89f273ac771ee39b04c09a84e844c25a0d0) | 地狱 |
| ds20261128-am-agent-eval-py-061 | 验证证物改版是否影响原调查的重定位解释 | [pyelftools](https://github.com/yzz2861/agent_eval/commit/6ee04900bb7f4eb083d702b593bd8b821cca96ac) | 地狱 |
| ds20261128-am-agent-eval-py-062 | 给已撤回 API 的公开常量作独立复盘 | [dnfile](https://github.com/yzz2861/agent_eval/commit/d8cd2e454ada12ecb88dca4b19977cb68424f3b1) | 地狱 |
| ds20261128-am-agent-eval-py-063 | 把复合文档截取范围翻译成独立证物图 | [olefile](https://github.com/yzz2861/agent_eval/commit/784bf7e89fc1fa7d2ed4fc089a7fae50ba4a3d12) | 地狱 |
| ds20261128-am-agent-eval-py-064 | 校验页提取前后能否复算证物坐标 | [pypdf](https://github.com/yzz2861/agent_eval/commit/3686e0dab1b22c2b080f990991b61265550f522f) | 地狱 |
| ds20261128-am-agent-eval-py-065 | 为证据等级有分歧的情报保留裁决过程 | [stix](https://github.com/yzz2861/agent_eval/commit/1d728a51ccd3b00e08f539e91f02738ea30a22cb) | 地狱 |
| ds20261128-am-agent-eval-py-066 | 隔离长期服务中不同请求的解析保护上下文 | [defusedxml](https://github.com/yzz2861/agent_eval/commit/04dd6a033df12e9d471c378619ab67bd836021b3) | 地狱 |
| ds20261128-am-agent-eval-py-067 | 校对多方签后附注是否属于原件的证物 | [asn1crypto](https://github.com/yzz2861/agent_eval/commit/b6068a92fa99d4ad0893a07654a7ac008cb42c29) | 困难 |
| ds20261128-am-agent-eval-py-068 | 联结准入结论与实际转交给解析器的对象身份 | [filetype](https://github.com/yzz2861/agent_eval/commit/78554c95c446860896976e223ba027263ef190bc) | 地狱 |
| ds20261128-am-agent-eval-py-069 | 按小份取证需求封装独立可读的采集摘录 | [pcapng](https://github.com/yzz2861/agent_eval/commit/de3f7e77b482e1e013586cb54d9615f04c05ef26) | 地狱 |
| ds20261128-am-agent-eval-py-070 | 用合法有限样本审查两种解码路径的防护契约 | [dissect-cstruct](https://github.com/yzz2861/agent_eval/commit/a9b2d1227839e526d1b4672c6e98e9f4dcbf7429) | 地狱 |
| ds20261128-am-agent-eval-py-071 | 重算取证请求只允许交付的 bbolt 键名范围 | [dissect.database](https://github.com/yzz2861/agent_eval/commit/f9d15e6b7e3120f39f18d504063a82f1db592447) | 地狱 |
| ds20261128-am-agent-eval-py-072 | 核对证物里呈现的某些时间值是否可以合法往返 | [dfdatetime](https://github.com/yzz2861/agent_eval/commit/49323cee9a30c62a8c49ead14abcaef3c8790ba4) | 地狱 |
| ds20261128-am-agent-eval-py-073 | 审查公开风险通知里的资产身份脱敏 | [cpe](https://github.com/yzz2861/agent_eval/commit/21e80ae2238f56e45d58d5c2a2884eb330d935b3) | 地狱 |
| ds20261128-am-agent-eval-py-074 | 核对签收回执对签名引用覆盖的陈述 | [signxml](https://github.com/yzz2861/agent_eval/commit/0a57444d4c23fb31d1e1db41d1881235f29490b0) | 地狱 |
| ds20261128-am-agent-eval-py-075 | 从可审阅清洗方案中选够用的最小放行范围 | [html-sanitizer](https://github.com/yzz2861/agent_eval/commit/526ae9d4a3134b88599cf5e177807e0af72c8aba) | 地狱 |
| ds20261128-am-agent-eval-py-076 | 将量化的复查资源分给风险依赖 | [sbom](https://github.com/yzz2861/agent_eval/commit/c4de5869fe108f6699f10f44db25b86de5095353) | 地狱 |
| ds20261128-am-agent-eval-py-077 | 给元数据归档格式迁移加一次无损检查 | [tuf](https://github.com/yzz2861/agent_eval/commit/081c0b45cb817a251aface93b7e27d5303bb4297) | 地狱 |
| ds20261128-am-agent-eval-py-078 | 在重试发布时保住已签收产物的处置顺序 | [intoto](https://github.com/yzz2861/agent_eval/commit/25740b30d883120fd8f17c4720325754d4d9a5cf) | 地狱 |
| ds20261128-am-agent-eval-py-079 | 验证旧扫描基线的合成哨兵结果满足防回归约定 | [detect-secrets](https://github.com/yzz2861/agent_eval/commit/390173c10e4a65ce7c45302cdf5323f705647aa7) | 地狱 |
| ds20261128-am-agent-eval-py-080 | 检验两种报告格式承载的审核语义完全相同 | [bandit](https://github.com/yzz2861/agent_eval/commit/5287ab350cf7857871394efba480a5f2f8c26f66) | 地狱 |
| ds20261128-am-agent-eval-py-081 | 用事件保留约束分配合规检测窗口 | [sigma](https://github.com/yzz2861/agent_eval/commit/894082fc4f0208ab225d7996f1ff7b72073a4047) | 地狱 |
| ds20261128-am-agent-eval-py-082 | 比较环境配置档案的独立保全分层 | [python-registry](https://github.com/yzz2861/agent_eval/commit/da1b6d1383bccfef424a1d5ffad9ba7e854c47ad) | 地狱 |
| ds20261128-am-agent-eval-py-083 | 跨多份事件文件归因有矛盾的采集声明 | [python-evtx](https://github.com/yzz2861/agent_eval/commit/755df184315291740eb5d40ebe7558a37ead8abc) | 地狱 |
| ds20261128-am-agent-eval-py-084 | 跨文件交接静态审阅覆盖责任 | [dlint](https://github.com/yzz2861/agent_eval/commit/30253a77f489f5935ceecd1f2acf4c187780879b) | 地狱 |
| ds20261128-am-agent-eval-py-085 | 量化分片取证对签名摘要的覆盖贡献 | [pefile](https://github.com/yzz2861/agent_eval/commit/478df89f273ac771ee39b04c09a84e844c25a0d0) | 地狱 |
| ds20261128-am-agent-eval-py-086 | 核验核心摘录里的身份备注有何保全资格 | [pyelftools](https://github.com/yzz2861/agent_eval/commit/6ee04900bb7f4eb083d702b593bd8b821cca96ac) | 地狱 |
| ds20261128-am-agent-eval-py-087 | 让程序集重建前后的类型关系可核对 | [dnfile](https://github.com/yzz2861/agent_eval/commit/d8cd2e454ada12ecb88dca4b19977cb68424f3b1) | 地狱 |
| ds20261128-am-agent-eval-py-088 | 隔离不完整复合文档的取证读取状态 | [olefile](https://github.com/yzz2861/agent_eval/commit/784bf7e89fc1fa7d2ed4fc089a7fae50ba4a3d12) | 地狱 |
| ds20261128-am-agent-eval-py-089 | 在文档审阅分流时保护各自的读取配额 | [pypdf](https://github.com/yzz2861/agent_eval/commit/3686e0dab1b22c2b080f990991b61265550f522f) | 地狱 |
| ds20261128-am-agent-eval-py-090 | 复核情报打包前后的对象身份 | [stix](https://github.com/yzz2861/agent_eval/commit/1d728a51ccd3b00e08f539e91f02738ea30a22cb) | 地狱 |
| ds20261128-am-agent-eval-py-091 | 检验已脱敏 XML 的退出清单能否复算 | [defusedxml](https://github.com/yzz2861/agent_eval/commit/04dd6a033df12e9d471c378619ab67bd836021b3) | 地狱 |
| ds20261128-am-agent-eval-py-092 | 审阅跨版本密码算法政策的历史解读 | [asn1crypto](https://github.com/yzz2861/agent_eval/commit/b6068a92fa99d4ad0893a07654a7ac008cb42c29) | 地狱 |
| ds20261128-am-agent-eval-py-093 | 在格式目录收紧后核实库存为何仍允许开放 | [filetype](https://github.com/yzz2861/agent_eval/commit/78554c95c446860896976e223ba027263ef190bc) | 地狱 |
| ds20261128-am-agent-eval-py-094 | 说明携带同一帧的不同装载记录如何归账 | [pcapng](https://github.com/yzz2861/agent_eval/commit/de3f7e77b482e1e013586cb54d9615f04c05ef26) | 地狱 |
| ds20261128-am-agent-eval-py-095 | 核算两个相邻归档的结构化可见边界 | [dissect-cstruct](https://github.com/yzz2861/agent_eval/commit/a9b2d1227839e526d1b4672c6e98e9f4dcbf7429) | 地狱 |
| ds20261128-am-agent-eval-py-096 | 交叉核验两类数据库副本对同一观察的证物表示 | [dissect.database](https://github.com/yzz2861/agent_eval/commit/f9d15e6b7e3120f39f18d504063a82f1db592447) | 地狱 |
| ds20261128-am-agent-eval-py-097 | 在搜索案件时间区间时区分缺时点与时间碰撞 | [dfdatetime](https://github.com/yzz2861/agent_eval/commit/49323cee9a30c62a8c49ead14abcaef3c8790ba4) | 地狱 |
| ds20261128-am-agent-eval-py-098 | 核验多通告重复引发的处置扣减 | [cpe](https://github.com/yzz2861/agent_eval/commit/21e80ae2238f56e45d58d5c2a2884eb330d935b3) | 地狱 |
| ds20261128-am-agent-eval-py-099 | 规范已验证文档的纠错回执序列 | [signxml](https://github.com/yzz2861/agent_eval/commit/0a57444d4c23fb31d1e1db41d1881235f29490b0) | 地狱 |
| ds20261128-am-agent-eval-py-100 | 校对多语发布是否保留必要的安全标签 | [html-sanitizer](https://github.com/yzz2861/agent_eval/commit/526ae9d4a3134b88599cf5e177807e0af72c8aba) | 地狱 |
