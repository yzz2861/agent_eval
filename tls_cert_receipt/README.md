# TLS 证书观察回执（dpkt）

针对"维护后服务器是否仍在用旧证书"的争议：用 dpkt 解析本地 TLS
测试抓包，输出**证书观察回执**——引用实际读到证书的握手报文、
连接边界（SYN/FIN 帧号与起止时间）、采集时间范围，再与维护方提供
的新旧证书摘要和假定维护窗口核对，给出逐条可对回帧号的结论。

## 组成

- \`make_pcaps.py\` — 生成合成测试材料：
  - \`certs/old.der\` / \`certs/new.der\`（openssl 自签的新旧证书）
  - \`pcaps/A_missed_cert.pcap\` — 抓包只存到握手前半截，Certificate
    记录被截断，传感器漏掉证书
  - \`pcaps/B_old_cert.pcap\` — 完整握手，出示旧证书（跨两个 TCP 段）
  - \`pcaps/C_new_cert.pcap\` — 完整握手，出示新证书
  - \`maintenance.json\` — 假定维护窗口 + 新旧证书 SHA-256 摘要
  - \`manifest.json\` — 各场景期望结论与证据帧号（供测试核对）
- \`receipt.py\` — 分析器与复核器
- \`test_receipt.py\` — 三种场景的端到端复核测试

## 用法

    PYTHONPATH=$PWD python3 tls_cert_receipt/make_pcaps.py
    python3 tls_cert_receipt/receipt.py analyze tls_cert_receipt/pcaps/B_old_cert.pcap \
        --maintenance tls_cert_receipt/maintenance.json -o receipt.json
    python3 tls_cert_receipt/receipt.py review receipt.json ...

注意：需用系统 \`python3\` 并把仓库根目录放进 \`PYTHONPATH\`（本目录的
\`.venv\` 是指向沙箱外路径的 editable 安装，不可用）。

## 判定逻辑

| 结论 | 含义 |
| --- | --- |
| INCONCLUSIVE_NO_CERT | 未观察到证书（如抓包截断），既不能证明也不能反驳 |
| ALERT_OLD_CERT_AFTER_WINDOW | 窗口结束后仍出示与旧摘要一致的证书，支持"仍在用旧证书" |
| OK_NEW_CERT_AFTER_WINDOW | 窗口结束后出示新证书，换证生效 |
| OLD_CERT_BEFORE_WINDOW_END / NEW_CERT_BEFORE_WINDOW_END | 窗口关闭前的观察，属换证期正常 |
| UNKNOWN_CERT | 指纹与新旧摘要均不符 |

## 测试

    cd tls_cert_receipt && python3 -m pytest test_receipt.py -q

