"""命令行入口：把多个 (pcap, 采集点) 组合成一份可复查报告。

用法示例::

    python -m dns_audit.cli \\
        --capture site_a=a.pcap --capture site_b=b.pcap --report text
"""
from __future__ import annotations

import argparse
import json
from typing import List, Tuple

from .audit import Audit
from .demo import build_demo_audit
from .model import qtype_name, rcode_name


def _parse_capture(spec: str) -> Tuple[str, str]:
    if '=' not in spec:
        raise argparse.ArgumentTypeError(
            '--capture 需要 site=path 形式，收到: %r' % spec
        )
    site, path = spec.split('=', 1)
    site, path = site.strip(), path.strip()
    if not site or not path:
        raise argparse.ArgumentTypeError('--capture 的站点名与路径都不能为空')
    return path, site


def _fmt_ts(value) -> str:
    if value is None:
        return '-'
    return '%.3f' % value


def render_text(audit: Audit) -> str:
    lines: List[str] = []
    lines.append('DNS 离线核对报告（证据按采集点隔离，结论仅限观察窗）')
    lines.append('=' * 56)

    lines.append('\n[1] 采集归属')
    for capture in audit.captures:
        lines.append(
            '  - 采集点 %s：%s，DNS 报文 %d 帧，读取异常 %d 条'
            % (capture.site, capture.source, len(capture.messages), len(capture.read_errors))
        )
        for error in capture.read_errors:
            lines.append(
                '      * 帧 %d 解析失败：%s' % (error.ref.frame_index, error.reason)
            )

    collisions = audit.matching.cross_site_txid_collisions
    lines.append('\n[2] 跨采集点同号（txid）清单——只提示，绝不跨点配对')
    if not collisions:
        lines.append('  - 未发现跨采集点复用的 txid')
    for item in collisions:
        lines.append(
            '  - txid 0x%04x 出现在采集点 %s，同号不等于同一事务'
            % (item['txid'], ', '.join(item['sites']))
        )

    lines.append('\n[3] 问答配对与匹配依据')
    for exchange in audit.exchanges:
        lines.append(
            '  - 站点=%s txid=0x%04x 状态=%s 依据=[%s]'
            % (
                exchange.site,
                exchange.txid,
                exchange.status,
                ', '.join(exchange.match_basis),
            )
        )
        if exchange.query is not None:
            lines.append(
                '      问题帧 #%d @%.3f: %s'
                % (
                    exchange.query.ref.frame_index,
                    exchange.query.ref.timestamp,
                    '; '.join(
                        '%s %s' % (q.name, qtype_name(q.qtype))
                        for q in exchange.query.questions
                    ),
                )
            )
        if exchange.response is not None:
            lines.append(
                '      回答帧 #%d @%.3f rcode=%s'
                % (
                    exchange.response.ref.frame_index,
                    exchange.response.ref.timestamp,
                    rcode_name(exchange.response.rcode),
                )
            )
        if exchange.candidates and exchange.status != 'unique':
            lines.append(
                '      候选问题帧: %s（无法排除，保留复查）'
                % ', '.join('#%d' % ref.frame_index for ref in exchange.candidates)
            )

    lines.append('\n[4] 有限的名称/地址主张（含声称的有效范围）')
    for index, claim in enumerate(audit.claims):
        scope = claim.scope
        if claim.kind == 'negative':
            body = '%s %s -> 否定回答 rcode=%s' % (
                claim.name,
                qtype_name(claim.qtype),
                rcode_name(claim.rcode),
            )
        elif claim.kind == 'alias':
            body = '%s CNAME -> %s' % (claim.name, claim.value)
        else:
            body = '%s %s -> %s' % (
                claim.name,
                qtype_name(claim.qtype),
                claim.value,
            )
        lines.append(
            '  #%d [站点=%s] %s | 观察窗 %s~%s TTL外推至 %s 截断=%s | 证据 问题帧#%d 回答帧#%d'
            % (
                index,
                claim.site,
                body,
                _fmt_ts(scope.observed_first),
                _fmt_ts(scope.observed_last),
                _fmt_ts(scope.ttl_until),
                scope.truncated,
                claim.query_ref.frame_index,
                claim.response_ref.frame_index,
            )
        )

    lines.append('\n[5] 离线别名观察（不完整链显式标注）')
    if not audit.alias_traces:
        lines.append('  - 未观察到 CNAME 链')
    for trace in audit.alias_traces:
        chain = ' -> '.join(
            [trace.start_name] + [hop.target_name for hop in trace.hops]
        )
        lines.append(
            '  - [站点=%s] %s | 终点地址=%s | 完整=%s'
            % (
                trace.site,
                chain,
                ', '.join(trace.terminal_addresses) or '-',
                trace.complete,
            )
        )
        for reason in trace.incomplete_reasons:
            lines.append('      * %s' % reason)

    lines.append('\n[6] 同址核对（仅同采集点、仅观察窗内）')
    if not audit.comparisons:
        lines.append('  - 同一采集点内没有可两两比较的名称')
    for comparison in audit.comparisons:
        lines.append(
            '  - [站点=%s] %s vs %s : 地址集合一致=%s'
            % (comparison.site, comparison.name_a, comparison.name_b, comparison.equal)
        )
        lines.append('      %s' % comparison.note)
        lines.append(
            '      A=%s | B=%s'
            % (
                ', '.join(sorted(comparison.addresses_a)) or '-',
                ', '.join(sorted(comparison.addresses_b)) or '-',
            )
        )
    return '\n'.join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='基于 dpkt 的离线 DNS 问答核对（按采集点隔离证据）'
    )
    parser.add_argument(
        '--capture',
        action='append',
        type=_parse_capture,
        metavar='SITE=PATH',
        help='采集点与 pcap 路径的绑定，可重复指定',
    )
    parser.add_argument(
        '--demo',
        action='store_true',
        help='运行内置内存样例（跨采集点同号、多候选与断链）',
    )
    parser.add_argument(
        '--report',
        choices=('text', 'json'),
        default='text',
        help='报告格式，默认 text',
    )
    parser.add_argument(
        '--output',
        default=None,
        help='报告输出路径，缺省打印到标准输出',
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.demo:
        audit = build_demo_audit()
    else:
        if not args.capture:
            parser.error('需要 --capture SITE=PATH，或使用 --demo')
        audit = Audit.from_sources(args.capture)
    if args.report == 'json':
        payload = json.dumps(audit.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
    else:
        payload = render_text(audit)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as handle:
            handle.write(payload + '\n')
    else:
        print(payload)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
