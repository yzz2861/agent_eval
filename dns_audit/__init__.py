"""离线 DNS 抓包核对工具。

只依赖 dpkt 做离线解析，按采集点（collection point）隔离证据，
把保存下来的问答组合成有限的名称/地址主张，并完整保留采集归属、
匹配依据与每条主张声称的有效范围，便于事后复查。
"""

from .model import (
    Claim,
    DnsMessage,
    Exchange,
    PacketRef,
    Question,
    ReadError,
    RR,
    Scope,
)

__all__ = [
    'Claim',
    'DnsMessage',
    'Exchange',
    'PacketRef',
    'Question',
    'ReadError',
    'RR',
    'Scope',
]
