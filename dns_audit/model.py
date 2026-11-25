"""核心数据模型：每条记录都带可复查的采集归属与证据指针。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# DNS 常用 RR 类型（dpkt 只提供整数常量，这里补名字）
QTYPE_NAMES = {
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    12: 'PTR',
    15: 'MX',
    16: 'TXT',
    28: 'AAAA',
    33: 'SRV',
    41: 'OPT',
    255: 'ANY',
}

RCODE_NAMES = {
    0: 'NOERROR',
    1: 'FORMERR',
    2: 'SERVFAIL',
    3: 'NXDOMAIN',
    4: 'NOTIMP',
    5: 'REFUSED',
}

# 问答匹配依据 / 状态
MATCH_UNIQUE = 'unique'          # 同采集点内唯一命中
MATCH_AMBIGUOUS = 'ambiguous'    # 同采集点内多个候选，无法排除
MATCH_ORPHAN = 'orphan_response'  # 同采集点内找不到候选问题
MATCH_UNANSWERED = 'unanswered'   # 同采集点内没有等到回答

# 主张种类
CLAIM_ADDRESS = 'address'
CLAIM_ALIAS = 'alias'
CLAIM_NEGATIVE = 'negative'


def qtype_name(qtype: int) -> str:
    return QTYPE_NAMES.get(qtype, 'TYPE%d' % qtype)


def rcode_name(rcode: int) -> str:
    return RCODE_NAMES.get(rcode, 'RCODE%d' % rcode)


@dataclass(frozen=True)
class PacketRef:
    """指向某个 pcap 文件中的具体帧。"""

    source: str          # 输入路径或来源标签
    site: str            # 采集点标识
    frame_index: int     # 从 0 开始的帧序号
    timestamp: float     # 抓包时间戳（秒）


@dataclass(frozen=True)
class Question:
    """DNS 问题段中的一个问题。"""

    name: str
    qtype: int
    qclass: int

    def key(self) -> Tuple[str, int, int]:
        return self.name.lower(), self.qtype, self.qclass


@dataclass(frozen=True)
class RR:
    """资源记录的离线摘要，仅保留核对所需字段。"""

    name: str
    rtype: int
    rclass: int
    ttl: int
    # A/AAAA 时为文本地址；CNAME 时为目标名；其余类型为 None
    value: Optional[str] = None


@dataclass(frozen=True)
class DnsMessage:
    """一帧 UDP/53 DNS 报文的离线摘要。"""

    ref: PacketRef
    txid: int
    is_response: bool
    rcode: int
    qr_names: Tuple[str, ...]
    questions: Tuple[Question, ...]
    answers: Tuple[RR, ...]
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    truncated: bool


@dataclass(frozen=True)
class ReadError:
    """无法解析的帧也保留下来，方便人工复查。"""

    ref: PacketRef
    reason: str


@dataclass(frozen=True)
class Scope:
    """一条主张声称的有效范围。

    observed_first/last 是抓包实际看到该回答的时间窗（经验范围）；
    ttl_until 是按回答内 TTL 外推的到期时间，外推不等于后续观测。
    """

    site: str
    observed_first: float
    observed_last: float
    ttl_until: Optional[float]
    truncated: bool


@dataclass(frozen=True)
class Claim:
    """从一条已匹配回答中提取的有限主张。"""

    kind: str                       # address / alias / negative
    site: str
    name: str                       # 主张所指名称（小写）
    qtype: Optional[int]            # negative 时记录查询类型，其余为 RR 类型
    value: Optional[str]            # 地址、别名目标；negative 时为 None
    rcode: Optional[int]            # negative 时的响应码
    scope: Scope
    exchange_index: int             # 指向 Audit.exchanges 中的证据
    response_ref: PacketRef
    query_ref: PacketRef


@dataclass(frozen=True)
class Exchange:
    """同一采集点内一次问答配对（或配对失败）的完整记录。"""

    site: str
    txid: int
    status: str                     # unique / ambiguous / orphan_response / unanswered
    match_basis: Tuple[str, ...]    # 匹配依据，逐条列出
    candidates: Tuple[PacketRef, ...] = field(default_factory=tuple)
    query: Optional[DnsMessage] = None
    response: Optional[DnsMessage] = None


@dataclass
class CaptureResult:
    """单个来源文件的读取结果。"""

    source: str
    site: str
    messages: List[DnsMessage] = field(default_factory=list)
    read_errors: List[ReadError] = field(default_factory=list)
