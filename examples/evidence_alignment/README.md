# 回拨时钟与残缺 chunk 对齐示例

这组小文件不把 Windows 时间戳当作默认定序键，而是合并三类证据：

- record_numbers.json：记录编号约束；
- signed_shift_markers.json：已签夜班交接标记，以及本地 01:40 在秋令时回拨中的两个候选锚点；
- file_relative_order.json：残缺 chunk 中仍然可见的文件相对顺序。

运行：

~~~bash
.venv/bin/python examples/evidence_alignment/demo.py
# 或
.venv/bin/python -m evtx_scripts.evtx_align_evidence examples/evidence_alignment
~~~

输出中的两个候选时间序为：

1. fold-0/EDT：交接标记位于 door-02 与 batch 之间；
2. fold-1/EST：交接标记位于 usb 与 stop 之间。

因此：

- 无争议、肯定在交班前：door-01、backup、door-02；
- 仍落在两个候选班次：batch、usb；
- 肯定在交班后：stop；
- printer 的记录编号 799 与文件原序冲突。接口不会删除或移动它，而是保留在 backup 与 door-02 之间的原位置，并放入 conflicts / conflicting_evidence。

编程接口可读取同一组文件：

~~~python
from Evtx.alignment import align_files

result = align_files("examples/evidence_alignment")
print(result.possible_orders)
print(result.definitely_before_handoff)
print(result.ambiguous_handoff)
print(result.conflicts)
~~~

使用 --json 可输出完整结构化结果。
