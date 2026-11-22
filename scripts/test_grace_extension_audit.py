import json
import subprocess
import sys

LEDGER = 'remediation_ledger.json'
SCRIPT = 'scripts/grace_extension_audit.py'


def run(ledger, tmp):
    with open(tmp, 'w') as f:
        json.dump(ledger, f)
    return subprocess.run(
        [sys.executable, SCRIPT, '--ledger', tmp, '--output', tmp + '.md'],
        capture_output=True,
        text=True,
    )


def main():
    with open(LEDGER) as f:
        ledger = json.load(f)

    bad = json.loads(json.dumps(ledger))
    bad['branches'][0]['findings'][0] = '0' * 40
    result = run(bad, '.tmp_bad_identity.json')
    assert result.returncode != 0 and '不在 baseline 既有身份中' in result.stderr
    print('ok: 非法发现身份被拒绝')

    dup = json.loads(json.dumps(ledger))
    dup['branches'][0]['downtime'].append(
        {'date': '2026-11-12', 'evidence': 'INC-DUP'},
    )
    result = run(dup, '.tmp_dup_pause.json')
    assert result.returncode != 0 and '重复绑定日期' in result.stderr
    print('ok: 同分支同日期停机证据重复绑定被拒绝')

    no_merge = json.loads(json.dumps(ledger))
    no_merge['merges'] = []
    result = run(no_merge, '.tmp_no_merge.json')
    assert result.returncode == 0
    assert 'release/merchant: 已用 10/10 (用尽)' in result.stdout
    print('ok: 无合流时 merchant 独立核算 10/10 用尽')

    result = run(ledger, '.tmp_ledger_copy.json')
    assert result.returncode == 0
    assert 'release/payment: 已用 9/10 (剩余 1), 截止 2026-11-24' in result.stdout
    assert 'release/settlement: 已用 11/10 (用尽), 截止 2026-11-20' in result.stdout
    print('ok: 合流后 payment 9/10 截止 2026-11-24, settlement 11/10 用尽')


if __name__ == '__main__':
    main()
