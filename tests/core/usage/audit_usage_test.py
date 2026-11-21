import pytest

from detect_secrets.core.usage import ParserBuilder


@pytest.fixture
def parser():
    return ParserBuilder().add_console_use_arguments()


def test_normal_mode_requires_single_file(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['audit', 'fileA', 'fileB'])


def test_diff_mode_requires_two_files(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['audit', 'fileA', '--diff'])


def test_export_vendors_requires_manifest_and_one_baseline(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['audit', 'baseline', '--export-vendors', 'out'])

    with pytest.raises(SystemExit):
        parser.parse_args([
            'audit',
            'a',
            'b',
            '--export-vendors',
            'out',
            '--vendor-manifest',
            'm',
        ])


def test_merge_vendors_can_infer_state(parser):
    args = parser.parse_args(['audit', '--merge-vendor-responses', 'a.json'])
    assert args.vendor_state is None


def test_conflict_report_requires_state(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(['audit', '--report-conflicts'])


def test_vendor_mode_cannot_combine_with_reporting_mode(parser):
    with pytest.raises(SystemExit):
        parser.parse_args([
            'audit',
            'baseline',
            '--stats',
            '--report-conflicts',
            '--vendor-state',
            'state.json',
        ])
