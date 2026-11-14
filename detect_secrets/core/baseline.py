import json
import time
from typing import Any
from typing import Callable
from typing import cast
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

from . import upgrades
from ..__version__ import VERSION
from ..exceptions import UnableToReadBaselineError
from ..settings import configure_settings_from_baseline
from ..settings import get_settings
from ..util.importlib import import_modules_from_package
from ..util.semver import Version
from .potential_secret import PotentialSecret
from .scan import get_files_to_scan
from .secrets_collection import SecretsCollection


def create(
    *paths: str,
    should_scan_all_files: bool = False,
    root: str = '',
    num_processors: Optional[int] = None,
) -> SecretsCollection:
    """Scans all the files recursively in path to initialize a baseline."""
    kwargs = {}
    if num_processors:
        kwargs['num_processors'] = num_processors

    secrets = SecretsCollection(root=root)
    secrets.scan_files(
        *get_files_to_scan(*paths, should_scan_all_files=should_scan_all_files, root=root),
        **kwargs,
    )

    return secrets


def update(
    secrets: SecretsCollection,
    baseline: Dict[str, Any],
) -> SecretsCollection:
    """
    Updates an old baseline with the results of a fresh scan, and returns the
    new state of the world.

    This applies strict scoping rules, so that exemptions cannot drift onto
    secrets that they were never audited for:

    1.  Audited labels (e.g. `is_secret`) are bound to the content hash of the
        secret (within the same file) -- never to line numbers alone. As such,
        inserting lines into a file will not cause an old exemption to cover a
        different secret that now sits at the previously exempted offset.
        Conversely, a known secret that merely moved offsets retains its
        labels, and its recorded offset is refreshed from the scan.
    2.  New secrets are never inherited as known items: anything not present
        in the old baseline stays unaudited.
    3.  Entries whose files no longer appear in the scan (e.g. deleted files)
        are dropped.
    4.  Conflicting labels resolve to the strictest outcome: a secret that was
        ever marked as a real secret stays marked as one.

    NOTE: This mutates (and reuses) the PotentialSecret objects in `secrets`,
    much like SecretsCollection.merge.
    """
    old_results = SecretsCollection.load_from_baseline(upgrade(baseline))

    output = SecretsCollection(root=secrets.root)
    for filename in secrets.files:
        # Exemptions are matched by content hash (and secret type), through
        # PotentialSecret's equality semantics -- line numbers play no part in
        # this binding.
        old_secrets = {
            secret: secret
            for secret in old_results.data.get(filename, set())
        }

        for secret in secrets[filename]:
            old_secret = old_secrets.get(secret)
            if old_secret is not None:
                _merge_audit_labels(secret, old_secret)

            output[filename].add(secret)

    return output


def _merge_audit_labels(new_secret: PotentialSecret, old_secret: PotentialSecret) -> None:
    """Carries over audited labels from a hash-matched old baseline entry."""
    if new_secret.is_secret is None:
        # Inherit the old audited label (True/False), or stay unaudited (None).
        new_secret.is_secret = old_secret.is_secret
    elif old_secret.is_secret is not None and new_secret.is_secret != old_secret.is_secret:
        # Conflicting rules resolve to the strictest outcome.
        new_secret.is_secret = True

    if not new_secret.is_verified:
        new_secret.is_verified = old_secret.is_verified


def load(baseline: Dict[str, Any], filename: str = '') -> SecretsCollection:
    """
    With a given baseline file, load all settings and discovered secrets from it.

    :raises: KeyError
    """
    # This is required for backwards compatibility, and supporting upgrades from older versions.
    baseline = upgrade(baseline)

    configure_settings_from_baseline(baseline, filename=filename)
    return SecretsCollection.load_from_baseline(baseline)


def load_from_file(filename: str) -> Dict[str, Any]:
    """
    :raises: UnableToReadBaselineError
    :raises: InvalidBaselineError
    """
    try:
        with open(filename) as f:
            return cast(Dict[str, Any], json.loads(f.read()))
    except (FileNotFoundError, IOError, json.decoder.JSONDecodeError) as e:
        raise UnableToReadBaselineError from e


def format_for_output(secrets: SecretsCollection, is_slim_mode: bool = False) -> Dict[str, Any]:
    output = {
        'version': VERSION,

        # This will populate settings of filters and plugins,
        **get_settings().json(),

        'results': secrets.json(),
    }

    if not is_slim_mode:
        output['generated_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    else:
        # NOTE: This has a nice little side effect of keeping it ordered by line number,
        # even though we don't output it.
        for filename, secret_list in cast(
            Dict[str, List[Dict[str, Any]]],
            output['results'],
        ).items():
            for secret_dict in secret_list:
                secret_dict.pop('line_number')

    return output


def save_to_file(
    secrets: Union[SecretsCollection, Dict[str, Any]],
    filename: str,
) -> None:    # pragma: no cover
    """
    :param secrets: if this is a SecretsCollection, it will output the baseline in its latest
        format. Otherwise, you should pass in a dictionary to this function, to manually
        specify the baseline format to save as.

        If you're trying to decide the difference, ask yourself whether there are any changes
        that does not directly impact the results of the scan.
    """
    # TODO: I wonder whether this should add the `detect_secrets.filters.common.is_baseline_file`
    # filter, since we know the filename already. However, one could argue that it would cause
    # this function to "do more than one thing".
    output = secrets
    if isinstance(secrets, SecretsCollection):
        output = format_for_output(secrets)

    with open(filename, 'w') as f:
        f.write(json.dumps(output, indent=2) + '\n')


def upgrade(baseline: Dict[str, Any]) -> Dict[str, Any]:
    """
    Baselines will eventually require format changes. This function is responsible for upgrading
    an older baseline to the latest version.
    """
    baseline_version = Version(baseline['version'])
    if baseline_version >= Version(VERSION):
        return baseline

    modules = import_modules_from_package(
        upgrades,
        filter=lambda x: not _is_relevant_upgrade_module(baseline_version)(x),
    )

    new_baseline = {**baseline}
    for module in modules:
        module.upgrade(new_baseline)

    new_baseline['version'] = VERSION
    return new_baseline


def _is_relevant_upgrade_module(current_version: Version) -> Callable:
    def wrapped(module_path: str) -> bool:
        # This converts `v1_0` to `1.0`
        affected_version_string = module_path.rsplit('.', 1)[-1].lstrip('v').replace('_', '.')

        # Patch version doesn't matter, because patches should not require baseline bumps.
        affected_version = Version(f'{affected_version_string}.0')

        return current_version < affected_version

    return wrapped
