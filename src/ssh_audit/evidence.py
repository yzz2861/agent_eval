"""
   Evidence model that reconciles the software version advertised in the
   banner with the capabilities actually observed during the key exchange.

   Vendors occasionally back-fill an old source tree with a newer version
   string (or, conversely, back-port a handful of fixes into an old release).
   Neither the banner version nor a single algorithm is trustworthy on its
   own, so this module derives an evidence set from every observed algorithm,
   scores the combination of conflicting features over version ranges, and
   emits structured evidence items that older consumers can ignore.
"""

from typing import Any, Dict, List, Optional, Tuple

from ssh_audit.algorithm import Algorithm
from ssh_audit.product import Product
from ssh_audit.software import Software
from ssh_audit.ssh2_kex import SSH2_Kex
from ssh_audit.ssh2_kexdb import SSH2_KexDB


class CapabilityEvidence:
    """Capabilities derived exclusively from the algorithms observed in a key exchange."""

    def __init__(self, product: str) -> None:
        self.product = product

        # OpenSSH version in which every observed algorithm was first available (the maximum of the per-algorithm introduction versions).
        self.since_version: Optional[str] = None

        # OpenSSH version in which every observed algorithm was still available (the minimum of the per-algorithm removal versions).
        self.supported_till_version: Optional[str] = None

        # Observed algorithms that did not exist in the claimed product (unknown algorithms are excluded).
        self.algorithms: List[Dict[str, str]] = []

        # Algorithms introduced in a release newer than the banner version.  These are forward-looking features; they do not upgrade the security of an old build by themselves.
        self.features_ahead: List[Dict[str, str]] = []

        # Algorithms removed before the banner version was released.  Multiple independent entries form the signature of a back-filled version string.
        self.features_behind: List[Dict[str, str]] = []

        # Modern, security-relevant markers that a build at the claimed version would normally expose.
        self.modern_markers: List[Dict[str, str]] = []

        # Modern markers expected at the claimed version but absent from the observed set.
        self.missing_modern_markers: List[Dict[str, str]] = []

        # The oldest OpenSSH release in which every observed algorithm coexisted, i.e. the release immediately before the newest observed introduction.  Used to detect a capability window that predates a back-filled claim without penalizing hardened builds that merely omit algorithms.
        self.oldest_coexisting_version: Optional[str] = None

        # Per-algorithm-type counts of known algorithms used in the derivation, useful for spotting sparse / missing feature sets.
        self.observed_counts: Dict[str, int] = {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'product': self.product,
            'since_version': self.since_version,
            'supported_till_version': self.supported_till_version,
            'algorithms': list(self.algorithms),
            'features_ahead': list(self.features_ahead),
            'features_behind': list(self.features_behind),
            'modern_markers': list(self.modern_markers),
            'missing_modern_markers': list(self.missing_modern_markers),
            'oldest_coexisting_version': self.oldest_coexisting_version,
            'observed_counts': dict(self.observed_counts),
        }


class EvidenceModel:
    """Combines the claimed software version with the observed capability evidence."""

    # Relationship between the banner claim and the observed capability window.
    CONSISTENT = 'consistent'                       # Claimed version lies inside the observed capability window.
    VERSION_CLAIM_ONLY = 'version_claim_only'       # No usable algorithm evidence, so only the banner can be reported.
    CAPABILITY_ONLY = 'capability_observation_only'  # No parseable software version, so only capabilities can be reported.
    BACKFILL_SUSPECTED = 'backfill_suspected'       # High version claim combined with multiple older capability features.
    FORWARD_FEATURES_ON_OLD_CLAIM = 'forward_features_on_old_claim'  # Low version claim combined with newer algorithms (likely a back-port).
    CONFLICT = 'conflict'                           # The claim and capabilities disagree without enough evidence to classify further.

    # Evidence severities.
    SEVERITY_INFO = 'info'
    SEVERITY_WARN = 'warn'
    SEVERITY_FAIL = 'fail'

    # A back-fill decision requires at least this many independent capability features agreeing with an older release.
    BACKFILL_MIN_FEATURES = 3

    # ...together with this aggregate score.
    BACKFILL_SCORE_THRESHOLD = 4

    # Window-based (non-removal) evidence only counts when the observed set covers this many known algorithms across this many categories, so minimal/hardened configurations are not mis-flagged.
    WINDOW_EVIDENCE_MIN_ALGORITHMS = 6
    WINDOW_EVIDENCE_MIN_TYPES = 3

    # Modern markers that demonstrate a genuinely modern build.  Each maps to the OpenSSH release in which the marker appeared.
    # Only high-signal, release-specific markers participate in missing-marker evidence; broadly-supported algorithms would just punish hardened configurations.
    _MODERN_MARKERS: Dict[Tuple[str, str], str] = {
        ('kex', 'ext-info-s'): '9.6',
        ('kex', 'sntrup761x25519-sha512@openssh.com'): '8.5',
        ('kex', 'sntrup761x25519-sha512'): '9.9',
        ('kex', 'mlkem768x25519-sha256'): '9.9',
        ('key', 'sk-ssh-ed25519@openssh.com'): '8.2',
        ('key', 'sk-ecdsa-sha2-nistp256@openssh.com'): '8.2',
        ('key', 'rsa-sha2-512'): '7.2',
    }

    def __init__(self, software: Optional[Software], kex: Optional[SSH2_Kex]) -> None:
        self.software = software
        self.kex = kex
        self.evidence: List[Dict[str, Any]] = []
        self.capability: Optional[CapabilityEvidence] = None

        claimed_product = software.product if software is not None else Product.OpenSSH
        if kex is not None:
            self.capability = self._derive_capabilities(kex, claimed_product)

        self.backfill_score = self._compute_backfill_score() if (self.capability is not None and software is not None) else 0
        self.status = self._classify()
        self._build_evidence()

    # --- Capability derivation -------------------------------------------------

    @staticmethod
    def _algorithm_lists(kex: SSH2_Kex) -> Dict[str, List[str]]:
        return {
            'kex': list(kex.kex_algorithms),
            'key': list(kex.key_algorithms),
            'enc': list(kex.server.encryption),
            'mac': list(kex.server.mac),
        }

    @classmethod
    def _derive_capabilities(cls, kex: SSH2_Kex, product: str) -> CapabilityEvidence:
        capability = CapabilityEvidence(product)
        if product != Product.OpenSSH:
            return capability

        db = SSH2_KexDB.get_db()
        introductions: List[str] = []
        removals: List[str] = []
        # Keep the comparison helper independent of any Software instance by building a lightweight reference for compare_version().
        reference = Software(None, product, '0.0', None, None)

        for alg_type, alg_list in cls._algorithm_lists(kex).items():
            capability.observed_counts[alg_type] = len(alg_list)
            for algorithm in alg_list:
                alg_desc = db.get(alg_type, {}).get(algorithm)
                if alg_desc is None:
                    # Unknown algorithms cannot be mapped to any version, so never contribute evidence.
                    continue

                versions = alg_desc[0] if len(alg_desc) > 0 else []
                entry: Dict[str, str] = {'type': alg_type, 'algorithm': algorithm}

                openssh_versions = cls._openssh_versions(versions)
                since_version = openssh_versions[0] if len(openssh_versions) > 0 else None
                # A three-marker entry (e.g. ['2.3.0', '6.6', '6.9']) documents introduction, a default change, and removal: only the final marker is the removal release.  A two-marker entry is still supported today, so it must not be treated as removed.
                removed_version = openssh_versions[-1] if len(openssh_versions) >= 3 else None

                if since_version is not None:
                    entry['since_version'] = since_version
                    introductions.append(since_version)
                if removed_version is not None:
                    entry['removed_in_version'] = removed_version
                    removals.append(removed_version)

                if (alg_type, algorithm) in cls._MODERN_MARKERS:
                    marker = dict(entry)
                    marker['marker_version'] = cls._MODERN_MARKERS[(alg_type, algorithm)]
                    capability.modern_markers.append(marker)

                capability.algorithms.append(entry)

        capability.since_version = cls._max_version(reference, introductions)
        capability.supported_till_version = cls._min_version(reference, removals)
        capability.oldest_coexisting_version = cls._previous_minor_version(capability.since_version)
        return capability

    @staticmethod
    def _previous_minor_version(version: Optional[str]) -> Optional[str]:
        '''Returns the minor release immediately preceding version (e.g. 9.5 for 9.6), or None when it cannot be computed.'''
        if version is None:
            return None
        try:
            parts = [int(part) for part in str(version).split('.')[:2]]
            if len(parts) < 2:
                return None
            major, minor = parts[0], parts[1]
            if minor == 0:
                return '{}.0'.format(max(0, major - 1))
            return '{}.{}'.format(major, minor - 1)
        except ValueError:
            return None

    @staticmethod
    def _openssh_versions(versions: List[Optional[str]]) -> List[str]:
        '''Extracts the ordered OpenSSH version markers (introduction, optional removal) from a database entry, dropping Dropbear/libssh/client-only descriptors.'''
        result: List[str] = []
        for version_desc in versions:
            if version_desc is None:
                # A None slot marks the end of the server-side availability interval without giving a removal version.
                break
            for descriptor in str(version_desc).split(','):
                ssh_product, ssh_version, is_client = Algorithm.get_ssh_version(descriptor)
                if ssh_product == Product.OpenSSH and ssh_version and not is_client:
                    if ssh_version not in result:
                        result.append(ssh_version)
        return result

    @staticmethod
    def _max_version(reference: Software, versions: List[str]) -> Optional[str]:
        result: Optional[str] = None
        for version in versions:
            if result is None or reference.compare_version(version) > 0:
                result = version
        return result

    @staticmethod
    def _min_version(reference: Software, versions: List[str]) -> Optional[str]:
        result: Optional[str] = None
        for version in versions:
            if result is None or reference.compare_version(version) < 0:
                result = version
        return result

    def _feature_lists(self) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
        '''Splits observed, version-mapped algorithms into features newer-than-claimed and features older-than-claimed.'''
        if self.software is None or self.capability is None:
            return [], []

        features_ahead: List[Dict[str, str]] = []
        features_behind: List[Dict[str, str]] = []
        for entry in self.capability.algorithms:
            since_version = entry.get('since_version')
            if since_version is not None and self.software.compare_version(since_version) < 0:
                features_ahead.append(dict(entry))
            # Explicit removal markers are hard evidence and always count as legacy features.  A mere introduction newer than the claim does not: the algorithm is simply not enabled, which is normal for hardened builds and back-ports.  The overall version-window check still detects the contradiction.
            removed_version = entry.get('removed_in_version')
            if removed_version is not None and self.software.compare_version(removed_version) >= 0:
                features_behind.append(dict(entry))
        return features_ahead, features_behind

    def _compute_backfill_score(self) -> int:
        '''Scores evidence that a newer version string was stamped onto an older code base.

        Two independent evidence families feed the score: explicit algorithm
        removals (hard evidence), and a broad observed capability window that
        predates the claim (corroborating evidence).  Sparse sets and vendor
        back-ports that merely add algorithms cannot reach the threshold.
        '''
        if self.software is None or self.capability is None:
            return 0

        features_ahead, features_behind = self._feature_lists()
        self.capability.features_ahead = features_ahead
        self.capability.features_behind = features_behind

        score = 0
        # 1) Hard evidence: every observed algorithm explicitly removed before the claimed release is an independent contradiction.
        for entry in features_behind:
            score += 3

        # A build that already exposes algorithms newer than its claim is a back-port, not a back-fill: window/marker evidence must not be held against it.
        if len(features_ahead) > 0 and len(features_behind) == 0:
            self.capability.missing_modern_markers = []
            return 0

        # 2) Corroborating window evidence: a sufficiently rich observed set whose newest introduction predates the claim by at least two minor releases narrows the real code base to an older release.  A one-release gap is tolerated to account for feature ordering within a release train, while the coexistence-window check below prevents a genuine modern build from being punished for retaining older algorithms.
        observed_types = len({entry['type'] for entry in self.capability.algorithms})
        rich_observation = len(self.capability.algorithms) >= self.WINDOW_EVIDENCE_MIN_ALGORITHMS and observed_types >= self.WINDOW_EVIDENCE_MIN_TYPES
        introduction_gap = self._minor_version_gap(self.capability.since_version, self.software.version) if self.capability.since_version is not None else 0
        if rich_observation and introduction_gap >= 2:
            score += 2

        # 3) Corroborating marker evidence: markers from releases between the observed introduction and the claim are absent on a genuinely old code base, but present on a back-port or modern build.
        missing_markers = self._missing_modern_markers()
        self.capability.missing_modern_markers = missing_markers
        if rich_observation:
            score += min(2, len(missing_markers))

        # Forward-looking features are evidence of back-porting, not back-filling, and therefore do not increase the score.
        return score

    @staticmethod
    def _minor_version_gap(older: Optional[str], newer: str) -> int:
        '''Returns the number of minor releases between two OpenSSH versions, or 0 when it cannot be established.'''
        try:
            older_parts = [int(part) for part in str(older).split('.')[:2]]
            newer_parts = [int(part) for part in str(newer).split('.')[:2]]
            if len(older_parts) < 2 or len(newer_parts) < 2:
                return 0
            return max(0, (newer_parts[0] - older_parts[0]) * 10 + (newer_parts[1] - older_parts[1]))
        except (TypeError, ValueError):
            return 0

    def _missing_modern_markers(self) -> List[Dict[str, str]]:
        if self.software is None or self.capability is None:
            return []
        observed = {(entry['type'], entry['algorithm']) for entry in self.capability.algorithms}
        missing: List[Dict[str, str]] = []
        for (alg_type, algorithm), marker_version in self._MODERN_MARKERS.items():
            # Markers introduced after the newest observed algorithm but no later than the claim are the ones an old code base cannot provide.
            if self.capability.since_version is not None and Software(None, self.software.product, self.capability.since_version, None, None).compare_version(marker_version) < 0 and self.software.compare_version(marker_version) >= 0 and (alg_type, algorithm) not in observed:
                missing.append({'type': alg_type, 'algorithm': algorithm, 'marker_version': marker_version})
        return missing

    def _distinct_feature_types(self, features: List[Dict[str, str]]) -> int:
        return len({entry['type'] for entry in features})

    def _classify(self) -> str:
        if self.software is None and self.capability is None:
            return self.VERSION_CLAIM_ONLY
        if self.software is None:
            return self.CAPABILITY_ONLY
        if self.capability is None or len(self.capability.algorithms) == 0:
            return self.VERSION_CLAIM_ONLY

        features_ahead, features_behind = self._feature_lists()
        self.capability.features_ahead = features_ahead
        self.capability.features_behind = features_behind

        since_version = self.capability.since_version
        till_version = self.capability.supported_till_version

        within_window = True
        if since_version is not None and self.software.compare_version(since_version) < 0:
            within_window = False
        if till_version is not None and self.software.compare_version(till_version) > 0:
            within_window = False

        # A genuine back-port that adds newer features is never classified as a back-fill, regardless of other contradictions.
        is_backport = len(features_ahead) > 0 and len(features_behind) == 0

        # Back-fill path A: several explicitly removed algorithms across multiple categories (the classic version-stamp signature).
        has_removal_evidence = len(features_behind) >= self.BACKFILL_MIN_FEATURES and self._distinct_feature_types(features_behind) >= 2

        # Back-fill path B: no single-algorithm blacklist, but a rich, multi-category observation whose whole capability window plus missing modern markers predates the claim.
        observed_types = len({entry['type'] for entry in self.capability.algorithms})
        rich_observation = len(self.capability.algorithms) >= self.WINDOW_EVIDENCE_MIN_ALGORITHMS and observed_types >= self.WINDOW_EVIDENCE_MIN_TYPES
        introduction_gap = self._minor_version_gap(since_version, self.software.version) if since_version is not None else 0
        has_window_evidence = rich_observation and introduction_gap >= 2 and len(self.capability.missing_modern_markers) > 0

        if not is_backport and self.backfill_score >= self.BACKFILL_SCORE_THRESHOLD and (has_removal_evidence or has_window_evidence):
            return self.BACKFILL_SUSPECTED

        # A low claim that nevertheless exposes newer algorithms is a back-port (or mis-configuration), never an automatic upgrade to a safe version.
        if is_backport:
            return self.FORWARD_FEATURES_ON_OLD_CLAIM

        if within_window:
            return self.CONSISTENT

        return self.CONFLICT

    def _add_evidence(self, evidence_id: str, severity: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        item: Dict[str, Any] = {'id': evidence_id, 'severity': severity, 'message': message}
        if data:
            item['data'] = data
        self.evidence.append(item)

    def _build_evidence(self) -> None:
        if self.software is not None:
            claim_data = {
                'product': self.software.product,
                'version': self.software.version,
                'patch': self.software.patch,
                'raw_suffix': self.software.raw_suffix,
                'platform': self.software.platform,
                'vendor_suffix': self.software.vendor_suffix,
            }
            self._add_evidence('version_claim', self.SEVERITY_INFO,
                               'Banner claims {} {}.'.format(self.software.product, self.software.version),
                               claim_data)
            if self.software.is_backported:
                self._add_evidence('vendor_suffix', self.SEVERITY_INFO,
                                   'Vendor/platform suffix retained: {}.'.format(self.software.platform or self.software.raw_suffix),
                                   {'raw_suffix': self.software.raw_suffix, 'platform': self.software.platform})

        if self.capability is not None and len(self.capability.algorithms) > 0:
            self._add_evidence('capability_observation', self.SEVERITY_INFO,
                               'Observed capabilities are consistent with {} releases {} through {}.'.format(
                                   self.capability.product,
                                   self.capability.since_version or 'unknown',
                                   self.capability.supported_till_version or 'later'),
                               {
                                   'since_version': self.capability.since_version,
                                   'supported_till_version': self.capability.supported_till_version,
                                   'observed_counts': dict(self.capability.observed_counts),
                               })

            for entry in self.capability.features_behind:
                self._add_evidence('legacy_feature', self.SEVERITY_WARN,
                                   'Observed {} {}, which was removed in OpenSSH {}.'.format(
                                       entry['type'], entry['algorithm'], entry.get('removed_in_version', 'unknown')),
                                   dict(entry))
            for entry in self.capability.features_ahead:
                self._add_evidence('forward_feature', self.SEVERITY_INFO,
                                   'Observed {} {}, unavailable before OpenSSH {}.'.format(
                                       entry['type'], entry['algorithm'], entry.get('since_version', 'unknown')),
                                   dict(entry))
            for entry in self.capability.missing_modern_markers:
                self._add_evidence('missing_modern_marker', self.SEVERITY_WARN,
                                   'Expected modern marker {} {} (available since OpenSSH {}) was not observed.'.format(
                                       entry['type'], entry['algorithm'], entry.get('marker_version', 'unknown')),
                                   dict(entry))

        if self.status == self.BACKFILL_SUSPECTED:
            self._add_evidence('backfilled_version', self.SEVERITY_FAIL,
                               'Version string appears back-filled: the claimed release conflicts with the observed capability window across multiple feature categories (score {}).'.format(
                                   self.backfill_score),
                               {
                                   'claimed_version': self.software.version if self.software else None,
                                   'observed_since_version': self.capability.since_version if self.capability else None,
                                   'legacy_feature_count': len(self.capability.features_behind) if self.capability else 0,
                                   'missing_modern_marker_count': len(self.capability.missing_modern_markers) if self.capability else 0,
                                   'backfill_score': self.backfill_score,
                                   'threshold': self.BACKFILL_SCORE_THRESHOLD,
                               })
        elif self.status == self.FORWARD_FEATURES_ON_OLD_CLAIM:
            self._add_evidence('backported_feature', self.SEVERITY_WARN,
                               'Newer algorithms were observed on an older version claim; this is treated as a back-port and does not raise the effective security version.',
                               {'claimed_version': self.software.version if self.software else None})
        elif self.status == self.CONFLICT:
            self._add_evidence('version_conflict', self.SEVERITY_WARN,
                               'Claimed version and observed algorithm capabilities conflict; security conclusions must rely on observed capabilities.',
                               {'claimed_version': self.software.version if self.software else None,
                                'observed_since_version': self.capability.since_version if self.capability else None})

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            'status': self.status,
            'backfill_score': self.backfill_score,
            'backfill_threshold': self.BACKFILL_SCORE_THRESHOLD,
            'backfill_min_features': self.BACKFILL_MIN_FEATURES,
            'evidence': list(self.evidence),
        }
        if self.software is not None:
            result['version_claim'] = {
                'product': self.software.product,
                'version': self.software.version,
                'patch': self.software.patch,
                'raw_suffix': self.software.raw_suffix,
                'platform': self.software.platform,
                'vendor_suffix': self.software.vendor_suffix,
                'backported_build': self.software.is_backported,
                'display': self.software.display(False),
            }
        else:
            result['version_claim'] = None
        if self.capability is not None:
            result['capability_observation'] = self.capability.to_dict()
        else:
            result['capability_observation'] = None
        return result
