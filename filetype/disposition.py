# -*- coding: utf-8 -*-

"""
Quarantine adjudication for file-type hints.

``filetype`` only inspects the beginning of a file.  That is useful for
triage, but it does not prove that every part of a container was inspected.
This module keeps the distinction explicit:

* a :class:`DispositionPolicy` maps a file hint to required capabilities;
* a :class:`Consumer` declares which capabilities it can actually cover;
* a :class:`Confirmation` records what one consumer confirmed for one asset;
* a :class:`QuarantineArbiter` releases an asset only when every required
  capability has a confirmation tied to that asset's identity.

Nothing here unpacks a container.  Instead, a consumer that only recognises
an outer archive can confirm the shell capability while the content
capability remains missing.  The asset stays quarantined and the publication
queue remains untouched.
"""

from __future__ import absolute_import

from .types import Type


_WILDCARD = '*'


def _capabilities(first, extra=()):
    """
    Normalises one capability or an iterable of capabilities into a
    ``frozenset`` of non-empty strings.
    """
    values = []

    if first is not None:
        if isinstance(first, str):
            values.append(first)
        else:
            values.extend(first)

    for item in extra:
        if isinstance(item, str):
            values.append(item)
        else:
            values.extend(item)

    result = []
    for value in values:
        if not isinstance(value, str):
            raise TypeError('capability must be a string')
        value = value.strip()
        if not value:
            raise ValueError('capability must not be empty')
        if value not in result:
            result.append(value)
    return frozenset(result)


def _consumer_name(consumer):
    if consumer is None:
        return None
    if isinstance(consumer, Consumer):
        return consumer.name
    return str(consumer)


class FileHint(object):
    """
    The triage result attached to a quarantined asset.

    A hint can wrap a :class:`filetype.Type`, a MIME type, or an extension.
    The original type object is retained as ``kind`` for callers that need
    more than the two selectors.
    """

    __slots__ = ('mime', 'extension', 'kind')

    def __init__(self, mime=None, extension=None, kind=None):
        self.mime = mime.lower() if mime else None
        self.extension = extension.lower().lstrip('.') if extension else None
        self.kind = kind

    @classmethod
    def coerce(cls, hint):
        """
        Returns a :class:`FileHint` for a type instance, MIME type,
        extension, or existing hint.
        """
        if hint is None:
            return cls()
        if isinstance(hint, FileHint):
            return hint
        if isinstance(hint, Type):
            return cls(hint.mime, hint.extension, hint)
        if isinstance(hint, str):
            if '/' in hint:
                return cls(mime=hint)
            return cls(extension=hint)
        if hasattr(hint, 'mime') and hasattr(hint, 'extension'):
            return cls(hint.mime, hint.extension, hint)
        raise TypeError('unsupported file hint: %r' % (hint,))

    @classmethod
    def detect(cls, obj):
        """
        Uses :func:`filetype.guess` to build a hint for a path or buffer.
        An undetected input produces an empty hint so that the policy default
        can keep the asset under review.
        """
        from .filetype import guess
        return cls.coerce(guess(obj))

    def selectors(self):
        selectors = []
        if self.mime:
            selectors.append(('mime', self.mime))
        if self.extension:
            selectors.append(('extension', self.extension))
        return tuple(selectors)

    def __repr__(self):
        return 'FileHint(mime=%r, extension=%r)' % (
            self.mime, self.extension)


class Consumer(object):
    """
    A receiver or inspection handler and the capabilities it can cover.

    ``external`` is informational.  It is useful when an application wants
    to explain why an outside consumer's partial claim still leaves an asset
    waiting for review; it does not by itself grant or deny capabilities.
    """

    __slots__ = ('name', 'capabilities', 'external')

    def __init__(self, name, capabilities=(), external=False):
        name = str(name).strip()
        if not name:
            raise ValueError('consumer name must not be empty')
        self.name = name
        self.capabilities = _capabilities(capabilities)
        self.external = bool(external)

    def can(self, capability):
        return capability in self.capabilities

    def __repr__(self):
        return 'Consumer(name=%r, capabilities=%r, external=%r)' % (
            self.name, sorted(self.capabilities), self.external)


class DispositionPolicy(object):
    """
    Maps file hints to the capabilities that must be confirmed.

    Rules can be global or scoped to one consumer name.  A rule registered
    with a :class:`filetype.Type` applies to both its MIME type and its
    extension.  When no exact rule matches, the configured default is used.
    """

    def __init__(self, default=None):
        self._defaults = {None: _capabilities(default)}
        self._rules = {None: self._empty_bucket()}

    @staticmethod
    def _empty_bucket():
        return {
            'mime': {},
            'extension': {},
            _WILDCARD: frozenset(),
        }

    def _bucket(self, consumer):
        name = _consumer_name(consumer)
        if name not in self._rules:
            self._rules[name] = self._empty_bucket()
            self._defaults[name] = frozenset()
        return self._rules[name]

    def set_default(self, capabilities, consumer=None):
        """
        Sets the fallback capabilities for hints without an exact rule.
        """
        self._bucket(consumer)
        self._defaults[_consumer_name(consumer)] = _capabilities(capabilities)
        return self

    def require(self, hint, capabilities, *more, **options):
        """
        Adds required capabilities for a hint.

        ``capabilities`` may be one string or an iterable.  Additional
        capabilities can be passed positionally.  ``consumer`` limits the
        rule to a single receiver; without it the rule is global.
        """
        consumer = options.pop('consumer', None)
        if options:
            raise TypeError('unexpected keyword argument: %s' %
                            next(iter(options)))

        required = _capabilities(capabilities, more)
        bucket = self._bucket(consumer)
        if hint == _WILDCARD:
            hint = FileHint()
        hint = FileHint.coerce(hint)

        if not hint.selectors():
            bucket[_WILDCARD] = bucket[_WILDCARD] | required
            return self

        for selector, value in hint.selectors():
            current = bucket[selector].get(value, frozenset())
            bucket[selector][value] = current | required
        return self

    add_rule = require

    @staticmethod
    def _resolve(bucket, default, hint):
        matched = False
        result = set(bucket[_WILDCARD])
        if bucket[_WILDCARD]:
            matched = True

        for selector, value in hint.selectors():
            if value in bucket[selector]:
                result.update(bucket[selector][value])
                matched = True

        if not matched:
            result.update(default)
        return result

    def requirements_for(self, hint, consumer=None):
        """
        Returns the capabilities required for ``hint`` and optionally for a
        particular consumer.
        """
        hint = FileHint.coerce(hint)
        result = self._resolve(self._rules[None], self._defaults[None], hint)

        name = _consumer_name(consumer)
        if name is not None and name in self._rules:
            result.update(self._resolve(
                self._rules[name], self._defaults.get(name, frozenset()), hint))
        return frozenset(result)

    def __repr__(self):
        return 'DispositionPolicy(default=%r)' % (
            sorted(self._defaults[None]),)


class Confirmation(object):
    """
    One consumer's claim that it covered certain capabilities for one asset.
    """

    __slots__ = (
        'asset_id', 'consumer', 'capabilities', 'confirmation_id',
        'content_id', 'declared_capabilities')

    def __init__(self, asset_id, consumer, capabilities=None,
                 confirmation_id=None, content_id=None):
        asset_id = str(asset_id).strip()
        if not asset_id:
            raise ValueError('asset_id must not be empty')

        if isinstance(consumer, Consumer):
            consumer_name = consumer.name
            declared_capabilities = consumer.capabilities
            if capabilities is None:
                capabilities = consumer.capabilities
        else:
            if consumer is None:
                raise ValueError('consumer must not be empty')
            consumer_name = str(consumer).strip()
            declared_capabilities = None
            if not consumer_name:
                raise ValueError('consumer name must not be empty')

        self.asset_id = asset_id
        self.consumer = consumer_name
        self.capabilities = _capabilities(capabilities)
        self.confirmation_id = confirmation_id
        self.content_id = content_id
        self.declared_capabilities = declared_capabilities

    def fingerprint(self):
        return (
            self.asset_id,
            self.consumer,
            self.capabilities,
            self.content_id,
        )

    def __repr__(self):
        return ('Confirmation(asset_id=%r, consumer=%r, '
                'capabilities=%r, confirmation_id=%r)' % (
                    self.asset_id, self.consumer,
                    sorted(self.capabilities), self.confirmation_id))


Receipt = Confirmation


class Rejection(object):
    """A confirmation that was not counted and the reason why."""

    __slots__ = ('asset_id', 'confirmation_id', 'consumer', 'reason')

    def __init__(self, asset_id, confirmation_id, consumer, reason):
        self.asset_id = asset_id
        self.confirmation_id = confirmation_id
        self.consumer = consumer
        self.reason = reason

    def __repr__(self):
        return 'Rejection(asset_id=%r, confirmation_id=%r, reason=%r)' % (
            self.asset_id, self.confirmation_id, self.reason)


class Publication(object):
    """The record placed on the publication queue after a release."""

    __slots__ = (
        'asset_id', 'hint', 'content_id', 'required', 'evidence',
        'released_by', 'metadata')

    def __init__(self, asset_id, hint, content_id, required, evidence,
                 released_by, metadata=None):
        self.asset_id = asset_id
        self.hint = hint
        self.content_id = content_id
        self.required = required
        self.evidence = evidence
        self.released_by = released_by
        self.metadata = metadata

    def __repr__(self):
        return 'Publication(asset_id=%r, required=%r, released_by=%r)' % (
            self.asset_id, self.required, self.released_by)


class PublicationQueue(object):
    """A small in-memory publication sink used by the arbiter and tests."""

    def __init__(self):
        self._items = []

    def publish(self, publication):
        self._items.append(publication)

    put = publish

    def drain(self):
        items = tuple(self._items)
        self._items[:] = []
        return items

    def clear(self):
        self._items[:] = []

    @property
    def items(self):
        return tuple(self._items)

    def __iter__(self):
        return iter(self._items)

    def __len__(self):
        return len(self._items)


class ReleaseDecision(object):
    """A point-in-time explanation of an asset's quarantine state."""

    __slots__ = (
        'asset_id', 'hint', 'content_id', 'status', 'released', 'required',
        'confirmed', 'missing', 'evidence', 'released_by', 'confirmations',
        'rejections', 'publication', 'reason')

    def __init__(self, asset_id, hint=None, content_id=None,
                 status='unknown', released=False, required=(),
                 confirmed=(), missing=(), evidence=None, released_by=(),
                 confirmations=(), rejections=(), publication=None,
                 reason='unknown_asset'):
        self.asset_id = asset_id
        self.hint = hint
        self.content_id = content_id
        self.status = status
        self.released = released
        self.required = frozenset(required)
        self.confirmed = frozenset(confirmed)
        self.missing = frozenset(missing)
        self.evidence = evidence or {}
        self.released_by = tuple(released_by)
        self.confirmations = tuple(confirmations)
        self.rejections = tuple(rejections)
        self.publication = publication
        self.reason = reason

    @property
    def witnesses(self):
        """Maps each required capability to the confirmations covering it."""
        return self.evidence

    def __repr__(self):
        return ('ReleaseDecision(asset_id=%r, status=%r, released=%r, '
                'missing=%r)' % (
                    self.asset_id, self.status, self.released,
                    sorted(self.missing)))


class ClaimResult(object):
    """The outcome of applying one confirmation to one asset."""

    __slots__ = (
        'asset_id', 'confirmation_id', 'accepted', 'duplicate', 'reason',
        'counted_capabilities', 'ignored_capabilities', 'missing',
        'released', 'decision')

    def __init__(self, asset_id, confirmation_id, accepted, reason,
                 counted_capabilities=(), ignored_capabilities=(),
                 missing=(), released=False, duplicate=False, decision=None):
        self.asset_id = asset_id
        self.confirmation_id = confirmation_id
        self.accepted = accepted
        self.duplicate = duplicate
        self.reason = reason
        self.counted_capabilities = frozenset(counted_capabilities)
        self.ignored_capabilities = frozenset(ignored_capabilities)
        self.missing = frozenset(missing)
        self.released = released
        self.decision = decision

    @property
    def ok(self):
        return self.accepted

    def __repr__(self):
        return ('ClaimResult(asset_id=%r, confirmation_id=%r, accepted=%r, '
                'released=%r, reason=%r)' % (
                    self.asset_id, self.confirmation_id, self.accepted,
                    self.released, self.reason))


class Asset(object):
    """Public, read-only view of one quarantined asset."""

    __slots__ = (
        'asset_id', 'hint', 'content_id', 'required', 'receiver',
        'metadata', 'confirmations', 'rejections', 'released',
        'released_by', 'publication', 'status')

    def __init__(self, asset_id, hint, content_id, required, receiver,
                 metadata):
        self.asset_id = asset_id
        self.hint = hint
        self.content_id = content_id
        self.required = frozenset(required)
        self.receiver = receiver
        self.metadata = metadata
        self.confirmations = []
        self.rejections = []
        self.released = False
        self.released_by = ()
        self.publication = None
        self.status = 'review' if not required else 'pending'

    def __repr__(self):
        return 'Asset(asset_id=%r, status=%r, required=%r)' % (
            self.asset_id, self.status, sorted(self.required))


class QuarantineArbiter(object):
    """
    Correlates file hints, consumers, and confirmations.

    A confirmation is counted only when it names the right asset, its
    consumer declares every claimed capability, and its confirmation id has
    not already been bound to a different receipt.  Releasing an asset emits
    exactly one :class:`Publication`; partial or irrelevant confirmations
    never touch the publication queue.
    """

    def __init__(self, policy=None, publisher=None, require_content_id=False,
                 auto_release_unrequired=False, queue=None,
                 on_release=None):
        self.policy = policy or DispositionPolicy()
        if publisher is None:
            publisher = queue if queue is not None else on_release
        self.publisher = publisher
        self.require_content_id = bool(require_content_id)
        self.auto_release_unrequired = bool(auto_release_unrequired)
        self._assets = {}
        self._seen = {}
        self._consumers = {}
        self._rejections = []
        self._subscribers = []
        self._counter = 0

    def register_consumer(self, consumer):
        """Registers a consumer so confirmations by name can be checked."""
        if not isinstance(consumer, Consumer):
            consumer = Consumer(consumer)
        self._consumers[consumer.name] = consumer
        return consumer

    def subscribe(self, callback):
        """Registers a callback invoked once per released asset."""
        if not callable(callback):
            raise TypeError('callback must be callable')
        self._subscribers.append(callback)
        return callback

    def unsubscribe(self, callback):
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def admit(self, asset_id, hint, consumer=None, content_id=None,
              required=None, metadata=None):
        """
        Puts an asset into quarantine.

        ``hint`` may be a :class:`filetype.Type`, MIME type, extension, or
        :class:`FileHint`.  ``consumer`` optionally selects consumer-specific
        policy rules.  ``required`` adds ad-hoc capabilities to the policy.
        """
        asset_id = str(asset_id).strip()
        if not asset_id:
            raise ValueError('asset_id must not be empty')
        if asset_id in self._assets:
            raise ValueError('asset already admitted: %s' % asset_id)

        hint = FileHint.coerce(hint)
        receiver = None if consumer is None else _consumer_name(consumer)
        if isinstance(consumer, Consumer):
            self.register_consumer(consumer)
        capabilities = set(self.policy.requirements_for(hint, consumer))
        capabilities.update(_capabilities(required))

        asset = Asset(asset_id, hint, content_id, capabilities, receiver,
                      metadata)
        self._assets[asset_id] = asset

        if self.auto_release_unrequired and not capabilities:
            self._release(asset)
        return asset

    def admit_file(self, asset_id, obj, consumer=None, content_id=None,
                   required=None, metadata=None):
        """Admits a path or buffer using :func:`filetype.guess` as the hint."""
        return self.admit(
            asset_id, FileHint.detect(obj), consumer=consumer,
            content_id=content_id, required=required, metadata=metadata)

    register = admit

    def acknowledge(self, asset_id, consumer=None, capabilities=None,
                    confirmation_id=None, content_id=None):
        """
        Applies one confirmation.

        The first argument may be a :class:`Confirmation`; in that case the
        remaining arguments are ignored.  Otherwise a confirmation is built
        from the arguments.
        """
        if isinstance(asset_id, Confirmation):
            confirmation = asset_id
        else:
            if isinstance(consumer, Consumer):
                self.register_consumer(consumer)
            confirmation = Confirmation(
                asset_id, consumer, capabilities=capabilities,
                confirmation_id=confirmation_id, content_id=content_id)
        return self._apply(confirmation)

    claim = acknowledge
    confirm = acknowledge
    ack = acknowledge

    def _next_confirmation_id(self):
        self._counter += 1
        return 'confirmation-%d' % self._counter

    def _reject(self, asset, confirmation, reason):
        rejection = Rejection(
            confirmation.asset_id, confirmation.confirmation_id,
            confirmation.consumer, reason)
        self._rejections.append(rejection)
        if asset is not None:
            asset.rejections.append(rejection)
        missing = () if asset is None else self._missing(asset)
        decision = None if asset is None else self.decision(asset.asset_id)
        return ClaimResult(
            confirmation.asset_id, confirmation.confirmation_id, False,
            reason, missing=missing, decision=decision)

    def _apply(self, confirmation):
        asset = self._assets.get(confirmation.asset_id)
        if asset is None:
            return self._reject(None, confirmation, 'unknown_asset')

        if not confirmation.capabilities:
            return self._reject(asset, confirmation, 'no_capabilities')

        known_capabilities = confirmation.declared_capabilities
        if known_capabilities is None:
            known_capabilities = self._consumer_capabilities(
                confirmation.consumer)
        if known_capabilities is not None:
            undeclared = confirmation.capabilities - known_capabilities
            if undeclared:
                return self._reject(
                    asset, confirmation, 'consumer_capability_mismatch')

        if self.require_content_id and not confirmation.content_id:
            return self._reject(
                asset, confirmation, 'content_id_required')

        if (confirmation.content_id is not None and
                asset.content_id is not None and
                confirmation.content_id != asset.content_id):
            return self._reject(
                asset, confirmation, 'content_id_mismatch')

        if confirmation.confirmation_id is None:
            confirmation.confirmation_id = self._next_confirmation_id()

        seen = self._seen.get(confirmation.confirmation_id)
        if seen is not None:
            if seen['fingerprint'] == confirmation.fingerprint():
                if seen['accepted']:
                    return self._accepted(
                        asset, confirmation, duplicate=True)
                return self._reject(
                    asset, confirmation, 'duplicate_rejected')
            return self._reject(
                asset, confirmation, 'confirmation_id_conflict')

        relevant = confirmation.capabilities & asset.required
        ignored = confirmation.capabilities - asset.required
        if not relevant:
            self._seen[confirmation.confirmation_id] = {
                'fingerprint': confirmation.fingerprint(),
                'accepted': True,
            }
            asset.confirmations.append(confirmation)
            return self._accepted(
                asset, confirmation, ignored=ignored)

        self._seen[confirmation.confirmation_id] = {
            'fingerprint': confirmation.fingerprint(),
            'accepted': True,
        }
        asset.confirmations.append(confirmation)
        return self._accepted(
            asset, confirmation, counted=relevant, ignored=ignored)

    def _consumer_capabilities(self, name):
        consumer = self._consumers.get(name)
        return None if consumer is None else consumer.capabilities

    def _accepted(self, asset, confirmation, counted=None, ignored=(),
                  duplicate=False):
        if counted is None:
            counted = confirmation.capabilities & asset.required

        if not asset.released and asset.required:
            missing = self._missing(asset)
            if not missing:
                self._release(asset)

        decision = self.decision(asset.asset_id)
        return ClaimResult(
            asset.asset_id, confirmation.confirmation_id, True,
            'accepted' if not duplicate else 'duplicate',
            counted_capabilities=counted,
            ignored_capabilities=ignored,
            missing=decision.missing,
            released=asset.released,
            duplicate=duplicate,
            decision=decision)

    def _missing(self, asset):
        return frozenset(asset.required - self._confirmed(asset))

    @staticmethod
    def _confirmed(asset):
        confirmed = set()
        for confirmation in asset.confirmations:
            confirmed.update(confirmation.capabilities & asset.required)
        return frozenset(confirmed)

    @staticmethod
    def _evidence(asset):
        evidence = {}
        for capability in asset.required:
            witnesses = []
            for confirmation in asset.confirmations:
                if capability in confirmation.capabilities:
                    witnesses.append(confirmation.confirmation_id)
            evidence[capability] = tuple(witnesses)
        return evidence

    def _release(self, asset):
        evidence = self._evidence(asset)
        released_by = []
        for confirmation in asset.confirmations:
            confirmation_id = confirmation.confirmation_id
            if (confirmation.capabilities & asset.required and
                    confirmation_id not in released_by):
                released_by.append(confirmation_id)

        publication = Publication(
            asset.asset_id, asset.hint, asset.content_id, asset.required,
            evidence, tuple(released_by), asset.metadata)

        asset.released = True
        asset.status = 'released'
        asset.released_by = tuple(released_by)
        asset.publication = publication
        self._publish(publication)

    def _publish(self, publication):
        if self.publisher is not None:
            if hasattr(self.publisher, 'publish'):
                self.publisher.publish(publication)
            elif hasattr(self.publisher, 'put'):
                self.publisher.put(publication)
            elif hasattr(self.publisher, 'append'):
                self.publisher.append(publication)
            elif callable(self.publisher):
                self.publisher(publication)
            else:
                raise TypeError(
                    'publisher must be callable or expose publish()/put()')

        for callback in tuple(self._subscribers):
            callback(publication)

    def decision(self, asset_id):
        """
        Returns a :class:`ReleaseDecision` without changing quarantine state.
        Unknown assets produce an ``unknown`` decision.
        """
        asset = self._assets.get(str(asset_id))
        if asset is None:
            return ReleaseDecision(str(asset_id))

        confirmed = self._confirmed(asset)
        missing = frozenset(asset.required - confirmed)
        if asset.released:
            status = 'released'
            reason = 'complete'
        elif not asset.required:
            status = 'review'
            reason = 'no_requirements'
        elif missing:
            status = 'pending'
            reason = 'awaiting_capabilities'
        else:
            status = 'ready'
            reason = 'release_not_requested'

        return ReleaseDecision(
            asset.asset_id, asset.hint, asset.content_id, status,
            asset.released, asset.required, confirmed, missing,
            self._evidence(asset), asset.released_by,
            asset.confirmations, asset.rejections, asset.publication,
            reason)

    def get(self, asset_id):
        """Returns the admitted :class:`Asset`, or ``None``."""
        return self._assets.get(str(asset_id))

    @property
    def assets(self):
        return tuple(self._assets.values())

    @property
    def rejections(self):
        return tuple(self._rejections)

    decide = decision


def adjudicate(asset_id, hint, consumer=None, policy=None,
               confirmations=(), content_id=None, required=None):
    """
    Convenience helper that admits one asset and applies confirmations.

    This is intentionally stateless from the caller's perspective: it
    returns the final decision.  Use :class:`QuarantineArbiter` directly
    when confirmations arrive over time or a publication queue is needed.
    """
    arbiter = QuarantineArbiter(policy)
    arbiter.admit(asset_id, hint, consumer=consumer, content_id=content_id,
                  required=required)
    for confirmation in confirmations:
        arbiter.acknowledge(confirmation)
    return arbiter.decision(asset_id)


__all__ = [
    'Asset',
    'ClaimResult',
    'Confirmation',
    'Consumer',
    'DispositionPolicy',
    'FileHint',
    'Publication',
    'PublicationQueue',
    'QuarantineArbiter',
    'Receipt',
    'Rejection',
    'ReleaseDecision',
    'adjudicate',
]
