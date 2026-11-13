import enum
import re
import secrets
import time
import uuid
from base64 import b32encode
from os import urandom

from django.conf import settings
from django.db import OperationalError, connection, models, transaction
from django.db.models import F, Q
from django.utils import timezone

from django_otp.models import Device, ThrottlingMixin, TimestampMixin


# Recovery codes are commonly displayed in groups separated by spaces,
# dashes, or punctuation.  Storage and comparison use the canonical form:
# no separators and upper case.
_TOKEN_SEPARATOR_RE = re.compile(r"[\s\u200b\ufeff\-_.,;:|/\\]+")


def normalize_static_token(value):
    """
    Returns the canonical representation of a static token.

    The normalization is deliberately lossless for code characters: it only
    removes presentation separators and normalizes case.  It lets old tokens
    stored as ``secret-token`` and imported CSV values such as ``SECRET TOKEN``
    verify against the same stored value.
    """
    if value is None:
        return ""

    return _TOKEN_SEPARATOR_RE.sub("", str(value)).upper()


class StaticTokenErrorReason(str, enum.Enum):
    """
    Stable reason codes returned by batch operations.

    The values are intentionally free of counts or other mutable batch
    details.  In particular, verification failures never expose how many
    recovery codes remain in a batch.
    """

    INVALID_TOKEN = 'invalid_token'
    INVALID_TOKEN_FORMAT = 'invalid_token_format'
    EMPTY_IMPORT = 'empty_import'
    INVALID_BATCH_CONFIG = 'invalid_batch_config'
    RANDOM_SPACE_EXHAUSTED = 'random_space_exhausted'
    BATCH_NOT_FOUND = 'batch_not_found'
    BATCH_REVOKED = 'batch_revoked'
    BATCH_EXHAUSTED = 'batch_exhausted'
    BATCH_CONFLICT = 'batch_conflict'


class StaticTokenError(Exception):
    """
    An error with a stable, machine-readable reason.

    ``reason`` and ``code`` intentionally contain no token, batch, or
    remaining-code information.
    """

    def __init__(self, reason, message=None):
        if not isinstance(reason, StaticTokenErrorReason):
            reason = StaticTokenErrorReason(reason)

        self.reason = reason
        self.code = reason.value
        super().__init__(message or reason.value)


class StaticTokenBatch(models.Model):
    """
    An independently revocable group of static recovery codes.

    A batch records the token generation policy (alphabet, length, and random
    source) and enough state to explain whether it is ``active``, ``revoked``,
    or ``exhausted``.  Legacy :class:`StaticToken` rows have no batch and keep
    their historical behavior.
    """

    class Status(models.TextChoices):
        ACTIVE = 'active', 'Active'
        REVOKED = 'revoked', 'Revoked'
        EXHAUSTED = 'exhausted', 'Exhausted'

    STATUS_ACTIVE = Status.ACTIVE
    STATUS_REVOKED = Status.REVOKED
    STATUS_EXHAUSTED = Status.EXHAUSTED

    device = models.ForeignKey(
        'StaticDevice', related_name='token_batches', on_delete=models.CASCADE
    )
    batch_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    reference = models.CharField(max_length=128, blank=True, default='')
    source = models.CharField(max_length=16, default='generated')

    # Non-null for imports.  It is a content fingerprint scoped to a device,
    # which makes re-importing the same CSV idempotent.
    import_key = models.CharField(max_length=64, null=True, blank=True, default=None)

    alphabet = models.TextField(blank=True, default='')
    token_length = models.PositiveSmallIntegerField(default=0)
    random_source = models.CharField(max_length=128, blank=True, default='')

    total_count = models.PositiveIntegerField(default=0)
    consumed_count = models.PositiveIntegerField(default=0)
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.ACTIVE
    )
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True, default=None)
    revocation_reason = models.CharField(max_length=64, blank=True, default='')

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['device', 'import_key'],
                condition=Q(import_key__isnull=False),
                name='otp_static_batch_import_key_uniq',
            ),
        ]
        indexes = [
            models.Index(
                fields=['device', 'status'], name='otp_static_batch_status_idx'
            ),
        ]

    def __str__(self):
        name = self.reference or str(self.batch_id)
        return '{0} ({1})'.format(name, self.status)

    @property
    def is_active(self):
        return self.status == self.Status.ACTIVE

    @property
    def state(self):
        return self.status

    @property
    def charset(self):
        return self.alphabet

    @property
    def length(self):
        return self.token_length

    @property
    def rng(self):
        return self.random_source

    @property
    def code_count(self):
        return self.total_count

    @property
    def remaining_count(self):
        """
        The number of unclaimed codes in this batch.

        This is intentionally a model/audit property.  Verification APIs
        return only a boolean and must not expose this value.
        """
        if self.status != self.Status.ACTIVE:
            return 0
        return max(0, self.total_count - self.consumed_count)

    @property
    def unused_count(self):
        return self.tokens.filter(
            consumed_at__isnull=True, invalidated_at__isnull=True
        ).count()

    @property
    def remaining_codes(self):
        return self.remaining_count

    @property
    def token_set(self):
        return self.tokens

    @property
    def codes(self):
        return self.tokens

    def revoke(self, *, reason=''):
        """
        Revokes the entire batch.

        Unused tokens are marked invalid in the same transaction as the batch
        status change.  Once this returns, none of those tokens can verify,
        even if the process that initiated revocation is interrupted.
        """
        with transaction.atomic():
            device_qs = StaticDevice.objects.filter(pk=self.device_id)
            if connection.features.has_select_for_update:
                device_qs = device_qs.select_for_update()
            # Lock the parent row first, matching the ordering used by
            # verification, to serialize revocation against consumption.
            device_qs.get()

            batch_qs = type(self).objects.filter(pk=self.pk)
            if connection.features.has_select_for_update:
                batch_qs = batch_qs.select_for_update()
            batch = batch_qs.get()

            now = timezone.now()
            if (
                batch.status != self.Status.REVOKED
                or batch.revoked_at is None
            ):
                batch.status = self.Status.REVOKED
                batch.revoked_at = now
                batch.revocation_reason = str(reason or '')[:64]
                batch.save(
                    update_fields=[
                        'status',
                        'revoked_at',
                        'revocation_reason',
                    ]
                )

            batch.tokens.filter(
                consumed_at__isnull=True, invalidated_at__isnull=True
            ).update(invalidated_at=now)

        self.status = self.Status.REVOKED
        self.revoked_at = batch.revoked_at
        self.revocation_reason = batch.revocation_reason
        return self


class StaticDevice(TimestampMixin, ThrottlingMixin, Device):
    """
    A static :class:`~django_otp.models.Device` simply consists of random
    tokens shared by the database and the user.

    These are frequently used as emergency tokens in case a user's normal
    device is lost or unavailable. They can be consumed in any order; each
    token becomes invalid as soon as it is used. Legacy single tokens are
    deleted, while batched tokens retain a consumption timestamp for audit.

    This model has no fields of its own, but serves as a container for
    :class:`StaticToken` objects.

    .. attribute:: token_set

        The RelatedManager for our tokens.

    .. attribute:: token_batches

        The RelatedManager for our recovery-code batches.

    """

    def get_throttle_factor(self):
        return getattr(settings, 'OTP_STATIC_THROTTLE_FACTOR', 1)

    def _locked_device(self):
        if self.pk is None:
            return self

        device_qs = type(self).objects.filter(pk=self.pk)
        if connection.features.has_select_for_update:
            device_qs = device_qs.select_for_update()
        return device_qs.get()

    def create_token_batch(self, count=10, **kwargs):
        from .lib import create_static_token_batch

        kwargs.pop('device', None)
        return create_static_token_batch(
            self.user, count, device=self, **kwargs
        )

    def import_tokens(self, source, **kwargs):
        from .lib import import_static_tokens

        kwargs.pop('device', None)
        return import_static_tokens(self.user, source, device=self, **kwargs)

    def revoke_token_batch(self, batch, *, reason=''):
        from .lib import get_static_token_batch

        if not isinstance(batch, StaticTokenBatch):
            batch = get_static_token_batch(batch)
        if batch.device_id != self.pk:
            raise StaticTokenError(StaticTokenErrorReason.BATCH_CONFLICT)
        return batch.revoke(reason=reason)

    def _sync_from(self, device):
        self.throttling_failure_count = device.throttling_failure_count
        self.throttling_failure_timestamp = device.throttling_failure_timestamp
        self.last_used_at = device.last_used_at

    def _find_candidate(self, device, normalized_token):
        if not normalized_token:
            return None

        token_set = StaticToken.objects.filter(
            device_id=device.pk,
            consumed_at__isnull=True,
            invalidated_at__isnull=True,
        )
        match = token_set.filter(normalized_token=normalized_token).first()
        if match is not None:
            return match

        # Be defensive about rows inserted by third-party code with
        # bulk_create() or with a stale normalized column.
        for candidate in token_set.iterator():
            if normalize_static_token(candidate.token) == normalized_token:
                return candidate

        return None

    def _consume_batch_token(self, match, now):
        batch_qs = StaticTokenBatch.objects.filter(pk=match.batch_id)
        if connection.features.has_select_for_update:
            batch_qs = batch_qs.select_for_update()
        batch = batch_qs.get()

        if batch.status != StaticTokenBatch.Status.ACTIVE:
            return False

        claimed = StaticToken.objects.filter(
            pk=match.pk,
            consumed_at__isnull=True,
            invalidated_at__isnull=True,
        ).update(consumed_at=now)
        if not claimed:
            return False

        StaticTokenBatch.objects.filter(pk=batch.pk).update(
            consumed_count=F('consumed_count') + 1
        )
        StaticTokenBatch.objects.filter(
            pk=batch.pk,
            status=StaticTokenBatch.Status.ACTIVE,
            consumed_count__gte=F('total_count'),
        ).update(status=StaticTokenBatch.Status.EXHAUSTED)

        return True

    def _consume_legacy_token(self, match):
        deleted, _ = StaticToken.objects.filter(
            pk=match.pk,
            batch_id__isnull=True,
            consumed_at__isnull=True,
            invalidated_at__isnull=True,
        ).delete()
        return bool(deleted)

    def _verify_token_once(self, normalized_token):
        with transaction.atomic():
            device = self._locked_device()
            verify_allowed, _ = device.verify_is_allowed()
            if not verify_allowed:
                self._sync_from(device)
                return False

            now = timezone.now()
            match = self._find_candidate(device, normalized_token)

            if match is None:
                device.throttle_increment()
                self._sync_from(device)
                return False

            if match.batch_id is not None:
                verified = self._consume_batch_token(match, now)
            else:
                verified = self._consume_legacy_token(match)

            if verified:
                device.throttle_reset(commit=False)
                device.set_last_used_timestamp(commit=False)
                device.save()
            else:
                # A code that is already revoked or consumed is an
                # unsuccessful attempt and follows the normal throttle path.
                device.throttle_increment()

            self._sync_from(device)
            return verified

    @staticmethod
    def _is_retryable_lock_error(error):
        message = str(error).lower()
        return 'locked' in message or 'deadlock' in message

    def verify_token(self, token):
        """
        Atomically verifies and consumes a token.

        Concurrent attempts with the same token race on a conditional update,
        so at most one can succeed.  Failed attempts, including attempts
        against revoked or exhausted batches, increment the normal static
        device throttle.
        """
        normalized_token = normalize_static_token(token)

        # SQLite serializes writers at the database level.  A concurrent
        # verification can therefore report a transient lock error; retrying
        # lets the losing attempt observe the committed consumption.
        for attempt in range(10):
            try:
                return self._verify_token_once(normalized_token)
            except OperationalError as error:
                if not self._is_retryable_lock_error(error):
                    raise
                if attempt == 9:
                    # On SQLite's shared-cache table locks, a losing writer
                    # can be starved despite the token already being claimed
                    # by another request.  Refusing the attempt is safe and
                    # preserves the at-most-one-success invariant.
                    return False
                time.sleep(min(0.01 * (2 ** attempt), 0.1))

    def verify_token_with_reason(self, token):
        """
        Returns ``(verified, reason)`` without exposing batch state.

        All unsuccessful verification attempts use the same stable reason,
        regardless of whether the code was unknown, revoked, or exhausted.
        """
        verified = self.verify_token(token)
        if verified:
            return True, None
        return False, StaticTokenErrorReason.INVALID_TOKEN


class StaticToken(models.Model):
    """
    A single token belonging to a :class:`StaticDevice`.

    Tokens created without a batch retain the historical single-token
    behavior.  Tokens in a batch are consumed by marking them used, which
    preserves an audit trail instead of deleting the row.

    .. attribute:: device

        *ForeignKey*: A foreign key to :class:`StaticDevice`.

    .. attribute:: token

        *CharField*: A random string up to 64 characters.

    .. attribute:: normalized_token

        *CharField*: Canonical form used for case-insensitive and
        separator-insensitive comparisons.

    .. attribute:: batch

        *ForeignKey*: The owning batch, or ``None`` for a legacy token.

    """

    device = models.ForeignKey(
        StaticDevice, related_name='token_set', on_delete=models.CASCADE
    )
    token = models.CharField(max_length=64, db_index=True)
    normalized_token = models.CharField(max_length=64, db_index=True, blank=True)
    batch = models.ForeignKey(
        StaticTokenBatch,
        related_name='tokens',
        null=True,
        blank=True,
        default=None,
        on_delete=models.CASCADE,
    )
    consumed_at = models.DateTimeField(null=True, blank=True, default=None)
    invalidated_at = models.DateTimeField(null=True, blank=True, default=None)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['device', 'normalized_token'],
                condition=Q(batch__isnull=False),
                name='otp_static_token_device_uniq',
            ),
        ]
        indexes = [
            models.Index(
                fields=['device', 'normalized_token'],
                name='otp_static_token_norm_idx',
            ),
        ]

    def save(self, *args, **kwargs):
        self.normalized_token = normalize_static_token(self.token)

        update_fields = kwargs.get('update_fields')
        if update_fields is not None and 'token' in update_fields:
            kwargs['update_fields'] = set(update_fields) | {'normalized_token'}

        super().save(*args, **kwargs)

    @property
    def normalized(self):
        return self.normalized_token

    @property
    def is_consumed(self):
        return self.consumed_at is not None

    @property
    def is_invalidated(self):
        return self.invalidated_at is not None

    @staticmethod
    def random_token(length=None, alphabet=None, random_source=None):
        """
        Returns a new random string that can be used as a static token.

        With no arguments, this preserves the historical base32 token format.
        A batch can pass a uniform length, alphabet, and random source.

        :rtype: str

        """
        if length is None and alphabet is None and random_source is None:
            return b32encode(urandom(5)).decode('utf-8').lower()

        if length is None:
            length = 8
        if alphabet is None:
            alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        if random_source is None:
            random_source = secrets.choice

        if length < 1:
            raise StaticTokenError(
                StaticTokenErrorReason.INVALID_BATCH_CONFIG
            )

        if hasattr(random_source, 'choice'):
            choose = random_source.choice
        elif callable(random_source):
            choose = random_source
        else:
            raise StaticTokenError(StaticTokenErrorReason.INVALID_BATCH_CONFIG)

        characters = []
        for _ in range(length):
            try:
                characters.append(choose(alphabet))
            except TypeError:
                # Accept zero-argument callables as well.
                characters.append(choose())

        return ''.join(characters)


# Convenience aliases for integrations that use recovery-code terminology.
RecoveryCodeBatch = StaticTokenBatch
RecoveryCode = StaticToken
