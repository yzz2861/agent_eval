import csv
import hashlib
import io
import os
import secrets
import time
import uuid
from threading import Lock

from django.contrib.auth import get_user_model
from django.db import IntegrityError, OperationalError, connection, transaction

from .models import (
    StaticDevice,
    StaticToken,
    StaticTokenBatch,
    StaticTokenError,
    StaticTokenErrorReason,
    normalize_static_token,
)


DEFAULT_BATCH_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
DEFAULT_BATCH_LENGTH = 8
DEFAULT_RANDOM_SOURCE = secrets.choice

# Static devices are intentionally not unique per user, so in-process
# issuance/import operations serialize device selection and creation.  The
# database constraints still make batches and imported codes idempotent
# across processes.
_DEVICE_MUTATION_LOCK = Lock()

# Management UIs sometimes include one of these as the first row.
_CSV_HEADERS = {
    'TOKEN',
    'TOKENS',
    'CODE',
    'CODES',
    'RECOVERYCODE',
    'RECOVERYCODES',
    'BACKUPCODE',
    'BACKUPCODES',
}


def _get_user(username):
    if hasattr(username, '_meta'):
        return username
    return get_user_model().objects.get_by_natural_key(username)


def _get_device(user, device=None):
    if device is not None:
        if device.user_id != user.pk:
            raise StaticTokenError(StaticTokenErrorReason.BATCH_CONFLICT)
        return device

    device = StaticDevice.objects.filter(user=user).first()
    if device is None:
        device = StaticDevice.objects.create(user=user, name='Backup Code')
    return device


def _lock_user(user):
    if connection.features.has_select_for_update:
        user.__class__.objects.select_for_update().filter(pk=user.pk).first()


def _random_source_name(random_source):
    if random_source is None:
        return 'secrets.choice'

    module = getattr(random_source, '__module__', '')
    name = getattr(random_source, '__qualname__', None) or getattr(
        random_source, '__name__', None
    )
    if name:
        return '{0}.{1}'.format(module, name) if module else name

    return type(random_source).__name__


def _validate_batch_config(count, length, alphabet):
    if not isinstance(count, int) or count < 1:
        raise StaticTokenError(StaticTokenErrorReason.INVALID_BATCH_CONFIG)
    if not isinstance(length, int) or not 1 <= length <= 64:
        raise StaticTokenError(StaticTokenErrorReason.INVALID_BATCH_CONFIG)
    if not isinstance(alphabet, str) or not alphabet:
        raise StaticTokenError(StaticTokenErrorReason.INVALID_BATCH_CONFIG)

    for character in alphabet:
        if (
            character.isspace()
            or normalize_static_token(character) != character.upper()
        ):
            raise StaticTokenError(StaticTokenErrorReason.INVALID_BATCH_CONFIG)

    capacity = len(set(alphabet)) ** length
    if capacity < count:
        raise StaticTokenError(StaticTokenErrorReason.RANDOM_SPACE_EXHAUSTED)


def _existing_normalized_tokens(device):
    return {
        normalize_static_token(token)
        for token in device.token_set.values_list('token', flat=True)
    }


def _generate_tokens(count, length, alphabet, random_source, existing):
    tokens = []
    seen = set(existing)
    max_attempts = max(1000, count * 100)

    for _ in range(max_attempts):
        if len(tokens) >= count:
            break

        token = StaticToken.random_token(
            length=length,
            alphabet=alphabet,
            random_source=random_source,
        )
        normalized = normalize_static_token(token)
        if normalized and normalized not in seen:
            seen.add(normalized)
            tokens.append(token)

    if len(tokens) != count:
        raise StaticTokenError(StaticTokenErrorReason.RANDOM_SPACE_EXHAUSTED)

    return tokens


def create_static_token_batch(
    username,
    count=10,
    length=DEFAULT_BATCH_LENGTH,
    alphabet=DEFAULT_BATCH_ALPHABET,
    random_source=None,
    batch_id=None,
    reference='',
    device=None,
    charset=None,
    rng=None,
):
    """
    Issues a batch of recovery codes for a user.

    All tokens in the batch use the same alphabet, length, and random source.
    Returns the :class:`~django_otp.plugins.otp_static.models.StaticTokenBatch`
    object.  The newly generated values are also available in the returned
    object's ``issued_tokens`` attribute for one-time display.

    Passing an existing ``batch_id`` is idempotent: the existing batch is
    returned and no additional codes are generated.
    """
    if charset is not None:
        alphabet = charset
    if rng is not None:
        random_source = rng

    _validate_batch_config(count, length, alphabet)

    user = _get_user(username)
    if random_source is None:
        random_source = secrets.choice
    batch_uuid = None
    if batch_id is not None:
        try:
            batch_uuid = uuid.UUID(str(batch_id))
        except (ValueError, TypeError, AttributeError):
            raise StaticTokenError(StaticTokenErrorReason.INVALID_BATCH_CONFIG)

    for attempt in range(5):
        try:
            with _DEVICE_MUTATION_LOCK, transaction.atomic():
                _lock_user(user)
                device = _get_device(user, device)
                if connection.features.has_select_for_update:
                    device = (
                        StaticDevice.objects.select_for_update().get(pk=device.pk)
                    )

                if batch_uuid is not None:
                    existing_batch = StaticTokenBatch.objects.filter(
                        batch_id=batch_uuid
                    ).first()
                    if existing_batch is not None:
                        if existing_batch.device_id != device.pk:
                            raise StaticTokenError(
                                StaticTokenErrorReason.BATCH_CONFLICT
                            )
                        existing_batch.issued_tokens = []
                        existing_batch.generated_tokens = []
                        existing_batch.imported_count = 0
                        existing_batch.duplicate_count = 0
                        existing_batch.created_count = 0
                        existing_batch.skipped_count = 0
                        return existing_batch

                existing = _existing_normalized_tokens(device)
                tokens = _generate_tokens(
                    count, length, alphabet, random_source, existing
                )

                batch = StaticTokenBatch.objects.create(
                    device=device,
                    batch_id=batch_uuid or uuid.uuid4(),
                    reference=str(reference or '')[:128],
                    source='generated',
                    alphabet=alphabet,
                    token_length=length,
                    random_source=_random_source_name(random_source),
                    total_count=count,
                    status=StaticTokenBatch.Status.ACTIVE,
                )
                StaticToken.objects.bulk_create(
                    [
                        StaticToken(
                            device=device,
                            batch=batch,
                            token=token,
                            normalized_token=normalize_static_token(token),
                        )
                        for token in tokens
                    ]
                )

                batch.issued_tokens = tokens
                batch.generated_tokens = tokens
                batch.imported_count = count
                batch.duplicate_count = 0
                batch.created_count = count
                batch.skipped_count = 0
                return batch
        except IntegrityError:
            if attempt == 4:
                raise StaticTokenError(StaticTokenErrorReason.BATCH_CONFLICT)
        except OperationalError as error:
            message = str(error).lower()
            if ('locked' not in message and 'deadlock' not in message) or attempt == 4:
                raise
            time.sleep(0.02 * (attempt + 1))


def parse_static_tokens(source):
    """
    Parses and normalizes one or more recovery codes.

    ``source`` may be a CSV string, a file-like object, or an iterable of
    values.  Comma, semicolon, tab, and newline delimiters are accepted.
    Presentation separators (spaces, dashes, and punctuation) inside a code
    are removed, as is case.  Duplicate values are collapsed in first-seen
    order.
    """
    if hasattr(source, 'read'):
        data = source.read()
    elif isinstance(source, os.PathLike):
        with open(source, 'rb') as file:
            data = file.read()
    elif isinstance(source, bytes):
        data = source.decode('utf-8')
    elif isinstance(source, str):
        is_path = (
            not any(character in source for character in ',\n\r;\t')
            and os.path.isfile(source)
        )
        if is_path:
            with open(source, 'rb') as file:
                data = file.read()
        else:
            data = source
    else:
        parts = []
        for item in source:
            if hasattr(item, 'read'):
                parts.append(item.read())
            elif isinstance(item, (list, tuple)):
                parts.append(','.join(str(value) for value in item))
            else:
                parts.append(str(item))
        data = '\n'.join(parts)

    normalized_tokens = []
    seen = set()

    for row in csv.reader(io.StringIO(data)):
        for cell in row:
            for value in cell.replace(';', '\t').split('\t'):
                normalized = normalize_static_token(value)
                if not normalized:
                    continue
                if len(normalized) > 64:
                    raise StaticTokenError(
                        StaticTokenErrorReason.INVALID_TOKEN_FORMAT
                    )
                if not normalized_tokens and normalized in _CSV_HEADERS:
                    continue
                if normalized not in seen:
                    seen.add(normalized)
                    normalized_tokens.append(normalized)

    if not normalized_tokens:
        raise StaticTokenError(StaticTokenErrorReason.EMPTY_IMPORT)

    return normalized_tokens


def _import_key(tokens):
    digest = hashlib.sha256()
    for token in sorted(tokens):
        digest.update(token.encode('utf-8'))
        digest.update(b'\n')
    return digest.hexdigest()


def _import_static_tokens_once(
    user,
    tokens,
    *,
    batch_id,
    reference,
    device,
):
    import_key = _import_key(tokens)
    batch_uuid = None

    if batch_id is not None:
        try:
            batch_uuid = uuid.UUID(str(batch_id))
        except (ValueError, TypeError, AttributeError):
            raise StaticTokenError(StaticTokenErrorReason.INVALID_BATCH_CONFIG)

    _lock_user(user)
    device = _get_device(user, device)
    if connection.features.has_select_for_update:
        device = StaticDevice.objects.select_for_update().get(pk=device.pk)

    batch = None
    if batch_uuid is not None:
        batch = StaticTokenBatch.objects.filter(batch_id=batch_uuid).first()
        if batch is not None:
            if batch.device_id != device.pk:
                raise StaticTokenError(StaticTokenErrorReason.BATCH_CONFLICT)
            if batch.import_key and batch.import_key != import_key:
                raise StaticTokenError(StaticTokenErrorReason.BATCH_CONFLICT)

    if batch is None:
        batch = StaticTokenBatch.objects.filter(
            device=device, import_key=import_key
        ).first()

    if batch is None:
        batch = StaticTokenBatch.objects.create(
            device=device,
            batch_id=batch_uuid or uuid.uuid4(),
            reference=str(reference or '')[:128],
            source='imported',
            import_key=import_key,
            alphabet=''.join(sorted(set(''.join(tokens)))),
            token_length=(
                len(tokens[0])
                if len({len(token) for token in tokens}) == 1
                else 0
            ),
            random_source='external',
            total_count=0,
            status=StaticTokenBatch.Status.ACTIVE,
        )

    batch_qs = StaticTokenBatch.objects.filter(pk=batch.pk)
    if connection.features.has_select_for_update:
        batch_qs = batch_qs.select_for_update()
    batch = batch_qs.get()

    if batch.status == StaticTokenBatch.Status.REVOKED:
        batch.imported_count = 0
        batch.duplicate_count = len(tokens)
        batch.created_count = 0
        batch.skipped_count = len(tokens)
        return batch

    existing = _existing_normalized_tokens(device)
    new_tokens = [token for token in tokens if token not in existing]

    if new_tokens:
        StaticToken.objects.bulk_create(
            [
                StaticToken(
                    device=device,
                    batch=batch,
                    token=token,
                    normalized_token=token,
                )
                for token in new_tokens
            ]
        )

    total_count = batch.tokens.count()
    consumed_count = batch.tokens.filter(consumed_at__isnull=False).count()
    update_fields = [
        'total_count',
        'consumed_count',
        'status',
        'alphabet',
        'token_length',
        'random_source',
    ]

    batch.total_count = total_count
    batch.consumed_count = consumed_count
    if total_count == 0 or consumed_count >= total_count:
        batch.status = StaticTokenBatch.Status.EXHAUSTED
    else:
        batch.status = StaticTokenBatch.Status.ACTIVE

    combined_alphabet = ''.join(sorted(set(batch.alphabet) | set(''.join(tokens))))
    batch.alphabet = combined_alphabet
    if len({len(token) for token in tokens}) == 1:
        batch.token_length = len(tokens[0])
    else:
        batch.token_length = 0
    batch.random_source = 'external'

    if batch.import_key is None:
        batch.import_key = import_key
        update_fields.append('import_key')
    if reference:
        batch.reference = str(reference)[:128]
        update_fields.append('reference')

    batch.save(update_fields=update_fields)

    batch.imported_count = len(new_tokens)
    batch.duplicate_count = len(tokens) - len(new_tokens)
    batch.created_count = len(new_tokens)
    batch.skipped_count = len(tokens) - len(new_tokens)
    return batch


def import_static_tokens(
    username,
    source=None,
    *,
    codes=None,
    batch_id=None,
    reference='',
    device=None,
):
    """
    Imports recovery codes from CSV text, a file-like object, or an iterable.

    The import is idempotent for the same set of normalized codes: a content
    fingerprint identifies the batch, duplicate values are skipped, and
    re-importing heals an interrupted partial import without creating
    duplicate rows.
    """
    if source is None:
        source = codes
    if source is None:
        raise StaticTokenError(StaticTokenErrorReason.EMPTY_IMPORT)

    user = _get_user(username)
    tokens = parse_static_tokens(source)

    for attempt in range(5):
        try:
            with _DEVICE_MUTATION_LOCK, transaction.atomic():
                return _import_static_tokens_once(
                    user,
                    tokens,
                    batch_id=batch_id,
                    reference=reference,
                    device=device,
                )
        except IntegrityError:
            if attempt == 4:
                raise StaticTokenError(StaticTokenErrorReason.BATCH_CONFLICT)
        except OperationalError as error:
            message = str(error).lower()
            if ('locked' not in message and 'deadlock' not in message) or attempt == 4:
                raise
            time.sleep(0.02 * (attempt + 1))


def revoke_static_token_batch(batch, *, reason=''):
    """
    Revokes a batch by object, UUID, or UUID string.

    Revocation is atomic and idempotent.  After it returns, no unused code in
    the batch can verify.
    """
    if not isinstance(batch, StaticTokenBatch):
        try:
            batch_uuid = uuid.UUID(str(batch))
        except (ValueError, TypeError, AttributeError):
            raise StaticTokenError(StaticTokenErrorReason.INVALID_BATCH_CONFIG)

        batch = StaticTokenBatch.objects.filter(batch_id=batch_uuid).first()
        if batch is None:
            raise StaticTokenError(StaticTokenErrorReason.BATCH_NOT_FOUND)

    return batch.revoke(reason=reason)


def get_static_token_batch(batch_id):
    try:
        batch_uuid = uuid.UUID(str(batch_id))
    except (ValueError, TypeError, AttributeError):
        raise StaticTokenError(StaticTokenErrorReason.INVALID_BATCH_CONFIG)

    batch = StaticTokenBatch.objects.filter(batch_id=batch_uuid).first()
    if batch is None:
        raise StaticTokenError(StaticTokenErrorReason.BATCH_NOT_FOUND)
    return batch


def add_static_token(username, token=None):
    """
    Adds a random static token to the identified user.

    This is the implementation for the management command of a similar name.
    Returns the StaticToken object created.  This legacy API intentionally
    does not create a batch.
    """
    user = _get_user(username)

    device = StaticDevice.objects.filter(user=user).first()
    if device is None:
        device = StaticDevice.objects.create(user=user, name='Backup Code')

    if token is None:
        token = StaticToken.random_token()

    return device.token_set.create(token=token)


# Descriptive aliases for callers that use issuance/import terminology.
issue_static_token_batch = create_static_token_batch


def add_static_tokens(username, count=10, **kwargs):
    """
    Compatibility helper: an integer second argument issues a batch, while
    code input (CSV text, iterable, or path) imports codes.
    """
    if not isinstance(count, int):
        import_kwargs = {
            key: value
            for key, value in kwargs.items()
            if key in ('batch_id', 'reference', 'device', 'codes')
        }
        return import_static_tokens(username, count, **import_kwargs)
    return create_static_token_batch(username, count, **kwargs)


bulk_add_static_tokens = add_static_tokens
import_recovery_codes = import_static_tokens
parse_recovery_codes = parse_static_tokens
normalize_token = normalize_static_token
normalize_recovery_code = normalize_static_token
revoke_batch = revoke_static_token_batch
