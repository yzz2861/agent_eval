import base64
import binascii
import datetime
import gzip
import hashlib
import hmac
import json
import logging
import pickle
import zlib

from huey.exceptions import ConfigurationError
from huey.exceptions import SerializationError
from huey.registry import Message
from huey.utils import ChordConfig
from huey.utils import Error
from huey.utils import SKIPPED
from huey.utils import encode


logger = logging.getLogger('huey.serializer')


JSON_VERSION = 1
JSON_FORMAT = 'huey-json'
JSON_FORMAT_KEY = '__huey_format__'
JSON_VERSION_KEY = '__huey_version__'
JSON_KIND_KEY = '__huey_kind__'
JSON_DATA_KEY = '__huey_data__'
JSON_TYPE_KEY = '__huey_type__'
JSON_VALUE_KEY = '__huey_value__'

MESSAGE_FIELDS = frozenset(Message._fields)
REQUIRED_MESSAGE_FIELDS = frozenset(('id', 'name', 'args', 'kwargs'))
ENVELOPE_FIELDS = frozenset((
    JSON_FORMAT_KEY,
    JSON_VERSION_KEY,
    JSON_KIND_KEY,
    JSON_DATA_KEY,
))


def is_compressed(data):
    return data and (data[0] == 0x1f or data[0] == 0x78)


class Serializer(object):
    def __init__(self, compression=False, compression_level=6, use_zlib=False,
                 pickle_protocol=pickle.HIGHEST_PROTOCOL):
        self.comp = compression
        self.comp_level = compression_level
        self.use_zlib = use_zlib
        self.pickle_protocol = pickle_protocol or pickle.HIGHEST_PROTOCOL

    def _serialize(self, data):
        return pickle.dumps(data, self.pickle_protocol)

    def _deserialize(self, data):
        return pickle.loads(data)

    def serialize(self, data):
        data = self._serialize(data)
        if self.comp:
            if self.use_zlib:
                data = zlib.compress(data, self.comp_level)
            else:
                data = gzip.compress(data, self.comp_level)
        return data

    def deserialize(self, data):
        if self.comp:
            if not is_compressed(data):
                logger.warning('compression enabled but message data does not '
                               'appear to be compressed.')
            elif self.use_zlib:
                data = zlib.decompress(data)
            else:
                data = gzip.decompress(data)
        return self._deserialize(data)


class JsonSerializer(Serializer):
    def __init__(self, compression=False, compression_level=6,
                 use_zlib=False, allow_pickle=False):
        super(JsonSerializer, self).__init__(
            compression=compression,
            compression_level=compression_level,
            use_zlib=use_zlib)
        self.allow_pickle = allow_pickle

    def _serialize(self, data):
        payload = self._build_envelope(data)
        try:
            return json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(',', ':')).encode('utf-8')
        except SerializationError:
            raise
        except (TypeError, ValueError, OverflowError) as exc:
            raise SerializationError(
                'unable to serialize value to JSON: %s' % exc)

    def _deserialize(self, data):
        if self.allow_pickle and self.is_pickle_data(data):
            try:
                return pickle.loads(data)
            except Exception as exc:
                raise SerializationError(
                    'unable to deserialize legacy pickle message: %s' % exc)

        try:
            payload = json.loads(data.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SerializationError(
                'unable to deserialize JSON message: %s' % exc)

        return self._parse_envelope(payload)

    def is_pickle_data(self, data):
        return bool(data) and not data.lstrip().startswith(b'{')

    def _build_envelope(self, data):
        if isinstance(data, Message):
            kind = 'message'
            encoded = self._encode_message(data)
        elif isinstance(data, Error):
            kind = 'error'
            encoded = self._encode_dict(data.metadata, 'error')
        else:
            kind = 'value'
            encoded = self._encode_value(data)

        return {
            JSON_FORMAT_KEY: JSON_FORMAT,
            JSON_VERSION_KEY: JSON_VERSION,
            JSON_KIND_KEY: kind,
            JSON_DATA_KEY: encoded,
        }

    def _parse_envelope(self, payload):
        if not isinstance(payload, dict):
            raise SerializationError(
                'invalid JSON message: expected an object, got %s' %
                type(payload).__name__)

        message_format = payload.get(JSON_FORMAT_KEY)
        if message_format != JSON_FORMAT:
            raise SerializationError(
                'unknown JSON message format: %r' % (message_format,))

        version = payload.get(JSON_VERSION_KEY)
        if not isinstance(version, int) or isinstance(version, bool) or \
                version != JSON_VERSION:
            raise SerializationError(
                'unsupported Huey JSON message version: %r' % (version,))

        unknown = set(payload) - ENVELOPE_FIELDS
        if unknown:
            raise SerializationError(
                'unsupported JSON envelope parameter(s): %s' %
                ', '.join(sorted(unknown)))

        kind = payload.get(JSON_KIND_KEY)
        try:
            if kind == 'message':
                return self._decode_message(payload[JSON_DATA_KEY])
            elif kind == 'error':
                return Error(self._decode_dict(
                    payload[JSON_DATA_KEY], 'error'))
            elif kind == 'value':
                return self._decode_value(payload[JSON_DATA_KEY])
        except KeyError as exc:
            raise SerializationError(
                'JSON message is missing required data: %s' % exc)
        raise SerializationError('unknown JSON message kind: %r' % (kind,))

    def _encode_message(self, message):
        data = {}
        for field in Message._fields:
            value = getattr(message, field)
            if field == 'chord_config' and value is not None:
                cid, size, idx, callback = value
                value = {
                    'cid': self._encode_string(cid, field),
                    'size': self._encode_integer(size, field),
                    'idx': self._encode_integer(idx, field),
                    'callback': self._encode_message(callback),
                }
            elif field in ('on_complete', 'on_error') and value is not None:
                value = self._encode_message(value)
            elif field in ('name', 'id') and value is not None:
                value = self._encode_string(value, field)
            elif field == 'args' and value is not None:
                value = self._encode_tuple(value, field)
            elif field == 'kwargs' and value is not None:
                value = self._encode_dict(value, field)
            elif field == 'retries' and value is not None:
                value = self._encode_integer(value, field)
            elif field in ('retry_delay', 'timeout', 'retry_backoff') \
                    and value is not None:
                value = self._encode_number(value, field)
            elif field in ('eta', 'expires_resolved') and value is not None:
                value = self._encode_datetime(value, field)
            elif field == 'expires' and value is not None:
                value = self._encode_expires(value, field)
            elif value is not None:
                value = self._encode_value(value)
            data[field] = value
        return data

    def _decode_message(self, data):
        if not isinstance(data, dict):
            raise SerializationError(
                'invalid JSON task message: expected an object, got %s' %
                type(data).__name__)

        unknown = set(data) - MESSAGE_FIELDS
        if unknown:
            raise SerializationError(
                'unsupported JSON task parameter(s): %s' %
                ', '.join(sorted(unknown)))

        missing = REQUIRED_MESSAGE_FIELDS - set(data)
        if missing:
            raise SerializationError(
                'missing required JSON task parameter(s): %s' %
                ', '.join(sorted(missing)))

        values = {}
        for field in Message._fields:
            value = data.get(field)
            if value is None:
                values[field] = None
            elif field == 'chord_config':
                values[field] = self._decode_chord_config(value, field)
            elif field in ('on_complete', 'on_error'):
                values[field] = self._decode_nested_message(value, field)
            elif field in ('name', 'id'):
                values[field] = self._decode_string(value, field)
            elif field == 'args':
                values[field] = self._decode_tuple(value, field)
            elif field == 'kwargs':
                values[field] = self._decode_dict(value, field)
            elif field == 'retries':
                values[field] = self._decode_integer(value, field)
            elif field == 'priority':
                values[field] = self._decode_number(value, field)
            elif field in ('retry_delay', 'timeout', 'retry_backoff'):
                values[field] = self._decode_number(value, field)
            elif field in ('eta', 'expires_resolved'):
                values[field] = self._decode_datetime(value, field)
            elif field == 'expires':
                values[field] = self._decode_expires(value, field)
            else:
                values[field] = self._decode_value(value)
        return Message(**values)

    def _decode_nested_message(self, value, field):
        try:
            return self._decode_message(value)
        except SerializationError as exc:
            raise SerializationError('invalid task field %r: %s' %
                                     (field, exc))

    def _decode_chord_config(self, data, field='chord_config'):
        if not isinstance(data, dict):
            raise SerializationError('expected an object')

        fields = {'cid', 'size', 'idx', 'callback'}
        unknown = set(data) - fields
        if unknown:
            raise SerializationError(
                'unsupported chord parameter(s): %s' %
                ', '.join(sorted(unknown)))

        try:
            return ChordConfig(
                self._decode_string(data['cid'], 'cid'),
                self._decode_integer(data['size'], 'size'),
                self._decode_integer(data['idx'], 'idx'),
                self._decode_nested_message(data['callback'], 'callback'))
        except KeyError as exc:
            raise SerializationError(
                'invalid task field %r: missing chord parameter %s' %
                (field, exc))

    def _encode_value(self, value):
        if value is None:
            return self._tag('null', None)
        if value is SKIPPED:
            return self._tag('skipped', None)
        if isinstance(value, Error):
            return self._tag('error', self._encode_value(value.metadata))
        if isinstance(value, bool):
            return self._tag('boolean', value)
        if isinstance(value, int):
            return self._tag('integer', value)
        if isinstance(value, float):
            if value != value or value in (float('inf'), float('-inf')):
                raise SerializationError('non-finite floats are not supported')
            return self._tag('float', value)
        if isinstance(value, str):
            return self._tag('string', value)
        if isinstance(value, bytes):
            return self._tag('bytes', base64.b64encode(value).decode('ascii'))
        if isinstance(value, datetime.datetime):
            return self._tag('datetime', value.isoformat())
        if isinstance(value, datetime.date):
            return self._tag('date', value.isoformat())
        if isinstance(value, datetime.time):
            return self._tag('time', value.isoformat())
        if isinstance(value, datetime.timedelta):
            return self._tag('timedelta', value.total_seconds())
        if isinstance(value, tuple):
            return self._tag('tuple', [self._encode_value(item)
                                      for item in value])
        if isinstance(value, list):
            return self._tag('list', [self._encode_value(item)
                                     for item in value])
        if isinstance(value, dict):
            return self._tag('dict', [
                [self._encode_value(key), self._encode_value(item)]
                for key, item in value.items()])
        raise SerializationError(
            'type %s is not JSON-serializable' % type(value).__name__)

    def _decode_value(self, value):
        if not self._is_tag(value):
            raise SerializationError('invalid tagged JSON value: %r' % value)

        type_name = value[JSON_TYPE_KEY]
        data = value[JSON_VALUE_KEY]
        if type_name == 'null':
            self._expect_exact(data, None, type_name)
            return None
        if type_name == 'skipped':
            self._expect_exact(data, None, type_name)
            return SKIPPED
        if type_name == 'error':
            return Error(self._decode_value(data))
        if type_name == 'boolean':
            return self._expect_type(data, bool, type_name)
        if type_name == 'integer':
            return self._expect_type(data, int, type_name)
        if type_name == 'float':
            return float(self._expect_type(data, (int, float), type_name))
        if type_name == 'string':
            return self._expect_type(data, str, type_name)
        if type_name == 'bytes':
            raw = self._expect_type(data, str, type_name)
            try:
                return base64.b64decode(raw, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise SerializationError('invalid bytes value: %s' % exc)
        if type_name in ('datetime', 'date', 'time'):
            return self._decode_datetime_like(
                type_name, self._expect_type(data, str, type_name))
        if type_name == 'timedelta':
            return datetime.timedelta(seconds=self._expect_type(
                data, (int, float), type_name))
        if type_name in ('tuple', 'list'):
            items = self._expect_type(data, list, type_name)
            decoded = [self._decode_value(item) for item in items]
            return tuple(decoded) if type_name == 'tuple' else decoded
        if type_name == 'dict':
            items = self._expect_type(data, list, type_name)
            result = {}
            for index, item in enumerate(items):
                if not isinstance(item, list) or len(item) != 2:
                    raise SerializationError(
                        'invalid dict entry at index %s' % index)
                key = self._decode_value(item[0])
                try:
                    hash(key)
                except TypeError:
                    raise SerializationError(
                        'invalid dict key at index %s: %s is not hashable' %
                        (index, type(key).__name__))
                result[key] = self._decode_value(item[1])
            return result
        raise SerializationError('unknown JSON value type: %r' % type_name)

    def _decode_datetime_like(self, type_name, value):
        try:
            if type_name == 'datetime':
                return datetime.datetime.fromisoformat(value)
            if type_name == 'date':
                return datetime.date.fromisoformat(value)
            return datetime.time.fromisoformat(value)
        except ValueError as exc:
            raise SerializationError('invalid %s value: %s' %
                                     (type_name, exc))

    def _encode_tuple(self, value, field):
        if not isinstance(value, tuple):
            raise SerializationError(
                'task field %r must be a tuple, got %s' %
                (field, type(value).__name__))
        return self._tag('tuple', [self._encode_value(item)
                                  for item in value])

    def _decode_tuple(self, value, field):
        decoded = self._decode_value(value)
        if not isinstance(decoded, tuple):
            raise SerializationError(
                'task field %r must be tuple, got %s' %
                (field, type(decoded).__name__))
        return decoded

    def _encode_dict(self, value, field):
        if not isinstance(value, dict):
            raise SerializationError(
                'task field %r must be a dict, got %s' %
                (field, type(value).__name__))
        return self._tag('dict', [
            [self._encode_value(key), self._encode_value(item)]
            for key, item in value.items()])

    def _decode_dict(self, value, field):
        decoded = self._decode_value(value)
        if not isinstance(decoded, dict):
            raise SerializationError(
                'task field %r must be dict, got %s' %
                (field, type(decoded).__name__))
        return decoded

    def _encode_number(self, value, field):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SerializationError(
                'task field %r must be a number, got %s' %
                (field, type(value).__name__))
        return self._encode_value(value)

    def _decode_number(self, value, field):
        decoded = self._decode_value(value)
        if isinstance(decoded, bool) or not isinstance(decoded, (int, float)):
            raise SerializationError(
                'task field %r must be number, got %s' %
                (field, type(decoded).__name__))
        return decoded

    def _encode_datetime(self, value, field):
        if not isinstance(value, datetime.datetime) or \
                value.tzinfo is not None:
            raise SerializationError(
                'task field %r must be a timezone-naive datetime, got %s' %
                (field, type(value).__name__))
        return self._encode_value(value)

    def _decode_datetime(self, value, field):
        decoded = self._decode_value(value)
        if not isinstance(decoded, datetime.datetime) or \
                decoded.tzinfo is not None:
            raise SerializationError(
                'task field %r must be a timezone-naive datetime, got %s' %
                (field, type(decoded).__name__))
        return decoded

    def _encode_expires(self, value, field):
        if not isinstance(value, (datetime.datetime, datetime.timedelta,
                                  int, float)) or isinstance(value, bool):
            raise SerializationError(
                'task field %r must be datetime, timedelta or number, got %s'
                % (field, type(value).__name__))
        return self._encode_value(value)

    def _decode_expires(self, value, field):
        decoded = self._decode_value(value)
        if isinstance(decoded, bool) or not isinstance(
                decoded, (datetime.datetime, datetime.timedelta, int, float)):
            raise SerializationError(
                'task field %r must be datetime, timedelta or number, got %s'
                % (field, type(decoded).__name__))
        return decoded

    def _encode_string(self, value, field):
        if not isinstance(value, str):
            raise SerializationError(
                'task field %r must be a string, got %s' %
                (field, type(value).__name__))
        return self._tag('string', value)

    def _decode_string(self, value, field):
        decoded = self._decode_value(value)
        if not isinstance(decoded, str):
            raise SerializationError(
                'task field %r must be string, got %s' %
                (field, type(decoded).__name__))
        return decoded

    def _encode_integer(self, value, field):
        if not isinstance(value, int) or isinstance(value, bool):
            raise SerializationError(
                'task field %r must be an integer, got %s' %
                (field, type(value).__name__))
        return self._tag('integer', value)

    def _decode_integer(self, value, field):
        decoded = self._decode_value(value)
        if not isinstance(decoded, int) or isinstance(decoded, bool):
            raise SerializationError(
                'task field %r must be integer, got %s' %
                (field, type(decoded).__name__))
        return decoded

    def _tag(self, type_name, value):
        return {JSON_TYPE_KEY: type_name, JSON_VALUE_KEY: value}

    def _is_tag(self, value):
        return (isinstance(value, dict) and
                set(value) == {JSON_TYPE_KEY, JSON_VALUE_KEY} and
                isinstance(value.get(JSON_TYPE_KEY), str))

    def _expect_exact(self, value, expected, type_name):
        if value != expected:
            raise SerializationError(
                'invalid %s payload: %r' % (type_name, value))

    def _expect_type(self, value, expected, type_name):
        if not isinstance(value, expected) or (
                isinstance(value, bool) and expected is not bool):
            if isinstance(expected, tuple):
                names = ', '.join(cls.__name__ for cls in expected)
            else:
                names = expected.__name__
            raise SerializationError(
                '%s payload must be %s, got %s' %
                (type_name, names, type(value).__name__))
        return value


def constant_time_compare(s1, s2):
    return hmac.compare_digest(s1, s2)


class SerializerSignatureMixin(object):
    def configure_signature(self, secret, salt):
        if not secret or not salt:
            raise ConfigurationError('The secret and salt parameters are '
                                     'required by %r' % type(self))
        self.secret = encode(secret)
        self.salt = encode(salt)
        self.separator = b':'
        self._key = hashlib.sha1(self.salt + self.secret).digest()

    def _signature(self, message):
        signature = hmac.new(self._key, msg=message, digestmod=hashlib.sha1)
        return signature.hexdigest().encode('utf8')

    def _sign(self, message):
        return message + self.separator + self._signature(message)

    def _unsign(self, signed):
        if self.separator not in signed:
            raise ValueError('Separator "%s" not found' % self.separator)

        msg, sig = signed.rsplit(self.separator, 1)
        if constant_time_compare(sig, self._signature(msg)):
            return msg

        raise ValueError('Signature "%s" mismatch!' % sig)

    def _serialize(self, message):
        data = super(SerializerSignatureMixin, self)._serialize(message)
        return self._sign(data)

    def _deserialize(self, data):
        return super(SerializerSignatureMixin, self)._deserialize(
            self._unsign(data))


class SignedSerializer(SerializerSignatureMixin, Serializer):
    def __init__(self, secret=None, salt='huey', **kwargs):
        super(SignedSerializer, self).__init__(**kwargs)
        self.configure_signature(secret, salt)


class SignedJsonSerializer(SerializerSignatureMixin, JsonSerializer):
    def __init__(self, secret=None, salt='huey', **kwargs):
        super(SignedJsonSerializer, self).__init__(**kwargs)
        self.configure_signature(secret, salt)
