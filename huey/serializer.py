import base64
import datetime
import gzip
import hashlib
import hmac
import importlib
import json
import logging
import pickle
import zlib

from huey.exceptions import ConfigurationError
from huey.exceptions import SerializerError
from huey.utils import encode


logger = logging.getLogger('huey.serializer')


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


def constant_time_compare(s1, s2):
    return hmac.compare_digest(s1, s2)


class SignedSerializer(Serializer):
    def __init__(self, secret=None, salt='huey', **kwargs):
        super(SignedSerializer, self).__init__(**kwargs)
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
        data = super(SignedSerializer, self)._serialize(message)
        return self._sign(data)

    def _deserialize(self, data):
        return super(SignedSerializer, self)._deserialize(self._unsign(data))


class JsonSerializer(Serializer):
    """
    Serialize messages to a versioned, human-inspectable JSON format.

    Unlike the default pickle-based serializer, only a fixed set of value
    types is supported, and deserializing a message never instantiates
    arbitrary objects:

    * None, bool, int, float and str
    * bytes (base64-encoded)
    * datetime.datetime (naive or timezone-aware, stored as ISO-8601)
    * tuple and namedtuples (reconstructed by dotted path, verified to
      be namedtuple classes before instantiation)
    * list and dict (arbitrarily nested; dict keys may be any supported
      hashable type)

    Tagged values are encoded as single-key objects using a reserved key,
    and user dictionaries are stored as key/value pair lists, so type tags
    can never collide with user-supplied dictionary keys.

    Legacy pickle messages are rejected by default. To read them, pass
    allow_pickle=True -- there is no automatic fallback to pickle when
    JSON parsing fails.
    """
    version = 1
    tag = '__huey__'

    def __init__(self, allow_pickle=False, **kwargs):
        super(JsonSerializer, self).__init__(**kwargs)
        self.allow_pickle = allow_pickle

    def _serialize(self, data):
        message = {'version': self.version, 'data': self._encode(data)}
        return json.dumps(message, separators=(',', ':')).encode('utf-8')

    def _deserialize(self, data):
        raw = data
        if isinstance(data, bytes):
            try:
                data = data.decode('utf-8')
            except UnicodeDecodeError:
                return self._deserialize_legacy(raw)

        try:
            message = json.loads(data)
        except ValueError:
            return self._deserialize_legacy(raw)

        if not isinstance(message, dict) or 'version' not in message:
            raise SerializerError(
                'Invalid message: missing version envelope.')
        version = message['version']
        if version != self.version:
            raise SerializerError(
                'Unsupported message version: %r (expected %r).' %
                (version, self.version))
        if 'data' not in message:
            raise SerializerError('Invalid message: missing "data".')
        return self._decode(message['data'])

    def _deserialize_legacy(self, data):
        if not self.allow_pickle:
            raise SerializerError(
                'Unable to deserialize message: data is not valid JSON. If '
                'this is a legacy pickle message, re-initialize the '
                'serializer with allow_pickle=True.')
        try:
            return pickle.loads(data)
        except Exception:
            raise SerializerError(
                'Unable to deserialize message as JSON or pickle.')

    def _encode(self, obj):
        if obj is None or isinstance(obj, (bool, int, float, str)):
            return obj
        if isinstance(obj, bytes):
            encoded = base64.b64encode(obj).decode('ascii')
            return {self.tag: ['bytes', encoded]}
        if isinstance(obj, datetime.datetime):
            return {self.tag: ['datetime', obj.isoformat()]}
        if isinstance(obj, tuple):
            values = [self._encode(value) for value in obj]
            if hasattr(obj, '_fields'):
                cls = type(obj)
                return {self.tag: ['namedtuple', cls.__module__,
                                   cls.__qualname__, values]}
            return {self.tag: ['tuple', values]}
        if isinstance(obj, list):
            return [self._encode(value) for value in obj]
        if isinstance(obj, dict):
            pairs = [[self._encode(key), self._encode(value)]
                     for key, value in obj.items()]
            return {self.tag: ['dict', pairs]}
        raise SerializerError(
            'Unable to serialize value of type "%s". Supported types are: '
            'None, bool, int, float, str, bytes, datetime, tuple, '
            'namedtuple, list and dict.' % type(obj).__name__)

    def _decode(self, obj):
        if isinstance(obj, list):
            return [self._decode(value) for value in obj]
        if not isinstance(obj, dict):
            return obj

        tagged = obj.get(self.tag)
        if not isinstance(tagged, list) or not tagged:
            raise SerializerError(
                'Invalid message data: malformed or missing type tag.')

        kind = tagged[0]
        if kind == 'bytes' and len(tagged) == 2:
            try:
                return base64.b64decode(tagged[1].encode('ascii'))
            except (TypeError, ValueError) as exc:
                raise SerializerError('Invalid bytes value: %s' % exc)
        if kind == 'datetime' and len(tagged) == 2:
            try:
                return datetime.datetime.fromisoformat(tagged[1])
            except (TypeError, ValueError) as exc:
                raise SerializerError('Invalid datetime value: %s' % exc)
        if kind == 'tuple' and len(tagged) == 2:
            return tuple(self._decode(value) for value in tagged[1])
        if kind == 'dict' and len(tagged) == 2:
            return dict((self._decode(key), self._decode(value))
                        for key, value in tagged[1])
        if kind == 'namedtuple' and len(tagged) == 4:
            return self._decode_namedtuple(tagged[1], tagged[2], tagged[3])
        if kind in ('bytes', 'datetime', 'tuple', 'dict', 'namedtuple'):
            raise SerializerError(
                'Invalid message data: malformed "%s" tag.' % kind)
        raise SerializerError('Unsupported type tag: %r.' % (kind,))

    def _decode_namedtuple(self, module_name, qualname, values):
        try:
            obj = importlib.import_module(module_name)
            for attr in qualname.split('.'):
                obj = getattr(obj, attr)
        except (ImportError, AttributeError):
            raise SerializerError(
                'Unable to resolve namedtuple "%s" in module "%s".' %
                (qualname, module_name))
        if not (isinstance(obj, type) and issubclass(obj, tuple) and
                hasattr(obj, '_fields')):
            raise SerializerError(
                'Refusing to deserialize "%s.%s": not a namedtuple.' %
                (module_name, qualname))
        return obj(*[self._decode(value) for value in values])


class SignedJsonSerializer(SignedSerializer, JsonSerializer):
    """
    Combine the JsonSerializer message format with the HMAC signature
    verification of SignedSerializer. Compression and legacy pickle reads
    can be enabled via the usual keyword arguments.
    """
    pass
