"""FILETIME interpretation and provenance conventions."""

UINT64_MAX = (1 << 64) - 1


class FiletimeInterpretation:
    """Interpretation identities for a raw FILETIME timestamp."""

    NEVER = "never"
    NOT_SET = "not_set"
    NOTSET = NOT_SET
    REAL = "real_time"
    REAL_TIME = "real_time"

    VALUES = frozenset([NEVER, NOT_SET, REAL_TIME])


NEVER = FiletimeInterpretation.NEVER
NOT_SET = FiletimeInterpretation.NOT_SET
REAL_TIME = FiletimeInterpretation.REAL_TIME

INTERPRETATION_NEVER = FiletimeInterpretation.NEVER
INTERPRETATION_NOT_SET = FiletimeInterpretation.NOT_SET
INTERPRETATION_REAL_TIME = FiletimeInterpretation.REAL_TIME


_INTERPRETATION_ALIASES = {
    "never": FiletimeInterpretation.NEVER,
    "not_set": FiletimeInterpretation.NOT_SET,
    "notset": FiletimeInterpretation.NOT_SET,
    "real": FiletimeInterpretation.REAL_TIME,
    "real_time": FiletimeInterpretation.REAL_TIME,
    "realtime": FiletimeInterpretation.REAL_TIME,
    "valid": FiletimeInterpretation.REAL_TIME,
}


def NormalizeInterpretation(interpretation):
    """Normalizes an interpretation identity.

    Args:
      interpretation (str): interpretation identity, such as "real_time".

    Returns:
      str: normalized interpretation identity.

    Raises:
      ValueError: if the interpretation identity is not supported.
    """
    if not isinstance(interpretation, str):
        raise ValueError(f"Unsupported interpretation: {interpretation!s}.")

    normalized_interpretation = interpretation.strip().lower().replace("-", "_")
    normalized_interpretation = normalized_interpretation.replace(" ", "_")

    interpretation_value = _INTERPRETATION_ALIASES.get(normalized_interpretation)
    if interpretation_value is None:
        raise ValueError(f"Unsupported interpretation: {interpretation:s}.")

    return interpretation_value


def _ParseTimestamp(timestamp):
    """Parses a raw FILETIME timestamp from a serializable value.

    Args:
      timestamp (int|str): raw timestamp.

    Returns:
      int: raw timestamp.

    Raises:
      ValueError: if the timestamp is not an integer value.
    """
    if isinstance(timestamp, str):
        try:
            timestamp = int(timestamp, 10)
        except ValueError as exception:
            raise ValueError(
                f"Unable to parse sentinel timestamp with error: {exception!s}"
            )
    if not isinstance(timestamp, int) or isinstance(timestamp, bool):
        raise ValueError("Sentinel timestamp must be an integer.")

    return timestamp


def GetFeasibleInterpretations(timestamp):
    """Determines the feasible interpretations of a raw FILETIME timestamp.

    A zero timestamp can either be a real date and time value, that represents
    January 1, 1601, or a value that is not set. The maximum uint64 value can
    either be a real date and time value or a value that means never.

    Args:
      timestamp (int): raw FILETIME timestamp.

    Returns:
      tuple[str, ...]: feasible interpretation identities.
    """
    if not isinstance(timestamp, int) or isinstance(timestamp, bool):
        return ()
    if timestamp < 0 or timestamp > UINT64_MAX:
        return ()

    if timestamp == 0:
        return (
            FiletimeInterpretation.REAL_TIME,
            FiletimeInterpretation.NOT_SET,
        )
    if timestamp in (0xFFFFFFFF, UINT64_MAX):
        return (
            FiletimeInterpretation.REAL_TIME,
            FiletimeInterpretation.NEVER,
        )

    return (FiletimeInterpretation.REAL_TIME,)


class FiletimeProvenanceConvention:
    """Caller-provided convention that interprets FILETIME sentinel values.

    A convention records who produced or consumed the raw value and which
    version of that producer's rules was used. All values that are not listed
    as sentinel values are interpreted as real date and time values.

    Attributes:
      description (str): optional human-readable description of the convention.
      producer (str): producer or consumer that defined the convention.
      version (str|int): version of the producer's convention.
    """

    def __init__(
        self,
        producer=None,
        version=None,
        sentinel_interpretations=None,
        description=None,
        identifier=None,
        convention_version=None,
    ):
        """Initializes a FILETIME provenance convention.

        Args:
          producer (Optional[str]): producer or consumer that defined the
              convention. An identifier can be used instead.
          version (Optional[str|int]): version of the producer's convention. A
              convention version can be used instead.
          sentinel_interpretations (Optional[dict[int, str]]): interpretation
              identities for raw FILETIME sentinel values.
          description (Optional[str]): human-readable description of the
              convention.
          identifier (Optional[str]): alias of producer.
          convention_version (Optional[str|int]): alias of version.

        Raises:
          TypeError: if a value type is not supported.
          ValueError: if a producer, version or interpretation is not supported.
        """
        if producer is None:
            producer = identifier
        if version is None:
            version = convention_version

        if not isinstance(producer, str) or not producer.strip():
            raise ValueError("Producer must be a non-empty string.")
        if not isinstance(version, (str, int)) or isinstance(version, bool):
            raise TypeError("Version must be a string or an integer.")
        if isinstance(version, str) and not version.strip():
            raise ValueError("Version must be a non-empty string.")

        self.description = description
        self.producer = producer.strip()
        self.version = version

        self._sentinel_interpretations = {}

        for timestamp, interpretation in (sentinel_interpretations or {}).items():
            if not isinstance(timestamp, int) or isinstance(timestamp, bool):
                raise TypeError("Sentinel timestamp must be an integer.")
            if timestamp < 0 or timestamp > UINT64_MAX:
                raise ValueError(f"Sentinel timestamp: {timestamp:d} out of bounds.")

            interpretation = NormalizeInterpretation(interpretation)
            self._sentinel_interpretations[timestamp] = interpretation

    @property
    def convention_version(self):
        """str|int: version of the producer's convention."""
        return self.version

    @property
    def identifier(self):
        """str: producer or consumer that defined the convention."""
        return self.producer

    @property
    def sentinel_interpretations(self):
        """dict[int, str]: interpretation identities of sentinel values."""
        return dict(self._sentinel_interpretations)

    def InterpretTimestamp(self, timestamp):
        """Determines the interpretation of a raw FILETIME timestamp.

        Args:
          timestamp (int): raw FILETIME timestamp or None if not set.

        Returns:
          str: interpretation identity or None if the timestamp is not set or
              out of bounds.
        """
        if not isinstance(timestamp, int) or isinstance(timestamp, bool):
            return None
        if timestamp < 0 or timestamp > UINT64_MAX:
            return None

        return self._sentinel_interpretations.get(
            timestamp, FiletimeInterpretation.REAL_TIME
        )

    Interpret = InterpretTimestamp
    interpret = InterpretTimestamp

    def CopyToSerializableDict(self):
        """Copies the convention to a serializable dictionary.

        Returns:
          dict[str, object]: serializable dictionary.
        """
        serializable_dict = {
            "producer": self.producer,
            "version": self.version,
            "sentinel_interpretations": [
                {"timestamp": timestamp, "interpretation": interpretation}
                for timestamp, interpretation in sorted(
                    self._sentinel_interpretations.items()
                )
            ],
        }
        if self.description:
            serializable_dict["description"] = self.description

        return serializable_dict

    @classmethod
    def FromSerializableDict(cls, serializable_dict):
        """Creates a convention from a serializable dictionary.

        Args:
          serializable_dict (dict[str, object]): serializable convention.

        Returns:
          FiletimeProvenanceConvention: provenance convention.

        Raises:
          TypeError: if the serializable dictionary is not a dictionary.
          ValueError: if the serializable dictionary is malformed.
        """
        if not isinstance(serializable_dict, dict):
            raise TypeError("Serializable convention must be a dictionary.")

        producer = serializable_dict.get(
            "producer", serializable_dict.get("identifier")
        )
        version = serializable_dict.get(
            "version", serializable_dict.get("convention_version")
        )
        if producer is None or version is None:
            raise ValueError("Serializable convention misses producer or version.")

        sentinel_interpretations = serializable_dict.get(
            "sentinel_interpretations", serializable_dict.get("sentinels", {})
        )

        interpretations = {}
        if isinstance(sentinel_interpretations, dict):
            for timestamp, interpretation in sentinel_interpretations.items():
                timestamp = _ParseTimestamp(timestamp)
                interpretations[timestamp] = interpretation
        elif isinstance(sentinel_interpretations, list):
            for sentinel in sentinel_interpretations:
                if not isinstance(sentinel, dict):
                    raise ValueError("Serializable sentinel must be a dictionary.")
                timestamp = sentinel.get("timestamp")
                interpretation = sentinel.get("interpretation")
                if timestamp is None or interpretation is None:
                    raise ValueError("Serializable sentinel misses a value.")
                interpretations[_ParseTimestamp(timestamp)] = interpretation
        else:
            raise ValueError("Serializable sentinel interpretations are malformed.")

        return cls(
            producer=producer,
            version=version,
            sentinel_interpretations=interpretations,
            description=serializable_dict.get("description"),
        )


class FiletimeInterpretationRecord:
    """Record of the interpretation of a raw FILETIME timestamp.

    Attributes:
      convention (FiletimeProvenanceConvention): convention that was applied or
          None if no convention was provided.
      feasible_interpretations (tuple[str, ...]): interpretations that remain
          feasible when no convention resolves the ambiguity.
      timestamp (int): raw FILETIME timestamp.
    """

    def __init__(self, timestamp, convention=None, interpretation=None):
        """Initializes a FILETIME interpretation record.

        Args:
          timestamp (int): raw FILETIME timestamp.
          convention (Optional[FiletimeProvenanceConvention]): convention that
              was applied.
          interpretation (Optional[str]): interpretation identity, which is
              determined from the convention if not set.

        Raises:
          ValueError: if the interpretation identity is not supported.
        """
        self.convention = convention
        self.timestamp = timestamp

        if interpretation is None and convention is not None:
            interpretation = convention.InterpretTimestamp(timestamp)
        if interpretation is not None:
            interpretation = NormalizeInterpretation(interpretation)

        self.interpretation = interpretation

        if interpretation is not None:
            self.feasible_interpretations = (interpretation,)
        else:
            self.feasible_interpretations = GetFeasibleInterpretations(timestamp)

    @property
    def convention_version(self):
        """str|int: version of the convention or None if no convention was used."""
        if self.convention is None:
            return None
        return self.convention.version

    @property
    def is_ambiguous(self):
        """bool: True if more than one interpretation remains feasible."""
        return self.interpretation is None and len(self.feasible_interpretations) > 1

    @property
    def is_real_time(self):
        """bool: True if the timestamp was interpreted as a real date and time."""
        return self.interpretation == FiletimeInterpretation.REAL_TIME

    @property
    def producer(self):
        """str: producer of the convention or None if no convention was used."""
        if self.convention is None:
            return None
        return self.convention.producer

    @property
    def raw_value(self):
        """int: raw FILETIME timestamp."""
        return self.timestamp

    @property
    def value(self):
        """int: raw FILETIME timestamp."""
        return self.timestamp

    def CopyToSerializableDict(self):
        """Copies the interpretation record to a serializable dictionary.

        Returns:
          dict[str, object]: serializable dictionary.
        """
        return {
            "timestamp": self.timestamp,
            "producer": self.producer,
            "convention_version": self.convention_version,
            "interpretation": self.interpretation,
            "feasible_interpretations": list(self.feasible_interpretations),
            "is_real_time": self.is_real_time,
        }


ProvenanceConvention = FiletimeProvenanceConvention
InterpretationRecord = FiletimeInterpretationRecord
