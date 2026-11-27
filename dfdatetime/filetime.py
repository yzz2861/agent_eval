"""FILETIME timestamp implementation."""

import decimal

from dfdatetime import definitions
from dfdatetime import factory
from dfdatetime import filetime_interpretation
from dfdatetime import interface

UINT64_MAX = filetime_interpretation.UINT64_MAX


class FiletimeEpoch(interface.DateTimeEpoch):
    """FILETIME epoch."""

    def __init__(self):
        """Initializes a FILETIME epoch."""
        super().__init__(1601, 1, 1)


class Filetime(interface.DateTimeValues):
    """FILETIME timestamp.

    The FILETIME timestamp is a 64-bit integer that contains the number
    of 100th nano seconds since 1601-01-01 00:00:00.

    Do not confuse this with the FILETIME structure that consists of
    2 x 32-bit integers and is presumed to be unsigned.

    Attributes:
      is_local_time (bool): True if the date and time value is in local time.
    """

    _EPOCH = FiletimeEpoch()

    # The difference between January 1, 1601 and January 1, 1970 in seconds.
    _FILETIME_TO_POSIX_BASE = 11644473600

    def __init__(
        self,
        precision=None,
        time_zone_offset=None,
        timestamp=None,
        convention=None,
        interpretation=None,
    ):
        """Initializes a FILETIME timestamp.

        Args:
          precision (Optional[str]): precision of the date and time value, which
              should be one of the PRECISION_VALUES in definitions.
          time_zone_offset (Optional[int]): time zone offset in number of minutes
              from UTC or None if not set.
          timestamp (Optional[int]): FILETIME timestamp.
          convention (Optional[FiletimeProvenanceConvention]): provenance
              convention that defines the interpretation of sentinel values.
          interpretation (Optional[str]): interpretation identity, such as
              "real_time", "not_set" or "never".
        """
        super().__init__(
            precision=precision or definitions.PRECISION_100_NANOSECONDS,
            time_zone_offset=time_zone_offset,
        )
        self._convention = None
        self._interpretation = None
        self.convention = convention
        self.interpretation = interpretation
        self._timestamp = timestamp

    @property
    def convention(self):
        """FiletimeProvenanceConvention: provenance convention or None if not set."""
        return self._convention

    @convention.setter
    def convention(self, convention):
        """Sets the provenance convention.

        Args:
          convention (FiletimeProvenanceConvention): provenance convention or
              None if not set.

        Raises:
          TypeError: if the convention type is not supported.
        """
        self._convention = self._CoerceConvention(convention)

    @property
    def interpretation(self):
        """str: interpretation identity or None if not set or unresolved."""
        return self.GetInterpretation().interpretation

    @interpretation.setter
    def interpretation(self, interpretation):
        """Sets the interpretation identity.

        Args:
          interpretation (str): interpretation identity or None if not set.

        Raises:
          ValueError: if the interpretation identity is not supported.
        """
        if interpretation is not None:
            interpretation = filetime_interpretation.NormalizeInterpretation(
                interpretation
            )

        self._interpretation = interpretation

    def _CoerceConvention(self, convention):
        """Coerces a provenance convention into a convention object.

        Args:
          convention (FiletimeProvenanceConvention|dict[str, object]): provenance
              convention or serializable convention.

        Returns:
          FiletimeProvenanceConvention: provenance convention or None if not set.

        Raises:
          TypeError: if the convention type is not supported.
        """
        if convention is None:
            return None
        if isinstance(convention, dict):
            convention_type = filetime_interpretation.FiletimeProvenanceConvention
            return convention_type.FromSerializableDict(convention)
        if not isinstance(
            convention, filetime_interpretation.FiletimeProvenanceConvention
        ):
            raise TypeError("Unsupported provenance convention type.")

        return convention

    @property
    def timestamp(self):
        """int: FILETIME timestamp or None if not set."""
        return self._timestamp

    def _GetNormalizedTimestamp(self):
        """Retrieves the normalized timestamp.

        Returns:
          decimal.Decimal: normalized timestamp, which contains the number of
              seconds since January 1, 1970 00:00:00 and a fraction of second used
              for increased precision, or None if the normalized timestamp cannot be
              determined.
        """
        if self._normalized_timestamp is None:
            if (
                self._timestamp is not None
                and self._timestamp >= 0
                and self._timestamp <= self._UINT64_MAX
            ):
                self._normalized_timestamp = (
                    decimal.Decimal(self._timestamp) / self._100_NANOSECONDS_PER_SECOND
                )
                self._normalized_timestamp -= self._FILETIME_TO_POSIX_BASE

                if self._time_zone_offset:
                    self._normalized_timestamp -= self._time_zone_offset * 60

        return self._normalized_timestamp

    def _GetNormalizedRangeBoundary(self, value):
        """Retrieves a normalized timestamp for a time range boundary.

        Args:
          value (Filetime|DateTimeValues|decimal.Decimal|float|int): time range
              boundary. An integer is interpreted as a raw FILETIME timestamp,
              a decimal or float as a normalized POSIX timestamp.

        Returns:
          decimal.Decimal: normalized timestamp.

        Raises:
          TypeError: if the boundary type is not supported.
          ValueError: if the boundary is out of bounds or cannot be normalized.
        """
        if isinstance(value, interface.DateTimeValues):
            normalized_timestamp = (
                value._GetNormalizedTimestamp()
            )  # pylint: disable=protected-access
        elif isinstance(value, int) and not isinstance(value, bool):
            if value < 0 or value > self._UINT64_MAX:
                raise ValueError(f"Range boundary: {value:d} out of bounds.")

            normalized_timestamp = (
                decimal.Decimal(value) / self._100_NANOSECONDS_PER_SECOND
            )
            normalized_timestamp -= self._FILETIME_TO_POSIX_BASE
        elif isinstance(value, (decimal.Decimal, float)):
            normalized_timestamp = decimal.Decimal(str(value))
        else:
            raise TypeError("Unsupported time range boundary type.")

        if normalized_timestamp is None:
            raise ValueError("Time range boundary cannot be normalized.")

        return normalized_timestamp

    def CopyFromDateTimeString(self, time_string):
        """Copies a FILETIME timestamp from a date and time string.

        Args:
          time_string (str): date and time value formatted as:
              YYYY-MM-DD hh:mm:ss.######[+-]##:##

              Where # are numeric digits ranging from 0 to 9 and the seconds
              fraction can be either 3, 6 or 9 digits. The time of day, seconds
              fraction and time zone offset are optional. The default time zone
              is UTC.

        Raises:
          ValueError: if the time string is invalid or not supported.
        """
        date_time_values = self._CopyDateTimeFromString(time_string)

        year = date_time_values.get("year", 0)
        month = date_time_values.get("month", 0)
        day_of_month = date_time_values.get("day_of_month", 0)
        hours = date_time_values.get("hours", 0)
        minutes = date_time_values.get("minutes", 0)
        seconds = date_time_values.get("seconds", 0)
        nanoseconds = date_time_values.get("nanoseconds", 0)
        time_zone_offset = date_time_values.get("time_zone_offset")

        if year < 1601:
            raise ValueError(f"Year value not supported: {year!s}.")

        nanoseconds, _ = divmod(nanoseconds, 100)

        timestamp = self._GetNumberOfSecondsFromElements(
            year, month, day_of_month, hours, minutes, seconds
        )
        timestamp += self._FILETIME_TO_POSIX_BASE
        timestamp *= self._100_NANOSECONDS_PER_SECOND
        timestamp += nanoseconds

        self._normalized_timestamp = None
        self._timestamp = timestamp
        self._time_zone_offset = time_zone_offset

    def CopyToDateTimeString(self):
        """Copies the FILETIME timestamp to a date and time string.

        Returns:
          str: date and time value formatted as: "YYYY-MM-DD hh:mm:ss.#######" or
              None if the timestamp is missing or invalid.
        """
        if (
            self._timestamp is None
            or self._timestamp < 0
            or self._timestamp > self._UINT64_MAX
        ):
            return None

        timestamp, fraction_of_second = divmod(
            self._timestamp, self._100_NANOSECONDS_PER_SECOND
        )
        number_of_days, hours, minutes, seconds = self._GetTimeValues(timestamp)

        year, month, day_of_month = self._GetDateValuesWithEpoch(
            number_of_days, self._EPOCH
        )
        return (
            f"{year:04d}-{month:02d}-{day_of_month:02d} "
            f"{hours:02d}:{minutes:02d}:{seconds:02d}.{fraction_of_second:07d}"
        )

    def CopyToSerializableDict(self, convention=None, include_interpretation=False):
        """Copies the date time value to a serializable dictionary.

        Args:
          convention (Optional[FiletimeProvenanceConvention]): provenance
              convention to apply. If not set the convention of the date time
              value is used.
          include_interpretation (Optional[bool]): True to include the feasible
              interpretations when no convention is used.

        Returns:
          dict[str, object]: serializable dictionary.
        """
        serializable_dict = self._CreateSerializableDict()

        serializable_dict["timestamp"] = self._timestamp

        if convention is None:
            convention = self._convention
        else:
            convention = self._CoerceConvention(convention)

        if convention is not None:
            interpretation_record = self.GetInterpretation(convention=convention)
            serializable_dict["provenance"] = convention.CopyToSerializableDict()
            serializable_dict["interpretation"] = interpretation_record.interpretation
            if include_interpretation:
                serializable_dict["feasible_interpretations"] = list(
                    interpretation_record.feasible_interpretations
                )
        elif include_interpretation:
            interpretation_record = self.GetInterpretation()
            serializable_dict["interpretation"] = interpretation_record.interpretation
            serializable_dict["feasible_interpretations"] = list(
                interpretation_record.feasible_interpretations
            )

        return serializable_dict

    def GetInterpretation(self, convention=None):
        """Retrieves the interpretation record of the FILETIME timestamp.

        Args:
          convention (Optional[FiletimeProvenanceConvention]): provenance
              convention to apply. If not set the convention of the date time
              value is used. If neither is set the feasible interpretations are
              left in the record.

        Returns:
          FiletimeInterpretationRecord: interpretation record.
        """
        if convention is None:
            convention = self._convention
        else:
            convention = self._CoerceConvention(convention)

        if convention is not None:
            return filetime_interpretation.FiletimeInterpretationRecord(
                self._timestamp, convention=convention
            )

        return filetime_interpretation.FiletimeInterpretationRecord(
            self._timestamp, interpretation=self._interpretation
        )

    def GetTimestampInterpretation(self, convention=None):
        """Retrieves the interpretation record of the FILETIME timestamp.

        Args:
          convention (Optional[FiletimeProvenanceConvention]): provenance
              convention to apply.

        Returns:
          FiletimeInterpretationRecord: interpretation record.
        """
        return self.GetInterpretation(convention=convention)

    def IsInTimeRange(self, start, end, convention=None, allow_ambiguous=False):
        """Determines if the FILETIME timestamp is within a time range.

        Only a timestamp that is interpreted as a real date and time value
        participates in the time range query. An ambiguous timestamp without a
        convention is excluded unless allow_ambiguous is True.

        Args:
          start (Filetime|DateTimeValues|decimal.Decimal|float|int): start of
              the time range, which is inclusive.
          end (Filetime|DateTimeValues|decimal.Decimal|float|int): end of the
              time range, which is inclusive.
          convention (Optional[FiletimeProvenanceConvention]): provenance
              convention to apply. If not set the convention of the date time
              value is used.
          allow_ambiguous (Optional[bool]): True if an ambiguous timestamp that
              can be a real date and time value should participate.

        Returns:
          bool: True if the timestamp participates in the time range.

        Raises:
          TypeError: if a time range boundary type is not supported.
          ValueError: if a time range boundary is out of bounds or the start is
              after the end.
        """
        normalized_start = self._GetNormalizedRangeBoundary(start)
        normalized_end = self._GetNormalizedRangeBoundary(end)

        if normalized_start > normalized_end:
            raise ValueError("Time range start is after the end.")

        interpretation_record = self.GetInterpretation(convention=convention)

        if interpretation_record.interpretation is not None:
            if not interpretation_record.is_real_time:
                return False
        elif interpretation_record.feasible_interpretations != (
            filetime_interpretation.FiletimeInterpretation.REAL_TIME,
        ):
            if not allow_ambiguous or not interpretation_record.is_ambiguous:
                return False
            if (
                filetime_interpretation.FiletimeInterpretation.REAL_TIME
                not in interpretation_record.feasible_interpretations
            ):
                return False

        normalized_timestamp = self._GetNormalizedTimestamp()
        if normalized_timestamp is None:
            return False

        return normalized_start <= normalized_timestamp <= normalized_end

    InTimeRange = IsInTimeRange


factory.Factory.RegisterDateTimeValues(Filetime)
