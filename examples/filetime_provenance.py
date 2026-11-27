#!/usr/bin/env python3
"""Shows how FILETIME provenance conventions resolve ambiguous raw values."""

from dfdatetime import filetime
from dfdatetime import filetime_interpretation
from dfdatetime import serializer


def BuildConventions():
    """Builds the conventions of two producers.

    Returns:
      tuple[FiletimeProvenanceConvention,
            FiletimeProvenanceConvention]: producer conventions.
    """
    ntfs_convention = filetime_interpretation.FiletimeProvenanceConvention(
        producer="ntfs",
        version="1",
        sentinel_interpretations={
            0: filetime_interpretation.FiletimeInterpretation.REAL_TIME,
            filetime_interpretation.UINT64_MAX: (
                filetime_interpretation.FiletimeInterpretation.NEVER
            ),
        },
    )
    win32_convention = filetime_interpretation.FiletimeProvenanceConvention(
        producer="win32-setfiletime",
        version="1",
        sentinel_interpretations={
            0: filetime_interpretation.FiletimeInterpretation.NOT_SET,
            filetime_interpretation.UINT64_MAX: (
                filetime_interpretation.FiletimeInterpretation.NEVER
            ),
        },
    )
    return ntfs_convention, win32_convention


def Main():
    """Shows three examples and queries the time range after a round-trip."""
    ntfs_convention, win32_convention = BuildConventions()
    zero = 0
    maximum = filetime_interpretation.UINT64_MAX

    examples = [
        ("ntfs zero", filetime.Filetime(timestamp=zero, convention=ntfs_convention)),
        ("win32 zero", filetime.Filetime(timestamp=zero, convention=win32_convention)),
        (
            "win32 maximum",
            filetime.Filetime(timestamp=maximum, convention=win32_convention),
        ),
    ]

    range_start = filetime.Filetime(timestamp=zero)
    range_end = filetime.Filetime(timestamp=maximum)

    for name, date_time_value in examples:
        serialized = serializer.Serializer.ConvertDateTimeValuesToJSON(date_time_value)
        round_trip_value = serializer.Serializer.ConvertJSONToDateTimeValues(
            dict(serialized)
        )
        record = round_trip_value.GetInterpretation()

        print(
            f"{name}: raw={record.timestamp} "
            f"producer={record.producer} "
            f"version={record.convention_version} "
            f"interpretation={record.interpretation} "
            f"in_range={round_trip_value.IsInTimeRange(range_start, range_end)}"
        )


if __name__ == "__main__":
    Main()
