#!/usr/bin/env python3
"""Tests for FILETIME interpretation and provenance conventions."""

import decimal
import unittest

from dfdatetime import filetime
from dfdatetime import filetime_interpretation
from dfdatetime import serializer


class FiletimeProvenanceConventionTest(unittest.TestCase):
    """Tests for the FILETIME provenance convention."""

    def testInitialize(self):
        """Tests the __init__ function."""
        convention = filetime_interpretation.FiletimeProvenanceConvention(
            producer="ntfs",
            version="1",
            sentinel_interpretations={
                0: filetime_interpretation.FiletimeInterpretation.NOT_SET
            },
            description="NTFS zero means not set.",
        )

        self.assertEqual(convention.producer, "ntfs")
        self.assertEqual(convention.identifier, "ntfs")
        self.assertEqual(convention.version, "1")
        self.assertEqual(convention.convention_version, "1")
        self.assertEqual(convention.description, "NTFS zero means not set.")
        self.assertEqual(
            convention.sentinel_interpretations,
            {0: filetime_interpretation.FiletimeInterpretation.NOT_SET},
        )

        with self.assertRaises(ValueError):
            filetime_interpretation.FiletimeProvenanceConvention("", "1")

        with self.assertRaises(TypeError):
            filetime_interpretation.FiletimeProvenanceConvention("ntfs", True)

        with self.assertRaises(ValueError):
            filetime_interpretation.FiletimeProvenanceConvention("ntfs", "1", {0: "?"})

        with self.assertRaises(ValueError):
            filetime_interpretation.FiletimeProvenanceConvention(
                "ntfs", "1", {-1: filetime_interpretation.FiletimeInterpretation.NEVER}
            )

    def testInterpretTimestamp(self):
        """Tests the InterpretTimestamp function."""
        convention = filetime_interpretation.FiletimeProvenanceConvention(
            "win32-setfiletime",
            "1",
            {
                0: filetime_interpretation.FiletimeInterpretation.NOT_SET,
                filetime_interpretation.UINT64_MAX: (
                    filetime_interpretation.FiletimeInterpretation.NEVER
                ),
            },
        )

        self.assertEqual(
            convention.interpret(0),
            filetime_interpretation.FiletimeInterpretation.NOT_SET,
        )
        self.assertEqual(
            convention.interpret(filetime_interpretation.UINT64_MAX),
            filetime_interpretation.FiletimeInterpretation.NEVER,
        )
        self.assertEqual(
            convention.interpret(42),
            filetime_interpretation.FiletimeInterpretation.REAL_TIME,
        )
        self.assertIsNone(convention.interpret(None))
        self.assertIsNone(convention.interpret(-1))
        self.assertIsNone(convention.interpret(filetime_interpretation.UINT64_MAX + 1))

    def testCopyToSerializableDict(self):
        """Tests the CopyToSerializableDict function."""
        convention = filetime_interpretation.FiletimeProvenanceConvention(
            "vendor-a",
            "2026.1",
            {0: "not-set", filetime_interpretation.UINT64_MAX: "never"},
            description="Vendor A sentinel convention.",
        )

        serializable_dict = convention.CopyToSerializableDict()
        self.assertEqual(
            serializable_dict,
            {
                "producer": "vendor-a",
                "version": "2026.1",
                "sentinel_interpretations": [
                    {"timestamp": 0, "interpretation": "not_set"},
                    {
                        "timestamp": filetime_interpretation.UINT64_MAX,
                        "interpretation": "never",
                    },
                ],
                "description": "Vendor A sentinel convention.",
            },
        )

    def testFromSerializableDict(self):
        """Tests the FromSerializableDict function."""
        serializable_dict = {
            "producer": "vendor-b",
            "version": 2,
            "sentinel_interpretations": [
                {"timestamp": 0, "interpretation": "real_time"},
                {
                    "timestamp": str(filetime_interpretation.UINT64_MAX),
                    "interpretation": "never",
                },
            ],
        }

        convention = (
            filetime_interpretation.FiletimeProvenanceConvention.FromSerializableDict(
                serializable_dict
            )
        )

        self.assertEqual(convention.producer, "vendor-b")
        self.assertEqual(convention.version, 2)
        self.assertEqual(
            convention.interpret(0),
            filetime_interpretation.FiletimeInterpretation.REAL_TIME,
        )
        self.assertEqual(
            convention.interpret(filetime_interpretation.UINT64_MAX),
            filetime_interpretation.FiletimeInterpretation.NEVER,
        )

        with self.assertRaises(TypeError):
            filetime_interpretation.FiletimeProvenanceConvention.FromSerializableDict(
                "not a dictionary"
            )

        with self.assertRaises(ValueError):
            filetime_interpretation.FiletimeProvenanceConvention.FromSerializableDict(
                {}
            )


class FiletimeInterpretationRecordTest(unittest.TestCase):
    """Tests for the FILETIME interpretation record."""

    def testInitialize(self):
        """Tests the __init__ function."""
        convention = filetime_interpretation.FiletimeProvenanceConvention(
            "vendor-c",
            "1",
            {
                0: filetime_interpretation.FiletimeInterpretation.NOT_SET,
                filetime_interpretation.UINT64_MAX: (
                    filetime_interpretation.FiletimeInterpretation.NEVER
                ),
            },
        )

        record = filetime_interpretation.FiletimeInterpretationRecord(
            0, convention=convention
        )
        self.assertEqual(record.timestamp, 0)
        self.assertEqual(record.raw_value, 0)
        self.assertEqual(record.producer, "vendor-c")
        self.assertEqual(record.convention_version, "1")
        self.assertEqual(
            record.interpretation,
            filetime_interpretation.FiletimeInterpretation.NOT_SET,
        )
        self.assertFalse(record.is_real_time)
        self.assertFalse(record.is_ambiguous)

        record = filetime_interpretation.FiletimeInterpretationRecord(0)
        self.assertIsNone(record.interpretation)
        self.assertIsNone(record.producer)
        self.assertIsNone(record.convention_version)
        self.assertTrue(record.is_ambiguous)
        self.assertEqual(
            record.feasible_interpretations,
            (
                filetime_interpretation.FiletimeInterpretation.REAL_TIME,
                filetime_interpretation.FiletimeInterpretation.NOT_SET,
            ),
        )

    def testCopyToSerializableDict(self):
        """Tests the CopyToSerializableDict function."""
        convention = filetime_interpretation.FiletimeProvenanceConvention(
            "vendor-d", "7", {0: filetime_interpretation.FiletimeInterpretation.NEVER}
        )
        record = filetime_interpretation.FiletimeInterpretationRecord(
            0, convention=convention
        )

        self.assertEqual(
            record.CopyToSerializableDict(),
            {
                "timestamp": 0,
                "producer": "vendor-d",
                "convention_version": "7",
                "interpretation": "never",
                "feasible_interpretations": ["never"],
                "is_real_time": False,
            },
        )


class FiletimeInterpretationTest(unittest.TestCase):
    """Tests for interpretation of FILETIME date and time values."""

    def testGetInterpretation(self):
        """Tests the GetInterpretation function."""
        filetime_object = filetime.Filetime(timestamp=0)

        record = filetime_object.GetInterpretation()
        self.assertIsNone(record.interpretation)
        self.assertEqual(
            record.feasible_interpretations,
            (
                filetime_interpretation.FiletimeInterpretation.REAL_TIME,
                filetime_interpretation.FiletimeInterpretation.NOT_SET,
            ),
        )

        record = filetime_object.GetTimestampInterpretation()
        self.assertEqual(
            record.feasible_interpretations,
            (
                filetime_interpretation.FiletimeInterpretation.REAL_TIME,
                filetime_interpretation.FiletimeInterpretation.NOT_SET,
            ),
        )

        filetime_object = filetime.Filetime(
            timestamp=filetime_interpretation.UINT64_MAX
        )
        record = filetime_object.GetInterpretation()
        self.assertEqual(
            record.feasible_interpretations,
            (
                filetime_interpretation.FiletimeInterpretation.REAL_TIME,
                filetime_interpretation.FiletimeInterpretation.NEVER,
            ),
        )

        filetime_object = filetime.Filetime(timestamp=0x01CB3A623D0A17CE)
        record = filetime_object.GetInterpretation()
        self.assertEqual(
            record.feasible_interpretations,
            (filetime_interpretation.FiletimeInterpretation.REAL_TIME,),
        )

    def testCopyToSerializableDict(self):
        """Tests the CopyToSerializableDict function."""
        filetime_object = filetime.Filetime(timestamp=0)

        self.assertEqual(
            filetime_object.CopyToSerializableDict(),
            {
                "__class_name__": "Filetime",
                "__type__": "DateTimeValues",
                "timestamp": 0,
            },
        )

        self.assertEqual(
            filetime_object.CopyToSerializableDict(include_interpretation=True),
            {
                "__class_name__": "Filetime",
                "__type__": "DateTimeValues",
                "timestamp": 0,
                "interpretation": None,
                "feasible_interpretations": ["real_time", "not_set"],
            },
        )

        convention = filetime_interpretation.FiletimeProvenanceConvention(
            "vendor-e",
            "1",
            {0: filetime_interpretation.FiletimeInterpretation.REAL_TIME},
        )

        filetime_object = filetime.Filetime(timestamp=0, convention=convention)
        self.assertEqual(
            filetime_object.CopyToSerializableDict(),
            {
                "__class_name__": "Filetime",
                "__type__": "DateTimeValues",
                "timestamp": 0,
                "provenance": {
                    "producer": "vendor-e",
                    "version": "1",
                    "sentinel_interpretations": [
                        {"timestamp": 0, "interpretation": "real_time"}
                    ],
                },
                "interpretation": "real_time",
            },
        )

    def testTimeRangeThreeProducerSamples(self):
        """Tests round-trip and time range query of three producer samples."""
        real_time_convention = filetime_interpretation.FiletimeProvenanceConvention(
            "ntfs",
            "1",
            {
                0: filetime_interpretation.FiletimeInterpretation.REAL_TIME,
                filetime_interpretation.UINT64_MAX: (
                    filetime_interpretation.FiletimeInterpretation.NEVER
                ),
            },
        )
        sentinel_convention = filetime_interpretation.FiletimeProvenanceConvention(
            "win32-setfiletime",
            "1",
            {
                0: filetime_interpretation.FiletimeInterpretation.NOT_SET,
                filetime_interpretation.UINT64_MAX: (
                    filetime_interpretation.FiletimeInterpretation.NEVER
                ),
            },
        )

        samples = [
            (
                "ntfs-zero-is-1601",
                filetime.Filetime(timestamp=0, convention=real_time_convention),
                filetime_interpretation.FiletimeInterpretation.REAL_TIME,
                True,
            ),
            (
                "win32-zero-is-not-set",
                filetime.Filetime(timestamp=0, convention=sentinel_convention),
                filetime_interpretation.FiletimeInterpretation.NOT_SET,
                False,
            ),
            (
                "win32-max-is-never",
                filetime.Filetime(
                    timestamp=filetime_interpretation.UINT64_MAX,
                    convention=sentinel_convention,
                ),
                filetime_interpretation.FiletimeInterpretation.NEVER,
                False,
            ),
        ]

        range_start = filetime.Filetime(timestamp=0)
        range_end = filetime.Filetime(timestamp=filetime_interpretation.UINT64_MAX)

        participating_samples = []
        for (
            name,
            date_time_value,
            expected_interpretation,
            expected_in_range,
        ) in samples:
            serialized_dict = serializer.Serializer.ConvertDateTimeValuesToJSON(
                date_time_value
            )
            round_trip_value = serializer.Serializer.ConvertJSONToDateTimeValues(
                dict(serialized_dict)
            )

            self.assertEqual(round_trip_value.timestamp, date_time_value.timestamp)
            self.assertEqual(
                round_trip_value.GetInterpretation().interpretation,
                expected_interpretation,
            )
            self.assertEqual(round_trip_value.convention.version, "1")

            in_time_range = round_trip_value.IsInTimeRange(range_start, range_end)
            self.assertEqual(in_time_range, expected_in_range, name)
            if in_time_range:
                participating_samples.append(name)

        self.assertEqual(participating_samples, ["ntfs-zero-is-1601"])

    def testTimeRangeWithoutConvention(self):
        """Tests time range queries without a provenance convention."""
        range_start = filetime.Filetime(timestamp=0)
        range_end = filetime.Filetime(timestamp=filetime_interpretation.UINT64_MAX)

        filetime_object = filetime.Filetime(timestamp=0x01CB3A623D0A17CE)
        self.assertTrue(filetime_object.IsInTimeRange(range_start, range_end))

        filetime_object = filetime.Filetime(timestamp=0)
        self.assertFalse(filetime_object.IsInTimeRange(range_start, range_end))
        self.assertTrue(
            filetime_object.IsInTimeRange(range_start, range_end, allow_ambiguous=True)
        )

        with self.assertRaises(ValueError):
            filetime_object.IsInTimeRange(range_end, range_start)

        with self.assertRaises(TypeError):
            filetime_object.IsInTimeRange("not a boundary", range_end)

        filetime_object = filetime.Filetime(timestamp=0x01CB3A623D0A17CE)
        self.assertTrue(
            filetime_object.IsInTimeRange(
                decimal.Decimal("1281647191"), decimal.Decimal("1281647192")
            )
        )

    def testDeserializeLegacyFormat(self):
        """Tests deserialization of the legacy serialization format."""
        serialized_dict = {
            "__class_name__": "Filetime",
            "__type__": "DateTimeValues",
            "timestamp": 0x01CB3A623D0A17CE,
        }

        date_time_value = serializer.Serializer.ConvertJSONToDateTimeValues(
            dict(serialized_dict)
        )
        self.assertEqual(date_time_value.timestamp, 0x01CB3A623D0A17CE)
        self.assertIsNone(date_time_value.convention)
        self.assertEqual(date_time_value.CopyToSerializableDict(), serialized_dict)

    def testDeserializeUnresolvedFormat(self):
        """Tests deserialization of a record with feasible interpretations."""
        serialized_dict = {
            "__class_name__": "Filetime",
            "__type__": "DateTimeValues",
            "timestamp": 0,
            "interpretation": None,
            "feasible_interpretations": ["real_time", "not_set"],
        }

        date_time_value = serializer.Serializer.ConvertJSONToDateTimeValues(
            dict(serialized_dict)
        )
        self.assertEqual(date_time_value.timestamp, 0)
        self.assertTrue(date_time_value.GetInterpretation().is_ambiguous)


if __name__ == "__main__":
    unittest.main()
