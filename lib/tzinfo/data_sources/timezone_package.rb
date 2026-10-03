# encoding: UTF-8
# frozen_string_literal: true

require 'json'

module TZInfo
  module DataSources
    # Base class for errors raised while exporting or importing a limited time
    # zone package.
    class TimezonePackageError < StandardError
    end

    # Raised when an attempt is made to export an invalid set of time zones or
    # query window.
    class InvalidTimezonePackageExport < TimezonePackageError
    end

    # Raised when a package cannot be imported because its JSON data is not a
    # valid time zone package.
    class InvalidTimezonePackage < TimezonePackageError
    end

    # Raised when a query is made against an imported package at an instant that
    # falls outside the coverage window of the package. Imported packages never
    # extrapolate beyond their data, so the last observed offset is not used
    # indefinitely.
    class TimezonePackageTimeOutOfRange < TimezonePackageError
    end

    # Contains the plain data serialization rules shared by
    # {TimezonePackageExporter} and {TimezonePackageDataSource}.
    #
    # A package is ordinary JSON-compatible data (hashes, arrays, integers,
    # strings and booleans only). No Ruby source is ever generated or
    # evaluated.
    module TimezonePackageFormat
      # The format version produced and accepted by this implementation.
      FORMAT_VERSION = 1

      # The name of the format.
      FORMAT_NAME = 'tzinfo-limited-timezone-package'

      # The maximum absolute base or observed UTC offset accepted on import, in
      # seconds. The widest civilian UTC offsets are well within this bound; it
      # exists only to reject corrupt numeric data.
      MAX_OFFSET_SECONDS = 86_400

      # Queries for local times are allowed this many seconds either side of
      # the coverage window. Converting local time to UTC can be ambiguous by at
      # most one day, matching the search range used elsewhere in TZInfo.
      LOCAL_WINDOW_MARGIN_SECONDS = 86_400

      # Converts a package to a JSON string.
      #
      # @param package [Hash] a package data structure.
      # @return [String] the package serialized as JSON.
      def self.dump(package)
        ::JSON.generate(package)
      end

      # Parses a JSON string into a package data structure.
      #
      # @param json [String] a JSON string previously produced by {dump}.
      # @return [Hash] the parsed package data structure.
      # @raise [InvalidTimezonePackage] if the JSON cannot be parsed or does
      #   not contain a JSON object.
      def self.load(json)
        raise InvalidTimezonePackage, 'package must be a String' unless json.kind_of?(String)

        begin
          parsed = ::JSON.parse(json)
        rescue ::JSON::ParserError => e
          raise InvalidTimezonePackage, "invalid JSON: #{e.message}"
        end

        raise InvalidTimezonePackage, 'package must be a JSON object' unless parsed.kind_of?(Hash)
        parsed
      end
    end
  end
end
