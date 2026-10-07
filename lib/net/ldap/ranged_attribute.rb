# -*- ruby encoding: utf-8 -*-
##
# Support for reading large multi-valued attributes (such as the +member+
# attribute of a big Active Directory group) that a server returns in
# several "ranged" segments, e.g. +member;range=0-1499+.
#
# Net::LDAP#read_ranged_attribute drives the retrieval; the classes in this
# file describe the pieces of a ranged attribute description and the
# outcome of a ranged read.
class Net::LDAP
  ##
  # Parses an attribute description as returned by a server during ranged
  # retrieval, keeping the raw attribute name, any attribute options (such
  # as +binary+), and the range markers separate from each other.
  #
  #   parsed = Net::LDAP::RangedAttributeName.parse("member;binary;range=0-499")
  #   parsed.name        # => "member"
  #   parsed.options     # => ["binary"]
  #   parsed.range_start # => 0
  #   parsed.range_end   # => 499
  #
  # A range end of <tt>"*"</tt> (the end-of-attribute marker sent by the
  # server) is represented by a nil #range_end; see #final?.
  class RangedAttributeName
    RANGE_OPTION_PATTERN = /\Arange=(\d+)-(\d+|\*)\z/i

    ##
    # The raw attribute name without any options or range markers.
    attr_reader :name

    ##
    # Attribute options (for example +binary+) with the range marker
    # removed.
    attr_reader :options

    ##
    # The first index (zero-based, inclusive) covered by this segment, or
    # nil when the description carries no range marker.
    attr_reader :range_start

    ##
    # The last index (inclusive) covered by this segment. Nil when the
    # server used the <tt>"*"</tt> end marker (see #final?) or when the
    # description carries no range marker.
    attr_reader :range_end

    ##
    # Splits an attribute description into its base name, options, and
    # range markers. The +range=+ option is recognized case-insensitively;
    # every other option is preserved verbatim in #options.
    def self.parse(description)
      segments = description.to_s.split(";")
      name = segments.shift.to_s
      options = []
      ranged = false
      range_start = nil
      range_end = nil

      segments.each do |segment|
        if (match = RANGE_OPTION_PATTERN.match(segment))
          ranged = true
          range_start = match[1].to_i
          range_end = match[2] == "*" ? nil : match[2].to_i
        else
          options << segment
        end
      end

      new(name, options, ranged, range_start, range_end)
    end

    def initialize(name, options, ranged, range_start, range_end) #:nodoc:
      @name = name
      @options = options
      @ranged = ranged
      @range_start = range_start
      @range_end = range_end
    end

    ##
    # True when the description carries a +range=+ marker.
    def ranged?
      @ranged
    end

    ##
    # True when the range end marker is <tt>"*"</tt>, meaning the server
    # has delivered the final segment of the attribute.
    def final?
      ranged? && @range_end.nil?
    end
  end

  ##
  # The outcome of Net::LDAP#read_ranged_attribute.
  #
  # On success #values holds every value of the attribute, concatenated
  # across all range segments in server order and otherwise untouched
  # (binary content is preserved as returned by the server). On failure
  # #error describes the problem and #values is empty: partial results are
  # discarded so callers can never mistake an incomplete list for a full
  # one.
  class RangedAttributeResult
    ##
    # The concatenated attribute values. Empty when the read failed.
    attr_reader :values

    ##
    # A human-readable failure description, or nil on success.
    attr_reader :error

    ##
    # Non-fatal notices collected during the read, for example that
    # snapshot consistency could not be guaranteed.
    attr_reader :warnings

    def initialize(args = {}) #:nodoc:
      @values = args[:values] || []
      @error = args[:error]
      @warnings = args[:warnings] || []
      @version_checked = args[:version_checked] ? true : false
    end

    ##
    # True when the attribute was read completely.
    def success?
      @error.nil?
    end

    ##
    # True when a caller-supplied version attribute was verified to be
    # unchanged across every segment of the read, so the values form a
    # consistent snapshot. False when no version attribute was given, when
    # the server did not provide one, or when the read failed.
    def consistent?
      success? && @version_checked
    end
  end
end

