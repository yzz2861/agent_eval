require 'net/sftp/constants'

module Net; module SFTP; module Protocol; module V04

  # A purely local preview of SFTP v4+ ACL inheritance and access
  # evaluation, built on top of the ACE entries carried by
  # Net::SFTP::Protocol::V04::Attributes#acl. It performs no I/O and
  # changes nothing on the wire: the encoding of Attributes is untouched.
  #
  # Two questions can be answered before an FXP_SETSTAT is ever sent:
  #
  # * ACLPreview.inherit:: given a parent directory's ACL and the type of
  #   the object about to be created, which ACEs would the child inherit?
  # * ACLPreview.evaluate:: given an ACL and a subject (user name plus
  #   group names), is each requested permission bit allowed, denied, or
  #   indeterminate?
  #
  # The evaluation follows the protocol's ordered allow/deny rules: ACEs
  # are examined in order, and the first ACE that matches the subject and
  # mentions a given permission bit decides that bit. Entries are never
  # merged or reordered, so the verdict for every bit names the exact ACE
  # it came from.
  #
  # Anything the preview cannot determine locally -- an unknown subject, a
  # permission bit it does not recognize, an ACE type it does not
  # understand, or simply no ACE covering a bit -- is reported as
  # :indeterminate. It never falls back to granting access.
  #
  # NOTE: this is only a client-side preview. The server remains the final
  # authority on access checks and on the ACL it actually stores; a
  # favorable preview does not guarantee the server will authorize the
  # operation.
  module ACLPreview
    include Net::SFTP::Constants::ACE

    # The union of all permission bits defined by the protocol. Any bit
    # outside this set is reported as :indeterminate.
    KNOWN_MASK = Mask.constants.map { |name| Mask.const_get(name) }.inject(0) { |acc, bit| acc | bit }

    # The well-known "who" string that matches every subject.
    EVERYONE = "EVERYONE@".freeze

    # The possible outcomes for a single permission bit.
    ALLOWED       = :allowed
    DENIED        = :denied
    INDETERMINATE = :indeterminate

    # The outcome of evaluating one permission bit against an ACL. The
    # +ace+ and +ace_index+ members identify the exact entry the verdict
    # came from (nil when the bit could not be resolved to any ACE), so
    # callers can show users precisely why a bit is allowed, denied, or
    # indeterminate.
    class Decision < Struct.new(:bit, :verdict, :ace, :ace_index, :reason)
      def allowed?
        verdict == ALLOWED
      end

      def denied?
        verdict == DENIED
      end

      def indeterminate?
        verdict == INDETERMINATE
      end
    end

    # Computes the ACEs a newly created object of the given +type+ (one of
    # the Attributes::T_* constants) would inherit from +parent_acl+, the
    # ACL of the parent directory. Returns a new array of ACE copies; the
    # parent's entries are never mutated, and entries are never merged --
    # each inherited ACE keeps its own type, mask, and who so that later
    # evaluation preserves the original ordering semantics.
    #
    # Inheritance rules (per the SFTP v4+ / NFSv4 ACE model):
    #
    # * a new file inherits only ACEs flagged FILE_INHERIT; a new
    #   directory inherits only ACEs flagged DIRECTORY_INHERIT;
    # * INHERIT_ONLY is cleared on the child copy (the entry now applies
    #   to the child itself);
    # * NO_PROPAGATE_INHERIT stops further propagation: the inherit flags
    #   are cleared on the child copy so grandchildren see nothing;
    # * non-directory children cannot have children, so all inherit flags
    #   are cleared on their copies.
    def self.inherit(parent_acl, type)
      return [] if parent_acl.nil?

      directory = (type == Attributes::T_DIRECTORY)
      inherit_flag = directory ? Flag::DIRECTORY_INHERIT : Flag::FILE_INHERIT

      parent_acl.each_with_object([]) do |ace, inherited|
        next unless ace.flag & inherit_flag != 0

        flag = ace.flag & ~Flag::INHERIT_ONLY
        if !directory || flag & Flag::NO_PROPAGATE_INHERIT != 0
          flag &= ~(Flag::FILE_INHERIT | Flag::DIRECTORY_INHERIT | Flag::NO_PROPAGATE_INHERIT)
        end

        inherited << Attributes::ACL.new(ace.type, flag, ace.mask, ace.who)
      end
    end

    # Evaluates each permission bit in +mask+ against +acl+ for the given
    # subject, and returns an array of Decision objects (one per bit, in
    # ascending bit order). +user+ is the subject's user name (or nil if
    # unknown) and +groups+ is an array of the subject's group names.
    #
    # For every bit, ACEs are scanned in order; INHERIT_ONLY entries and
    # audit/alarm entries are skipped. The first ACCESS_ALLOWED or
    # ACCESS_DENIED entry that matches the subject and includes the bit
    # decides it. If no entry resolves the bit -- because the subject is
    # unknown, the bit is not a known permission, an entry has an
    # unrecognized type, or simply no entry covers the bit for this
    # subject -- the verdict is :indeterminate rather than a default
    # grant.
    def self.evaluate(acl, user:, groups: [], mask:)
      bits(mask).map { |bit| evaluate_bit(acl || [], user, groups || [], bit) }
    end

    # Splits +mask+ into its individual permission bits, preserving any
    # unrecognized bits so they can be reported as indeterminate.
    def self.bits(mask)
      result = []
      bit = 1
      remaining = mask
      while remaining != 0
        result << bit if remaining & 1 != 0
        remaining >>= 1
        bit <<= 1
      end
      result
    end

    # True if the ACE applies to the given subject: EVERYONE@ matches
    # everybody, an IDENTIFIER_GROUP entry matches any of the subject's
    # groups, and any other entry matches the subject's user name. A nil
    # user or nil groups simply fails to match the corresponding entries,
    # which will surface as :indeterminate unless EVERYONE@ covers the
    # bit.
    def self.ace_matches?(ace, user, groups)
      return true if ace.who == EVERYONE

      if ace.flag & Flag::IDENTIFIER_GROUP != 0
        groups.include?(ace.who)
      else
        !user.nil? && ace.who == user
      end
    end

    def self.evaluate_bit(acl, user, groups, bit) #:nodoc:
      unless KNOWN_MASK & bit != 0
        return Decision.new(bit, INDETERMINATE, nil, nil, :unknown_mask_bit)
      end

      acl.each_with_index do |ace, index|
        next if ace.flag & Flag::INHERIT_ONLY != 0
        next unless ace_matches?(ace, user, groups)
        next unless ace.mask & bit != 0

        case ace.type
        when Type::ACCESS_ALLOWED
          return Decision.new(bit, ALLOWED, ace, index, :allowed_by_ace)
        when Type::ACCESS_DENIED
          return Decision.new(bit, DENIED, ace, index, :denied_by_ace)
        when Type::SYSTEM_AUDIT, Type::SYSTEM_ALARM
          next
        else
          return Decision.new(bit, INDETERMINATE, ace, index, :unknown_ace_type)
        end
      end

      Decision.new(bit, INDETERMINATE, nil, nil, :no_matching_ace)
    end
  end

  class Attributes
    # Returns the ACL that a new child of this (directory) object would
    # inherit, as an array of ACE copies. See ACLPreview.inherit.
    def inherit_acl(type)
      ACLPreview.inherit(acl, type)
    end

    # Previews, purely locally, whether the given subject would be granted
    # each permission bit in +mask+ under this object's ACL. Returns an
    # array of ACLPreview::Decision objects. This preview does not replace
    # the server's final authorization decision. See ACLPreview.evaluate.
    def preview_access(user:, groups: [], mask:)
      ACLPreview.evaluate(acl, :user => user, :groups => groups, :mask => mask)
    end
  end

end ; end ; end ; end
