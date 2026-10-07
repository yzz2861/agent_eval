require 'net/sftp/constants'
require 'net/sftp/protocol/04/attributes'

module Net; module SFTP

  # A purely local, read-only preview of how SFTP v4/v6 access control lists
  # (see Net::SFTP::Protocol::V04::Attributes::ACL and Net::SFTP::Constants::ACE)
  # propagate to newly created objects, and how the ordered allow/deny rules
  # would evaluate for a given principal.
  #
  # This is intended for tools (e.g. permission migration utilities) that want
  # to preview the effect of an ACL before sending it via SETSTAT. It performs
  # no I/O and never modifies the wire encoding of Attributes.
  #
  # IMPORTANT: this is only a client-side approximation. The server remains
  # the final authority on access checks; it may apply additional policy,
  # default entries, or privilege semantics that this preview cannot see.
  # Whenever this module cannot locally determine an outcome it reports
  # :indeterminate rather than guessing, and it never defaults to allowing
  # access.
  module ACL
    include Constants

    # The identity of the principal (user) for which an ACL is evaluated.
    # +user+ is the user name (matching ACE "who" strings without the
    # IDENTIFIER_GROUP flag), and +groups+ is the list of group names the
    # principal belongs to (matching ACEs with IDENTIFIER_GROUP set).
    # Either may be nil to indicate the identity is not known locally; any
    # conclusion depending on the missing information will be :indeterminate.
    Principal = Struct.new(:user, :groups)

    # The result of inheriting a single ACE from a parent directory. +ace+ is
    # the new ACE for the child object (with inheritance flags adjusted per
    # the protocol rules), and +source+ is the parent ACE it was derived
    # from, so callers can trace every inherited entry back to its origin.
    InheritedEntry = Struct.new(:ace, :source)

    # The per-permission-bit outcome of an evaluation. +mask+ is the single
    # permission bit, +status+ is one of :allowed, :denied or :indeterminate,
    # +ace+ is the ACE that produced the conclusion (nil when no ACE
    # addressed the bit), and +source+ is the parent ACE the deciding ACE
    # was inherited from, when the evaluated list was produced by #inherit.
    Verdict = Struct.new(:mask, :status, :ace, :source)

    # The union of all permission bits defined by the protocol. Bits outside
    # this mask are not understood by the preview and always evaluate to
    # :indeterminate.
    KNOWN_MASK = Constants::ACE::Mask.constants.map { |c| Constants::ACE::Mask.const_get(c) }.reduce(0, :|)

    # Well-known "who" identifiers defined by the protocol.
    EVERYONE = "EVERYONE@"
    OWNER    = "OWNER@"
    GROUP    = "GROUP@"

    class <<self
      # Computes the ACEs that a newly created child object would inherit
      # from +parent_acl+ (an array of Attributes::ACL entries, in order).
      # +object_type+ is the type of the object about to be created: :file
      # (or T_REGULAR) or :directory (or T_DIRECTORY).
      #
      # Returns an array of InheritedEntry, preserving the order of the
      # parent ACL. Entries are never merged or reordered, so each inherited
      # ACE keeps its own semantics and its link to the originating ACE.
      #
      # Inheritance rules (mirroring the SFTP v4/v6 / NFSv4 model):
      #
      # * ACEs with FILE_INHERIT apply to new files; ACEs with
      #   DIRECTORY_INHERIT apply to new directories. ACEs without the
      #   matching flag are not inherited.
      # * INHERIT_ONLY is cleared on the child, so the entry now applies to
      #   the child object itself.
      # * NO_PROPAGATE_INHERIT stops further propagation: when the child is
      #   a directory, DIRECTORY_INHERIT is cleared on the inherited entry,
      #   and the NO_PROPAGATE_INHERIT flag itself is cleared.
      # * Files have no children, so all inheritance flags are cleared on
      #   entries inherited by a file.
      def inherit(parent_acl, object_type)
        directory = case object_type
          when :directory, Protocol::V04::Attributes::T_DIRECTORY then true
          when :file, Protocol::V04::Attributes::T_REGULAR then false
          else raise ArgumentError, "unknown object type: #{object_type.inspect}"
        end

        flag = Constants::ACE::Flag
        (parent_acl || []).each_with_object([]) do |ace, entries|
          applies = directory ? (ace.flag & flag::DIRECTORY_INHERIT) != 0
                              : (ace.flag & flag::FILE_INHERIT) != 0
          next unless applies

          new_flag = ace.flag & ~flag::INHERIT_ONLY & ~flag::NO_PROPAGATE_INHERIT
          if directory
            new_flag &= ~flag::DIRECTORY_INHERIT if (ace.flag & flag::NO_PROPAGATE_INHERIT) != 0
          else
            new_flag &= ~(flag::FILE_INHERIT | flag::DIRECTORY_INHERIT)
          end

          inherited = Protocol::V04::Attributes::ACL.new(ace.type, new_flag, ace.mask, ace.who)
          entries << InheritedEntry.new(inherited, ace)
        end
      end

      # Evaluates +acl+ (an array of Attributes::ACL entries, InheritedEntry
      # objects, or a mixture) for +principal+ (a Principal), one permission
      # bit at a time, following the protocol's ordered semantics: entries
      # are scanned in order and the first entry that matches the principal
     # and mentions the bit decides it (ACCESS_ALLOWED allows,
     # ACCESS_DENIED denies). Audit and alarm entries never decide access.
      # Entries flagged INHERIT_ONLY are skipped, since they do not apply
      # to the object carrying the ACL itself.
      #
      # +mask+ is a bitmask of the requested permissions (see
      # Net::SFTP::Constants::ACE::Mask). Returns one Verdict per requested
      # bit, in ascending bit order.
      #
      # A bit is :indeterminate when no matching entry addresses it, when
      # the principal's identity is incomplete, when an entry's "who" cannot
      # be resolved locally (e.g. OWNER@/GROUP@), when the entry type is
      # unknown, or when the bit itself is not a known permission bit. The
      # preview never defaults to allowing access.
      def evaluate(acl, principal, mask)
        entries = (acl || []).map do |entry|
          entry.is_a?(InheritedEntry) ? entry : InheritedEntry.new(entry, nil)
        end

        bits = []
        bit = 1
        while bit <= mask
          bits << bit if (mask & bit) != 0
          bit <<= 1
        end

        bits.map { |b| evaluate_bit(entries, principal, b) }
      end

      private

        def evaluate_bit(entries, principal, bit)
          return Verdict.new(bit, :indeterminate, nil, nil) if (bit & KNOWN_MASK) == 0

          entries.each do |entry|
            ace = entry.ace
            next if (ace.mask & bit) == 0
            next if (ace.flag & Constants::ACE::Flag::INHERIT_ONLY) != 0

            case match_principal(ace, principal)
            when false then next
            when :unknown
              return Verdict.new(bit, :indeterminate, ace, entry.source)
            else
              case ace.type
              when Constants::ACE::Type::ACCESS_ALLOWED
                return Verdict.new(bit, :allowed, ace, entry.source)
              when Constants::ACE::Type::ACCESS_DENIED
                return Verdict.new(bit, :denied, ace, entry.source)
              when Constants::ACE::Type::SYSTEM_AUDIT, Constants::ACE::Type::SYSTEM_ALARM
                next
              else
                return Verdict.new(bit, :indeterminate, ace, entry.source)
              end
            end
          end

          Verdict.new(bit, :indeterminate, nil, nil)
        end

        # Returns true/false when the ACE definitely applies/does not apply
        # to the principal, or :unknown when local information is
        # insufficient to tell.
        def match_principal(ace, principal)
          return true if ace.who == EVERYONE
          return :unknown if ace.who == OWNER || ace.who == GROUP

          if (ace.flag & Constants::ACE::Flag::IDENTIFIER_GROUP) != 0
            return :unknown if principal.nil? || principal.groups.nil?
            principal.groups.include?(ace.who)
          else
            return :unknown if principal.nil? || principal.user.nil?
            principal.user == ace.who
          end
        end
    end
  end

end ; end
