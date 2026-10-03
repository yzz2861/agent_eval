# frozen_string_literal: true

module Dry
  module Types
    class Schema < Hash
      # A group of members constrained together. A member is either a single
      # key, a fixed nested path (array of symbols) or a bundle of paths
      # (array mixing symbols and paths), in which case every path must be
      # present for the member to count as present.
      #
      # @see Schema#exactly_one
      # @see Schema#at_least_one
      # @see Schema#all_or_none
      #
      # @api public
      class KeyGroup
        include ::Dry::Equalizer(:kind, :members, :check, inspect: false, immutable: true)

        # Supported kinds of groups
        KINDS = %i[exactly_one at_least_one all_or_none].freeze

        # Supported moments when presence is evaluated
        CHECKS = %i[before_defaults after_defaults].freeze

        # @return [Symbol]
        attr_reader :kind

        # @return [Array<Array<Array<Symbol>>>] normalized members, each
        #   member being a bundle of fixed paths
        attr_reader :members

        # @return [Symbol]
        attr_reader :check

        # @param kind [Symbol]
        # @param members [Array<Symbol, Array>]
        # @param check [Symbol]
        #
        # @api private
        def initialize(kind, members, check: :before_defaults)
          unless KINDS.include?(kind)
            raise ::ArgumentError,
              "unknown group kind #{kind.inspect}, must be one of #{KINDS.inspect}"
          end

          unless CHECKS.include?(check)
            raise ::ArgumentError,
              "unknown check moment #{check.inspect}, must be one of #{CHECKS.inspect}"
          end

          if members.empty?
            raise ::ArgumentError, "a group must contain at least one member"
          end

          members = members.map { |member| self.class.normalize_member(member) }

          members.each do |paths|
            paths.each do |path|
              if path.empty? || path.any? { |segment| !segment.is_a?(::Symbol) }
                raise ::ArgumentError,
                  "group paths must be non-empty arrays of symbols, #{path.inspect} given"
              end
            end
          end

          @kind = kind
          @members = members.freeze
          @check = check
          freeze
        end

        # All paths referenced by the group, flat and unique
        #
        # @return [Array<Array<Symbol>>]
        #
        # @api private
        def paths
          members.flatten(1).uniq
        end

        # @return [Array] AST representation
        #
        # @api private
        def to_ast
          [kind, members, check]
        end

        # Build a group from a serializable representation
        #
        # @param spec [KeyGroup, Hash]
        #
        # @return [KeyGroup]
        #
        # @api private
        def self.coerce(spec)
          case spec
          when KeyGroup
            spec
          when ::Hash
            new(spec.fetch(:kind), spec.fetch(:members), check: spec.fetch(:check, :before_defaults))
          else
            raise ::ArgumentError, "cannot coerce #{spec.inspect} into a key group"
          end
        end

        # Normalize a member into a bundle of fixed paths. A symbol is a
        # single key, a single-element array wrapping a path marks a fixed
        # nested path and a multi-element array bundles keys and paths.
        #
        # @example
        #   normalize_member(:name)          # => [[:name]]
        #   normalize_member([[:a, :b]])     # => [[:a, :b]] (a nested path)
        #   normalize_member([:a, [:b, :c]]) # => [[:a], [:b, :c]] (a bundle)
        #
        # @api private
        def self.normalize_member(member)
          case member
          when ::Symbol
            [[member]]
          when ::Array
            if member.empty?
              raise ::ArgumentError, "group members must not be empty"
            elsif member.size == 1 && path?(member.first)
              [member.first]
            else
              member.map do |part|
                if part.is_a?(::Symbol)
                  [part]
                elsif path?(part)
                  part
                else
                  raise ::ArgumentError,
                    "group members must be symbols, paths or bundles of paths, " \
                    "#{member.inspect} given"
                end
              end
            end
          else
            raise ::ArgumentError,
              "group members must be symbols or arrays, #{member.inspect} given"
          end
        end

        # @api private
        def self.path?(part)
          part.is_a?(::Array) && !part.empty? &&
            part.all? { |segment| segment.is_a?(::Symbol) }
        end
      end
    end
  end
end
