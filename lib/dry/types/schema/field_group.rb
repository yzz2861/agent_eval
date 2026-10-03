# frozen_string_literal: true

module Dry
  module Types
    class Schema < Hash
      class FieldGroup
        include ::Dry::Equalizer(:kind, :paths, :name, :check, inspect: false, immutable: true)

        CHECKS = %i[before_defaults after_defaults].freeze

        attr_reader :kind, :paths, :name, :check

        def self.[](kind, paths, name: nil, check: :before_defaults)
          paths = paths.map { |path| Array(path).dup }.freeze
          check = check.to_sym

          unless %i[exactly_one at_least_one all_or_none].include?(kind)
            raise ::ArgumentError, "unknown field group kind #{kind.inspect}"
          end

          unless CHECKS.include?(check)
            raise ::ArgumentError, "check must be one of #{CHECKS.map(&:inspect).join(", ")}"
          end

          if paths.empty?
            raise ::ArgumentError, "field group must contain at least one path"
          end

          if paths.any? { |path| path.empty? }
            raise ::ArgumentError, "field group paths cannot be empty"
          end

          if paths.any? { |path| path.any? { |segment| !segment.is_a?(::Symbol) } }
            raise ::ArgumentError, "field group paths must contain symbol keys"
          end

          name ||= paths.map { |path| path.join(".") }.join("_or_")
          new(kind: kind, paths: paths, name: name.to_sym, check: check)
        end

        def initialize(kind:, paths:, name:, check:)
          @kind = kind
          @paths = paths
          @name = name
          @check = check
          freeze
        end

        def before_defaults? = check == :before_defaults

        def to_ast
          [kind, {paths: paths.map(&:dup), name: name, check: check}]
        end

        def self.from_ast(node)
          kind, options = node
          self[kind, options.fetch(:paths), **options.except(:paths)]
        end
      end
    end
  end
end
