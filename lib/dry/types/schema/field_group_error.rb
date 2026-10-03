# frozen_string_literal: true

module Dry
  module Types
    class Schema < Hash
      class FieldGroupError < CoercionError
        MESSAGES = {
          exactly_one: "must contain exactly one of",
          at_least_one: "must contain at least one of",
          all_or_none: "must contain all or none of"
        }.freeze

        attr_reader :group, :paths

        def initialize(group, present_paths)
          @group = group
          @paths = group.paths
          present = present_paths.map(&method(:format_path))
          members = group.paths.map(&method(:format_path))

          super(
            "field group #{group.name.inspect} #{MESSAGES.fetch(group.kind)} " \
            "#{members.join(", ")}; found #{present.empty? ? "none" : present.join(", ")}",
            meta: {kind: group.kind, name: group.name, paths: group.paths}
          )
        end

        private

        def format_path(path)
          ":#{path.join(".")}"
        end
      end

      GroupError = FieldGroupError
    end
  end
end
