require "dotenv/circular_dependency_error"
require "dotenv/substitutions/variable"
require "dotenv/substitutions/command" if RUBY_VERSION > "1.8.7"

module Dotenv
  # Resolves raw definitions after all files have been collected.
  class Resolver
    def self.call(definition_set)
      new(definition_set).call
    end

    def initialize(definition_set)
      @definition_set = definition_set
      @resolved = {}
      @stack = []
    end

    def call
      validate!
      resolve_definition(@definition_set.definitions.fetch("DOTENV_LINEBREAK_MODE")) if linebreak_mode_definition?
      @definition_set.each do |definition|
        next if definition.key == "DOTENV_LINEBREAK_MODE"
        @resolved[definition.key] = resolve_definition(definition)
      end
      @definition_set.keys.each do |key|
        @resolved[key] = @definition_set.external_value(key) if @definition_set.external?(key)
      end
      @resolved
    end

    private

    def validate!
      @definition_set.each do |definition|
        dependencies(definition).each do |dependency|
          follow_dependency(dependency, [definition.key])
        end
      end
    end

    def follow_dependency(key, chain)
      definition = @definition_set.definitions[key]
      return unless definition

      if chain.include?(key)
        cycle = chain.drop(chain.index(key)) + [key]
        raise CircularDependencyError, cycle
      end

      dependencies(definition).each do |dependency|
        follow_dependency(dependency, chain + [key])
      end
    end

    def dependencies(definition)
      return [] if definition.single_quoted?

      definition.value.scan(Substitutions::Variable::VARIABLE).filter_map do
        match = $LAST_MATCH_INFO
        match[3] unless match[1] == "\\"
      end.uniq
    end

    def resolve_definition(definition)
      key = definition.key
      return @resolved.fetch(key) if @resolved.key?(key)

      if @stack.include?(key)
        cycle_start = @stack.index(key)
        raise CircularDependencyError, @stack[cycle_start..] + [key]
      end

      @stack.push(key)
      value = begin
        prepare_value(definition)
      ensure
        @stack.pop
      end
      @resolved[key] = value
    end

    def prepare_value(definition)
      value = definition.value
      return value if definition.single_quoted?

      value = expand_newlines(value) if definition.quote == '"'
      value = unescape_characters(value)
      resolve_variables(resolve_commands(value))
    end

    def resolve_commands(value)
      value.gsub(Substitutions::Command::INTERPOLATED_SHELL_COMMAND) do
        match = $LAST_MATCH_INFO
        next match[0][1..] if match[:backslash]

        command = resolve_variables(match[:cmd][1..-2])
        `#{command}`.chomp
      end
    end

    def resolve_variables(value)
      value.gsub(Substitutions::Variable::VARIABLE) do |variable|
        match = $LAST_MATCH_INFO

        if match[1] == "\\"
          variable[1..]
        elsif match[3]
          resolve_reference(match[3])
        else
          variable
        end
      end
    end

    def resolve_reference(key)
      definition = @definition_set.definitions[key]
      return resolve_definition(definition) if definition

      @definition_set.external.key?(key) ? @definition_set.external.fetch(key) : ""
    end

    def unescape_characters(value)
      value.gsub(/\\([^$])/, '\\1')
    end

    def expand_newlines(value)
      if linebreak_mode == "legacy"
        value.gsub('\\n', "\n").gsub('\\r', "\r")
      else
        value.gsub('\\n', "\\\\n").gsub('\\r', "\\\\r")
      end
    end

    def linebreak_mode
      @resolved["DOTENV_LINEBREAK_MODE"] || ENV["DOTENV_LINEBREAK_MODE"]
    end

    def linebreak_mode_definition?
      @definition_set.definitions.key?("DOTENV_LINEBREAK_MODE")
    end
  end
end
