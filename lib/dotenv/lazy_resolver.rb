require "dotenv/substitutions/variable"
require "dotenv/substitutions/command" if RUBY_VERSION > "1.8.7"

module Dotenv
  # Resolves definitions after all sources and their override order have been collected.
  class LazyResolver
    SHELL_COMMAND = /
      (?<backslash>\\)?   # is it escaped with a backslash?
      \$                  # literal $
      (?<cmd>             # collect command content for eval
        \(                # require opening paren
        (?:[^()]|\g<cmd>)+  # allow any number of non-parens, or balanced
                            # parens (by nesting the <cmd> expression
                            # recursively)
        \)                # require closing paren
      )
    /x

    def self.call(...)
      new(...).call
    end

    def initialize(definitions, overwrite: false, environment: ENV.to_h)
      @definitions = definitions
      @overwrite = overwrite
      @environment = environment
      @values = {}
      @state = {}
      @stack = []
      @resolving = []
    end

    def call
      detect_cycles!
      @definitions.each_key { |key| final_value(key) }
      @values
    end

    private

    def active?(key)
      @definitions.key?(key) &&
        (@overwrite == true || !@environment.key?(key) || key == "DOTENV_LINEBREAK_MODE")
    end

    def dependencies
      @dependencies ||= @definitions.to_h do |key, definition|
        [key, definition.single_quoted? ? [] : variable_names(definition.raw_value.to_s, key)]
      end
    end

    def variable_names(value, key)
      names = scan_variables(value)
      command_contents(value).each do |command, escaped|
        next if escaped

        scan_variables(command).each { |name| names.delete(name) if name == key }
      end
      names
    end

    def scan_variables(value)
      value.to_s.scan(Substitutions::Variable::VARIABLE).filter_map do |escaped, _dollar, name|
        next if escaped
        next unless name

        name
      end.uniq
    end

    def command_contents(value)
      commands = []
      value.to_s.scan(SHELL_COMMAND) do
        match = $LAST_MATCH_INFO
        commands << [match[:cmd][1..-2], match[:backslash]]
      end
      commands
    end

    def detect_cycles!
      @definitions.each_key { |key| visit_cycle(key) }
    end

    def visit_cycle(key)
      return if @state[key] == :complete

      if @state[key] == :visiting
        start = @stack.index(key)
        raise CircularReferenceError, @stack[start..] + [key]
      end

      @state[key] = :visiting
      @stack << key

      dependencies.fetch(key, []).select { |dependency| active?(dependency) }.each do |dependency|
        visit_cycle(dependency)
      end

      @stack.pop
      @state[key] = :complete
    end

    def final_value(key)
      return @values[key] if @values.key?(key)

      if active?(key)
        resolve(key)
      else
        @values[key] = @environment[key]
      end
    end

    def resolve(key)
      return @values[key] if @values.key?(key)
      return @environment[key] unless active?(key)
      raise CircularReferenceError, @resolving + [key] if @resolving.include?(key)

      definition = @definitions[key]
      value = definition.raw_value
      @resolving << key

      begin
        unless definition.single_quoted?
          mode = linebreak_mode
          value = expand_newlines(value, mode) if definition.quote == '"'
          value = unescape_characters(value)

          dependencies.fetch(key, []).each { |dependency| resolve(dependency) }

          context = substitution_context
          value = Substitutions::Command.call(value, context)
          value = Substitutions::Variable.call(value, context)
        end
      ensure
        @resolving.pop
      end

      @values[key] = value
    end

    def substitution_context
      @substitution_context ||= Context.new(self, @values)
    end

    def linebreak_mode
      definition = @definitions["DOTENV_LINEBREAK_MODE"]
      definition&.raw_value || @environment["DOTENV_LINEBREAK_MODE"]
    end

    def context_value(key)
      if @values.key?(key)
        @values[key]
      elsif @resolving.last == key
        @environment[key]
      elsif active?(key)
        resolve(key)
      elsif @environment.key?(key)
        @environment[key]
      end
    end

    def context_key?(key)
      @values.key?(key) || active?(key) || @environment.key?(key)
    end

    def variable_value(key)
      context_value(key).to_s
    end

    def unescape_characters(value)
      value.gsub(/\\([^$])/, '\\1')
    end

    def expand_newlines(value, mode)
      if mode == "legacy"
        value.gsub('\\n', "\n").gsub('\\r', "\r")
      else
        value.gsub('\\n', "\\\\\\n").gsub('\\r', "\\\\\\r")
      end
    end

    class Context
      def initialize(resolver, values)
        @resolver = resolver
        @values = values
      end

      def [](key)
        @resolver.send(:context_value, key)
      end

      def key?(key)
        @resolver.send(:context_key?, key)
      end

      def variable_value(key)
        @resolver.send(:variable_value, key)
      end
    end
  end
end
