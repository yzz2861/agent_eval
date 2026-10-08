# frozen_string_literal: true

module Rake

  # An ExecutionContext describes the working directory and environment
  # modifications that Rake command helpers (+sh+, +ruby+, ...) apply when
  # they spawn subprocesses.
  #
  # Contexts are immutable value objects.  A task may carry a context (see
  # Rake::Task#execution_context); while a task runs, its effective context
  # is derived from the context of the task that invoked it, so nested and
  # parallel tasks inherit their parent's directory and environment unless
  # they override them.
  #
  # The context only affects commands spawned through Rake's command
  # helpers.  It does not change the Dir.pwd or ENV visible to Ruby code
  # running directly inside task blocks.
  class ExecutionContext
    # Working directory for spawned commands (a String), or nil to use the
    # current process directory.
    attr_reader :dir

    # Environment modifications for spawned commands.  A nil value removes
    # the variable from the spawned command's environment.
    attr_reader :env

    def initialize(dir: nil, env: nil)
      @dir = dir
      @env = (env || {}).each_with_object({}) { |(k, v), h| h[k.to_s] = v }.freeze
    end

    # The empty context: inherit the directory and environment unchanged.
    EMPTY = new

    # True when this context applies no modifications.
    def empty?
      @dir.nil? && @env.empty?
    end

    # Derive a new context from this one.  +dir+ replaces the directory
    # when given; +env+ entries are merged over the current ones, where a
    # nil value marks the variable for removal.
    def derive(dir: nil, env: nil)
      self.class.new(dir: dir || @dir, env: @env.merge(env || {}))
    end

    # The context currently in effect on this thread.
    def self.current
      Thread.current[:rake_execution_context] || EMPTY
    end

    # Run the block with +context+ as the current context on this thread.
    def self.with(context)
      previous = Thread.current[:rake_execution_context]
      Thread.current[:rake_execution_context] = context
      yield
    ensure
      Thread.current[:rake_execution_context] = previous
    end

    # Coerce +object+ (an ExecutionContext or a Hash with :dir/:env keys)
    # into an ExecutionContext.
    def self.coerce(object)
      case object
      when nil then nil
      when ExecutionContext then object
      when Hash then new(dir: object[:dir], env: object[:env])
      else
        raise ArgumentError,
              "cannot convert #{object.inspect} to Rake::ExecutionContext"
      end
    end

    # Merge this context into a command argument list and spawn options as
    # used by FileUtils#sh.  Explicit call-site settings win: an env hash
    # leading +cmd+ overrides individual variables, and an existing :chdir
    # option overrides the context directory.
    def apply_to_command(cmd, options) # :nodoc:
      unless @env.empty?
        explicit = Hash === cmd.first ? cmd.shift : {}
        merged = @env.merge(explicit)
        cmd.unshift(merged) unless merged.empty?
      end
      options[:chdir] = @dir if @dir && !options.key?(:chdir)
    end
  end
end
