# frozen_string_literal: true

module Rake

  ##
  # An ExecutionContext describes the working directory and environment
  # variable overrides that Rake's command helpers (+sh+, +ruby+, ...)
  # apply when spawning subprocesses.
  #
  # A context may be attached to a task (see
  # Rake::Task#set_execution_context) and is inherited by the tasks it
  # invokes, so a child task derives its context from its parent.  Use
  # #derive to build a modified copy:
  #
  #   context = Rake::ExecutionContext.new(chdir: "build", env: { "CC" => "clang" })
  #   child   = context.derive(env: { "CC" => "gcc", "LEGACY" => nil })
  #
  # A +nil+ value in +env+ removes the variable from the child process
  # environment, even if it was inherited from the parent context or the
  # current process.
  #
  # The context only affects commands run through Rake's command helpers;
  # it does not change +Dir.pwd+ or +ENV+ as seen by ordinary Ruby code
  # inside task blocks.
  #
  class ExecutionContext
    # Working directory for spawned commands, or nil to inherit the
    # process working directory.
    attr_reader :chdir

    # Environment variable overrides for spawned commands.  A nil value
    # means the variable is removed from the child process environment.
    attr_reader :env

    def initialize(chdir: nil, env: {})
      @chdir = chdir
      @env = env.each_with_object({}) { |(k, v), h| h[k.to_s] = v }
      @env.freeze
      freeze
    end

    # Derive a new context from this one.  +chdir+ replaces the inherited
    # directory when given; +env+ entries are merged over the inherited
    # ones, with nil values marking variables for removal.
    def derive(chdir: nil, env: {})
      self.class.new(chdir: chdir || @chdir, env: @env.merge(env))
    end

    # Merge another ExecutionContext over this one.
    def merge(other)
      derive(chdir: other.chdir, env: other.env)
    end

    # True when this context carries no overrides at all.
    def empty?
      @chdir.nil? && @env.empty?
    end

    # The context with no overrides.
    ROOT = new

    # The context active for the current thread of execution.
    def self.current
      Thread.current[:rake_execution_context] || ROOT
    end

    # Run the given block with +context+ as the current execution
    # context, restoring the previous one when the block exits, even on
    # error.
    def self.with(context)
      previous = Thread.current[:rake_execution_context]
      Thread.current[:rake_execution_context] = context
      yield
    ensure
      Thread.current[:rake_execution_context] = previous
    end
  end
end
