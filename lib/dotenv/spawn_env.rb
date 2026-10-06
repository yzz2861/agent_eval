require "dotenv/parser"

module Dotenv
  # A parser that resolves variables only within a given environment view,
  # never falling back to the process ENV.
  class SpawnEnvParser < Parser
    @substitutions = [
      ->(value, env) { Substitutions::Command.call(value, env, fallback: nil) },
      ->(value, env) { Substitutions::Variable.call(value, env, fallback: nil) }
    ]

    def initialize(string, view)
      super(string, overwrite: true)
      @hash = view
    end

    private

    def expand_newlines(value)
      if @hash["DOTENV_LINEBREAK_MODE"] == "legacy"
        value.gsub('\\n', "\n").gsub('\\r', "\r")
      else
        value.gsub('\\n', "\\\\\\n").gsub('\\r', "\\\\\\r")
      end
    end
  end

  # Builds an environment map for spawning child processes (e.g. several
  # test backends, each with its own .env file) without mutating the
  # parent process ENV.
  #
  #   env = Dotenv.spawn_env("backend.env",
  #     inherit: %w[PATH HOME LANG],
  #     override: { "PORT" => "3001", "DEBUG" => nil })
  #
  #   spawn(env, "ruby", "server.rb") # PORT=3001, DEBUG unset in the child
  #   env.summary # => { "added" => [...], "changed" => [...], "removed" => [...] }
  #
  # Values are strings, +nil+ (explicitly deleted, unset in the child), or
  # absent (not provided). The +summary+ only lists key names, never values,
  # so it is safe to log without leaking secrets.
  class SpawnEnv < Hash
    # Environment variable names are case-insensitive on Windows.
    DEFAULT_CASE_SENSITIVE = !Gem.win_platform?

    attr_reader :summary

    # @param filenames [Array<String>] .env files to layer over the inherited variables
    # @param inherit [true, false, Array<String>, Regexp] which parent ENV
    #   variables to start from: +true+ for all, +false+/+nil+ for none, an
    #   Array of names, or a Regexp matched against names
    # @param override [Hash] explicit values applied last; a +nil+ value
    #   deletes the variable (it will be unset in the spawned child)
    # @param case_sensitive [Boolean] how to treat keys that differ only in
    #   case. Defaults to the platform rule (insensitive on Windows)
    # @param ignore [Boolean] ignore missing files instead of raising Errno::ENOENT
    def initialize(*filenames, inherit: true, override: {}, case_sensitive: DEFAULT_CASE_SENSITIVE, ignore: false)
      super()
      @case_sensitive = case_sensitive
      @canonical = {} # normalized key => actual key, for case-insensitive lookups
      @view = {}
      @deleted = []

      inherit_env(inherit).each { |key, value| assign(key, value) }
      base = @view.dup

      filenames.each { |filename| load_file(filename, ignore: ignore) }

      override.each do |key, value|
        value.nil? ? delete_key(key.to_s) : assign(key.to_s, value.to_s)
      end

      replace(@view)
      @deleted.each { |key| self[key] = nil }
      @summary = build_summary(base)
    end

    private

    def normalize(key)
      @case_sensitive ? key : key.downcase
    end

    def assign(key, value)
      if @case_sensitive
        @view[key] = value
      else
        normalized = normalize(key)
        if (existing = @canonical[normalized]) && existing != key
          @view.delete(existing)
        end
        @canonical[normalized] = key
        @view[key] = value
      end
    end

    def delete_key(key)
      actual = @case_sensitive ? key : @canonical[key.downcase]
      @view.delete(actual) if actual
      @canonical.delete(key.downcase) unless @case_sensitive
      @deleted << (actual || key) unless @deleted.include?(actual || key)
    end

    def inherit_env(inherit)
      case inherit
      when true then ENV.to_h
      when false, nil then {}
      when Regexp then ENV.select { |key, _| key.match?(inherit) }
      else
        Array(inherit).each_with_object({}) do |name, hash|
          name = name.to_s
          actual = @case_sensitive ? name : ENV.keys.find { |key| key.downcase == name.downcase }
          hash[actual] = ENV[actual] if actual && ENV.key?(actual)
        end
      end
    end

    def load_file(filename, ignore:)
      parsed = SpawnEnvParser.new(read_file(filename), @view.dup).call
      parsed.each { |key, value| assign(key, value) }
    rescue Errno::ENOENT, Errno::EISDIR
      raise unless ignore
    end

    def read_file(filename)
      File.open(File.expand_path(filename), "rb:bom|utf-8", &:read)
    end

    # Key names only, so the summary never contains secret values.
    def build_summary(base)
      base_keys = base.keys.group_by { |key| normalize(key) }
      view_keys = @view.keys.group_by { |key| normalize(key) }

      {
        "added" => (view_keys.keys - base_keys.keys).map { |key| view_keys[key].last }.sort,
        "changed" => (view_keys.keys & base_keys.keys).select { |key|
          @view[view_keys[key].last] != base[base_keys[key].last]
        }.map { |key| view_keys[key].last }.sort,
        "removed" => (base_keys.keys - view_keys.keys).map { |key| base_keys[key].last }.sort
      }
    end
  end
end
