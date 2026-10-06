require "dotenv"
require "dotenv/version"
require "dotenv/template"
require "optparse"

module Dotenv
  # The `dotenv` command line interface. Run `$ dotenv --help` to see usage.
  class CLI < OptionParser
    attr_reader :argv, :filenames, :overwrite, :command_substitution

    def initialize(argv = [])
      @argv = argv.dup
      @filenames = []
      @ignore = false
      @overwrite = false
      @command_substitution = :shell

      super("Usage: dotenv [options]")
      separator ""

      on("-f FILES", Array, "List of env files to parse") do |list|
        @filenames = list
      end

      on("-i", "--ignore", "ignore missing env files") do
        @ignore = true
      end

      on("-o", "--overwrite", "overwrite existing ENV variables") do
        @overwrite = true
      end
      on("--overload") { @overwrite = true }

      on("--commands=POLICY", %i[shell disabled literal],
        "command substitution policy: shell, disabled, or literal") do |policy|
        @command_substitution = policy
      end

      on("-h", "--help", "Display help") do
        puts self
        exit
      end

      on("-v", "--version", "Show version") do
        puts "dotenv #{Dotenv::VERSION}"
        exit
      end

      on("-t", "--template=FILE", "Create a template env file") do |file|
        template = Dotenv::EnvTemplate.new(file)
        template.create_template
      end

      order!(@argv)
    end

    def run
      Dotenv.load(
        *@filenames,
        overwrite: @overwrite,
        ignore: @ignore,
        command_substitution: @command_substitution
      )
    rescue Errno::ENOENT => e
      abort e.message
    else
      exec(*@argv) unless @argv.empty?
    end
  end
end
