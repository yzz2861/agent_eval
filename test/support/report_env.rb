# frozen_string_literal: true
# Tiny reporter subprocess used by test_rake_execution_context.rb.
# Writes the values of the environment variables named in ARGV[1..] to
# the file named by ARGV[0], one "NAME=value" line each.
File.write(ARGV[0], ARGV[1..].map { |name| "#{name}=#{ENV[name].inspect}" }.join("\n"))
