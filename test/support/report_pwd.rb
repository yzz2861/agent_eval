# frozen_string_literal: true
# Tiny reporter subprocess used by test_rake_execution_context.rb.
# Writes its working directory to the file named by ARGV[0].
File.write(ARGV[0], Dir.pwd)
