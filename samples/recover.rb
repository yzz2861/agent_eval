#!/usr/bin/env ruby
# frozen_string_literal: true

$LOAD_PATH << '../lib'

require 'zip'

# Scans a zip archive whose central directory is missing or corrupt and
# prints a recovery manifest. Given a second argument, exports every
# verified entry to a new archive (the source is never modified).
#
#   ruby recover.rb broken.zip
#   ruby recover.rb broken.zip recovered.zip

unless (1..2).cover?(ARGV.size)
  puts 'Usage: ruby recover.rb <broken.zip> [recovered.zip]'
  exit 1
end

report = Zip::Recovery.scan(ARGV[0])
puts report

if ARGV[1]
  Zip::Recovery.export(ARGV[0], ARGV[1])
  puts "Verified entries written to '#{ARGV[1]}'."
end
