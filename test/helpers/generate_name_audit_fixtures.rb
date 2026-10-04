# frozen_string_literal: true

# Regenerates the handcrafted entry-name audit fixtures in
# test/data/name_audit. These fixtures contain deliberately malformed or
# inconsistent name data that Zip::OutputStream cannot produce, which is
# why they are built byte-by-byte. Run from the repository root with:
#
#   ruby test/helpers/generate_name_audit_fixtures.rb
#
# The entry_name_audit tests verify that the files on disk still match
# what the builder produces, so regenerate them whenever the builder
# changes.
require_relative 'name_audit_fixture_builder'

dir = File.expand_path('../data/name_audit', __dir__)
NameAuditFixtureBuilder.write_all(dir)
puts "Wrote #{NameAuditFixtureBuilder::SAMPLES.size} fixtures to #{dir}"

