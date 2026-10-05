# frozen_string_literal: true

require "dry/system/config_audit"
require "dry/system/container"

# Fixtures under spec/fixtures/config_audit provide directory samples covering
# differently cased file names, inflector acronyms and nested namespaces. Every
# fixture file raises when executed, proving the audit never executes sources.
RSpec.describe Dry::System::ConfigAudit do
  subject(:report) { described_class.new(container).call }

  let(:fixture_root) { SPEC_ROOT.join("fixtures/config_audit/app") }

  let(:container) {
    root = fixture_root

    Class.new(Dry::System::Container) {
      configure do |config|
        config.name = :audit_test
        config.root = root
        config.inflector = Dry::Inflector.new { |inflector| inflector.acronym("API") }

        config.component_dirs.add "lib" do |dir|
          dir.namespaces.add "admin", key: nil
          dir.namespaces.add "api_v1", const: "api/v1"
          dir.namespaces.add "widgets", key: nil
        end

        config.component_dirs.add "plugins" do |dir|
          dir.auto_register = proc { |component| component.key != "never" }
        end

        config.component_dirs.add "ops" do |dir|
          dir.loader = Class.new {
            def self.call(component)
              component
            end
          }
        end
      end
    }
  }

  def find_collision(collisions, type, value)
    collisions.detect { |collision| collision.type == type && collision.value == value }
  end

  def fixture_files(collision)
    collision.files.map { |file| file.relative_path_from(fixture_root).to_s }
  end

  it "does not execute any source files" do
    expect { report }.not_to raise_error
  end

  it "is not clean" do
    expect(report).not_to be_clean
  end

  describe "definite conflicts" do
    it "reports key collisions from nested paths and dotted file names" do
      collision = find_collision(report.conflicts, :key, "foo.bar")

      expect(collision).to be_key
      expect(fixture_files(collision)).to contain_exactly("lib/foo/bar.rb", "lib/foo.bar.rb")
    end

    it "reports key collisions from namespaces with nil keys" do
      collision = find_collision(report.conflicts, :key, "user")

      expect(fixture_files(collision)).to contain_exactly("lib/admin/user.rb", "lib/user.rb")
    end

    it "reports constant collisions from nested paths and dotted file names" do
      collision = find_collision(report.conflicts, :constant, "Foo::Bar")

      expect(collision).to be_constant
      expect(fixture_files(collision)).to contain_exactly("lib/foo/bar.rb", "lib/foo.bar.rb")
    end

    it "reports constant collisions from differently cased file names" do
      collision = find_collision(report.conflicts, :constant, "CasedReport")

      expect(fixture_files(collision)).to contain_exactly(
        "lib/cased_report.rb",
        "lib/CasedReport.rb"
      )
    end

    it "reports constant collisions from acronyms and nested namespace const mappings" do
      collision = find_collision(report.conflicts, :constant, "API::V1::Client")

      expect(fixture_files(collision)).to contain_exactly(
        "lib/api/v1/client.rb",
        "lib/api_v1/client.rb"
      )
    end

    it "reports the transformation rules involved on both sides" do
      collision = find_collision(report.conflicts, :constant, "API::V1::Client")

      nested = collision.entries.detect { |entry| entry.key == "api.v1.client" }
      mapped = collision.entries.detect { |entry| entry.key == "api_v1.client" }

      expect(nested.rules).to include(
        "component dir \"lib\"",
        "root namespace (key: nil, const: nil)",
        "file \"api/v1/client.rb\" maps to key \"api.v1.client\"",
        "const path \"api/v1/client\" camelizes to constant \"API::V1::Client\""
      )

      expect(mapped.rules).to include(
        "component dir \"lib\"",
        "namespace \"api_v1\" (key: \"api_v1\", const: \"api/v1\")",
        "file \"api_v1/client.rb\" maps to key \"api_v1.client\"",
        "const path \"api/v1/client\" camelizes to constant \"API::V1::Client\""
      )
    end

    it "reports no constant conflict when the constants differ" do
      expect(find_collision(report.conflicts, :constant, "User")).to be_nil
      expect(find_collision(report.conflicts, :constant, "Admin::User")).to be_nil
    end
  end

  describe "undetermined collisions" do
    it "reports key collisions involving proc-based auto_register policies" do
      collision = find_collision(report.undetermined, :key, "dashboard")

      expect(fixture_files(collision)).to contain_exactly(
        "lib/dashboard.rb",
        "plugins/dashboard.rb"
      )
      expect(collision.reasons.join).to include "plugins/dashboard.rb"
      expect(collision.reasons.join).to include "auto_register policy is a proc"
    end

    it "reports constant collisions involving proc-based auto_register policies" do
      collision = find_collision(report.undetermined, :constant, "Dashboard")

      expect(fixture_files(collision)).to contain_exactly(
        "lib/dashboard.rb",
        "plugins/dashboard.rb"
      )
    end

    it "reports constant collisions involving custom loaders" do
      collision = find_collision(report.undetermined, :constant, "Beta::Gamma")

      expect(fixture_files(collision)).to contain_exactly(
        "ops/beta/gamma.rb",
        "ops/beta.gamma.rb"
      )
      expect(collision.reasons.join).to include "custom loader"
    end

    it "still reports key collisions as definite when only the loader is custom" do
      collision = find_collision(report.conflicts, :key, "beta.gamma")

      expect(collision).not_to be_nil
      expect(fixture_files(collision)).to contain_exactly(
        "ops/beta/gamma.rb",
        "ops/beta.gamma.rb"
      )
    end
  end

  describe "exclusions" do
    it "does not report collisions when all but one side are excluded by magic comments" do
      expect(find_collision(report.collisions, :key, "thing")).to be_nil
      expect(find_collision(report.collisions, :constant, "Thing")).to be_nil
    end
  end

  describe "entries" do
    let(:collision) { find_collision(report.conflicts, :key, "user") }

    it "exposes the underlying components and component dirs" do
      expect(collision.entries).to all be_a Dry::System::ConfigAudit::Entry
      expect(collision.entries.map(&:component)).to all be_a Dry::System::Component
      expect(collision.entries.map(&:component_dir)).to all be_a Dry::System::ComponentDir
    end

    it "exposes registration status per entry" do
      expect(collision.entries.map(&:registration)).to all eq :registered
    end

    it "describes the auto_register policy source" do
      admin_entry = collision.entries.detect { |entry|
        entry.file_path.to_s.include?("admin")
      }

      expect(admin_entry.rules.last).to eq(
        "auto_register: true (from component dir \"lib\" configuration)"
      )
    end
  end

  describe "report output" do
    it "summarizes both categories with files and rules" do
      output = report.to_s

      expect(output).to include "definite conflicts:"
      expect(output).to include "undetermined collisions (depend on runtime custom logic):"
      expect(output).to include 'key "user" is mapped by 2 files:'
      expect(output).to include "lib/admin/user.rb"
      expect(output).to include 'namespace "admin" (key: nil, const: "admin")'
    end
  end

  context "with no collisions" do
    let(:fixture_root) { SPEC_ROOT.join("fixtures/config_audit/clean") }

    let(:container) {
      root = fixture_root

      Class.new(Dry::System::Container) {
        configure do |config|
          config.name = :clean_audit_test
          config.root = root
          config.component_dirs.add "lib"
        end
      }
    }

    it "is clean" do
      expect(report).to be_clean
      expect(report.to_s).to eq "no collisions found"
    end
  end
end
