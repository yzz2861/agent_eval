# frozen_string_literal: true

require "dry/system/config_auditor"
require "dry/system/container"

RSpec.describe Dry::System::ConfigAuditor do
  subject(:report) { container.audit_config }

  # Sample directory trees are created inside the repo (rather than the system tmp
  # dir) so that file globbing works in restricted environments
  audit_tmp_dirs = []

  define_method :make_audit_dir do
    FileUtils.mkdir_p SPEC_ROOT.join("tmp")
    Pathname(Dir.mktmpdir("config_auditor", SPEC_ROOT.join("tmp"))).tap { |dir|
      audit_tmp_dirs << dir
    }
  end

  after :all do
    audit_tmp_dirs.each { |dir| FileUtils.remove_entry(dir) }
  end

  let(:container) {
    container_root = @dir
    container_inflector = inflector
    dir_config = component_dir_config

    Class.new(Dry::System::Container) {
      configure do |config|
        config.root = container_root
        config.inflector = container_inflector
        config.component_dirs.add "lib" do |dir|
          dir_config.(dir) if dir_config
        end
      end
    }
  }

  let(:inflector) { Dry::Inflector.new }
  let(:component_dir_config) { nil }

  context "no collisions" do
    before :all do
      @dir = make_audit_dir

      with_directory(@dir) do
        write "lib/foo.rb"
        write "lib/bar/baz.rb"
        write "lib/invalid_ruby.rb", "this is not valid ruby %$#"
      end
    end

    it "reports no collisions" do
      expect(report).not_to be_collisions
      expect(report.to_s).to include "No collisions"
    end

    it "expands every component file without executing its source" do
      expect(report.entries.map(&:key)).to contain_exactly(
        "foo", "bar.baz", "invalid_ruby"
      )
    end
  end

  context "key collision through a nested namespace" do
    before :all do
      @dir = make_audit_dir

      with_directory(@dir) do
        write "lib/admin/user.rb"
        write "lib/user.rb"
      end
    end

    let(:component_dir_config) {
      -> dir {
        dir.namespaces.add "admin", key: nil
      }
    }

    it "reports a definite key collision with both files and the rules involved" do
      expect(report.collisions.length).to eq 1

      collision = report.collisions.first
      expect(collision.kind).to eq :key
      expect(collision.value).to eq "user"
      expect(collision).to be_definite
      expect(collision.files.map { |f| f.to_s }).to contain_exactly(
        @dir.join("lib/admin/user.rb").to_s,
        @dir.join("lib/user.rb").to_s
      )

      admin_entry = collision.entries.detect { |e| e.namespace.path == "admin" }
      expect(admin_entry.rules.join).to include 'namespace "admin" (key: nil, const: "admin")'
    end

    it "does not report a constant collision" do
      expect(report.entries.map(&:constant_name)).to contain_exactly("Admin::User", "User")
    end

    it "renders the collision in the report output" do
      expect(report.to_s).to include 'key collision on "user" (definite)'
      expect(report.to_s).to include "lib/admin/user.rb"
      expect(report.to_s).to include "lib/user.rb"
    end
  end

  context "constant collision through letter case" do
    before :all do
      @dir = make_audit_dir

      with_directory(@dir) do
        write "lib/foo_bar.rb"
        write "lib/fooBar.rb"
      end
    end

    it "reports a definite constant collision while the keys remain distinct" do
      expect(report.collisions.length).to eq 1

      collision = report.collisions.first
      expect(collision.kind).to eq :constant
      expect(collision.value).to eq "FooBar"
      expect(collision).to be_definite
      expect(collision.files.map { |f| f.to_s }).to contain_exactly(
        @dir.join("lib/foo_bar.rb").to_s,
        @dir.join("lib/fooBar.rb").to_s
      )

      expect(report.entries.map(&:key)).to contain_exactly("foo_bar", "fooBar")
    end
  end

  context "constant collision involving inflector acronyms" do
    before :all do
      @dir = make_audit_dir

      with_directory(@dir) do
        write "lib/crm_adapter.rb"
        write "lib/services/crm_adapter.rb"
      end
    end

    let(:inflector) {
      Dry::Inflector.new { |i| i.acronym "CRM" }
    }

    let(:component_dir_config) {
      -> dir {
        dir.namespaces.add "services", const: nil
      }
    }

    it "derives constants using the configured inflector acronyms" do
      expect(report.entries.map(&:constant_name)).to contain_exactly("CRMAdapter", "CRMAdapter")

      collision = report.collisions.first
      expect(collision.kind).to eq :constant
      expect(collision.value).to eq "CRMAdapter"
      expect(collision).to be_definite
    end
  end

  context "key collision through a nested namespace path" do
    before :all do
      @dir = make_audit_dir

      with_directory(@dir) do
        write "lib/api/v1/client.rb"
        write "lib/client.rb"
      end
    end

    let(:component_dir_config) {
      -> dir {
        dir.namespaces.add "api/v1", key: nil
      }
    }

    it "reports a definite key collision" do
      collision = report.collisions.first
      expect(collision.kind).to eq :key
      expect(collision.value).to eq "client"
      expect(collision).to be_definite

      expect(report.entries.map(&:constant_name)).to contain_exactly("API::V1::Client", "Client")
    end
  end

  context "exclusion rules" do
    context "auto_register disabled via magic comment" do
      before :all do
        @dir = make_audit_dir

        with_directory(@dir) do
          write "lib/admin/user.rb", <<~RUBY
            # auto_register: false
          RUBY
          write "lib/user.rb"
        end
      end

      let(:component_dir_config) {
        -> dir {
          dir.namespaces.add "admin", key: nil
        }
      }

      it "excludes the file from key collisions" do
        expect(report.collisions).to be_empty

        excluded = report.entries.detect { |e| e.file_path.to_s.end_with?("admin/user.rb") }
        expect(excluded).to be_excluded
      end
    end

    context "auto_register disabled for the whole dir" do
      before :all do
        @dir = make_audit_dir

        with_directory(@dir) do
          write "lib/foo.rb"
        end
      end

      let(:component_dir_config) {
        -> dir {
          dir.auto_register = false
        }
      }

      it "skips the dir" do
        expect(report.entries).to be_empty
        expect(report.skipped_component_dirs).to eq ["lib"]
      end
    end
  end

  context "runtime-dependent configuration" do
    context "callable auto_register policy" do
      before :all do
        @dir = make_audit_dir

        with_directory(@dir) do
          write "lib/admin/user.rb"
          write "lib/user.rb"
        end
      end

      let(:component_dir_config) {
        -> dir {
          dir.namespaces.add "admin", key: nil
          dir.auto_register = proc { |component| component.key != "user" }
        }
      }

      it "reports the key collision as indeterminate" do
        collision = report.collisions.first
        expect(collision.kind).to eq :key
        expect(collision.value).to eq "user"
        expect(collision).to be_indeterminate
        expect(report.indeterminate_collisions).to eq [collision]
        expect(report.definite_collisions).to be_empty
      end
    end

    context "custom instance proc" do
      before :all do
        @dir = make_audit_dir

        with_directory(@dir) do
          write "lib/foo_bar.rb"
          write "lib/fooBar.rb"
        end
      end

      let(:component_dir_config) {
        -> dir {
          dir.instance = proc { |component| component.loader.constant(component) }
        }
      }

      it "reports the constant collision as indeterminate" do
        collision = report.collisions.first
        expect(collision.kind).to eq :constant
        expect(collision.value).to eq "FooBar"
        expect(collision).to be_indeterminate
      end
    end
  end
end
