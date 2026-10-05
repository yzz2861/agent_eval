# frozen_string_literal: true

require "dry/system/component_manifest"
require "fileutils"

RSpec.describe Dry::System::ComponentManifest do
  include RSpec::Support::TmpDirectory

  let(:root) {
    Pathname(File.expand_path("../../tmp/component-manifest-unit-#{SecureRandom.hex(4)}", __dir__))
  }

  before do
    root.join("lib/admin").mkpath
    write(root.join("lib/admin/user.rb"), "module Admin; class User; end; end\n")
  end

  after do
    FileUtils.remove_entry(root) if root.exist?
  end

  it "detects a changed component key namespace before building a component" do
    manifest = build_manifest { |dir| dir.namespaces.add "admin", key: "admin" }
    container = build_container { |dir| dir.namespaces.add "admin", key: "users" }
    component_dir = container.component_dirs.first
    entry = manifest.find("lib", "admin.user")

    expect { manifest.component_for(component_dir, entry) }
      .to raise_error(Dry::System::ComponentManifestNamingConfigError)
  end

  it "detects changed constant namespace naming before building a component" do
    manifest = build_manifest { |dir| dir.namespaces.add "admin", const: "admin" }
    container = build_container { |dir| dir.namespaces.add "admin", const: "users" }
    component_dir = container.component_dirs.first
    entry = manifest.find("lib", "admin.user")

    expect { manifest.component_for(component_dir, entry) }
      .to raise_error(Dry::System::ComponentManifestNamingConfigError)
  end

  it "rejects component paths that escape the root" do
    manifest = build_manifest { |dir| dir.namespaces.add "admin" }
    entry = manifest.components.first.merge("relative_path" => "../outside.rb")
    container = build_container { |dir| dir.namespaces.add "admin" }
    component_dir = container.component_dirs.first

    expect { manifest.send(:component_for_unverified, component_dir, entry) }
      .to raise_error(Dry::System::ComponentManifestBoundaryError)
  end

  private

  def build_manifest(&)
    described_class.build(build_container(&))
  end

  def build_container
    Class.new(Dry::System::Container).tap do |klass|
      klass.configure do |config|
        config.root = root
        config.provider_dirs = []
        config.component_dirs.add("lib") { |dir| yield dir }
      end
    end
  end
end
