# frozen_string_literal: true

require "fileutils"
require "json"

RSpec.describe "Component manifest" do
  include RSpec::Support::TmpDirectory

  subject(:container) { build_container }

  let(:root) {
    Pathname(File.expand_path("../../../tmp/component-manifest-#{SecureRandom.hex(4)}", __dir__))
  }

  let(:manifest_path) { root.join("component-manifest.json") }

  before do
    $component_manifest_loaded = nil
    root.join("lib/test").mkpath
    write(root.join("lib/test/foo.rb"), <<~RUBY)
      module Test
        class Foo
          $component_manifest_loaded = true
        end
      end
    RUBY
  end

  after do
    FileUtils.remove_entry(root) if root.exist?
  end

  it "exports primitive component metadata without executing providers" do
    provider_path = root.join("system/providers/test.rb")
    write(provider_path, <<~'RUBY')
      raise "providers must not execute during manifest export"
    RUBY

    build_container(provider_dirs: ["system/providers"]).export_component_manifest
    data = JSON.parse(manifest_path.read)
    component = data["components"].find { |entry| entry["key"] == "test.foo" }

    expect(component).to eq(
      "component_dir" => "lib",
      "key" => "test.foo",
      "relative_path" => "lib/test/foo.rb",
      "require_path" => "test/foo",
      "const_path" => "test/foo",
      "const_name" => "Test::Foo",
      "digest" => Digest::SHA256.file(root.join("lib/test/foo.rb")).hexdigest
    )
    expect(component).not_to include("instance", "loader", "provider")
  end

  it "raises a manifest error for malformed JSON before requiring components" do
    export_manifest
    File.write(manifest_path, "{")

    expect { container.finalize! }
      .to raise_error(Dry::System::ComponentManifestMalformedError)
    expect($component_manifest_loaded).to be_nil
  end

  it "verifies a changed digest before requiring the component" do
    export_manifest

    File.write(root.join("lib/test/foo.rb"), <<~RUBY)
      module Test
        class Foo
          $component_manifest_loaded = false
        end
      end
    RUBY

    expect { container.finalize! }
      .to raise_error(Dry::System::ComponentManifestDigestMismatchError)
    expect($component_manifest_loaded).to be_nil
  end

  it "verifies the root before requiring a component" do
    export_manifest

    moved_root = root.dirname.join("#{root.basename}-moved")
    FileUtils.cp_r(root, moved_root)

    moved_container = build_container(root: moved_root)

    expect { moved_container.finalize! }
      .to raise_error(Dry::System::ComponentManifestRootMismatchError)
    expect($component_manifest_loaded).to be_nil
  ensure
    FileUtils.remove_entry(moved_root) if moved_root&.exist?
  end

  it "verifies the inflector naming configuration before requiring a component" do
    export_manifest

    changed_container = build_container(inflector: Dry::Inflector.new)
    expect { changed_container.finalize! }
      .to raise_error(Dry::System::ComponentManifestNamingConfigError)
    expect($component_manifest_loaded).to be_nil
  end

  it "allows unlisted components only when fallback scanning is explicitly enabled" do
    export_manifest

    write(root.join("lib/test/bar.rb"), <<~RUBY)
      module Test
        class Bar
        end
      end
      $component_manifest_unlisted_loaded = true
    RUBY

    $component_manifest_unlisted_loaded = nil
    fallback_container = build_container(fallback_scan: true)

    expect(fallback_container["test.bar"]).to be_a(Test::Bar)
    expect($component_manifest_unlisted_loaded).to be(true)

    $component_manifest_unlisted_loaded = nil
    expect(container.resolve("test.bar") { :missing }).to be(:missing)
    expect($component_manifest_unlisted_loaded).to be_nil
  end

  private

  def export_manifest
    build_container.tap { |manifest_container| manifest_container.export_component_manifest }
  end

  def build_container(
    root: self.root,
    inflector: build_inflector,
    fallback_scan: false,
    provider_dirs: []
  )
    Class.new(Dry::System::Container).tap do |klass|
      klass.configure do |config|
        config.root = root
        config.provider_dirs = provider_dirs
        config.registrations_dir = "system/registrations-#{SecureRandom.hex(4)}"
        config.inflector = inflector
        config.component_dirs.add "lib"
        config.component_manifest_path = "component-manifest.json"
        config.component_manifest_fallback_scan = fallback_scan
      end
    end
  end

  def build_inflector
    Dry::Inflector.new do |inflector|
      inflector.acronym("GSB")
    end
  end
end
