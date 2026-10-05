# frozen_string_literal: true

require "json"
require "dry/system/component_manifest"
require "dry/system/container"

RSpec.describe Dry::System::ComponentManifest do
  subject(:manifest) { described_class.build(container) }

  let(:root) { Pathname(@dir).realpath }

  let(:container) {
    container_root = root

    Class.new(Dry::System::Container) {
      configure do |config|
        config.root = container_root
        config.component_dirs.add "lib"
      end
    }
  }

  before :all do
    @dir = make_tmp_directory

    with_directory(@dir) do
      write "lib/test/dep.rb", <<~RUBY
        module Test
          class Dep
          end
        end
      RUBY

      write "lib/test/create_article.rb", <<~RUBY
        module Test
          class CreateArticle
          end
        end
      RUBY
    end
  end

  describe ".build" do
    it "lists every component in the component dirs" do
      expect(manifest.entries.keys).to eq %w[test.create_article test.dep]
    end

    it "records the key, root-relative path, constant name and digest for each component" do
      entry = manifest["test.create_article"]

      expect(entry.key).to eq "test.create_article"
      expect(entry.dir).to eq "lib"
      expect(entry.path).to eq "lib/test/create_article.rb"
      expect(entry.const_name).to eq "Test::CreateArticle"
      expect(entry.digest).to eq Digest::SHA256.file(root.join("lib/test/create_article.rb")).hexdigest
      expect(entry.namespace).to eq("path" => nil, "key" => nil, "const" => nil)
    end

    it "records the real root and a naming version" do
      expect(manifest.root).to eq root.to_s
      expect(manifest.naming_version).to match(/\A[0-9a-f]{64}\z/)
    end

    it "defaults to strict manifest mode" do
      expect(manifest.mode).to eq :manifest
      expect(manifest).not_to be_fallback_scan
    end

    it "does not load any component source file" do
      features = $LOADED_FEATURES.grep(/\.rb\z/)

      manifest

      expect($LOADED_FEATURES.grep(/\.rb\z/) - features).to eq []
    end

    it "does not define the component constants" do
      manifest

      expect(Object.const_defined?("Test::CreateArticle")).to be false
    end

    it "rejects a component file that symlinks outside the root" do
      outside = root.parent.join("component-manifest-outside-#{Process.pid}.rb")
      File.write(outside, "module Outside\nend\n")
      File.symlink(outside, root.join("lib/escaped.rb"))

      expect { described_class.build(container) }
        .to raise_error(Dry::System::ComponentManifestBoundaryError)
    ensure
      File.delete(root.join("lib/escaped.rb"))
      File.delete(outside)
    end
  end

  describe "#to_h and JSON round trip" do
    it "round trips through JSON" do
      parsed = described_class.from_h(JSON.parse(JSON.generate(manifest.to_h)))

      expect(parsed.root).to eq manifest.root
      expect(parsed.naming_version).to eq manifest.naming_version
      expect(parsed.mode).to eq manifest.mode
      expect(parsed.entries.keys).to eq manifest.entries.keys
      expect(parsed["test.dep"].path).to eq "lib/test/dep.rb"
    end

    it "persists the fallback scan mode" do
      parsed = described_class.from_h(
        JSON.parse(JSON.generate(described_class.build(container, mode: :fallback_scan).to_h))
      )

      expect(parsed).to be_fallback_scan
    end
  end

  describe ".load" do
    it "loads a manifest written as JSON" do
      path = root.join("components.json")
      path.write(JSON.generate(manifest.to_h))

      expect(described_class.load(path).entries.keys).to eq manifest.entries.keys
    end

    it "raises when the manifest file is absent" do
      expect { described_class.load(root.join("missing.json")) }
        .to raise_error(Dry::System::ComponentManifestNotFoundError)
    end

    it "raises for malformed JSON" do
      path = root.join("broken.json")
      path.write("{nope")

      expect { described_class.load(path) }
        .to raise_error(Dry::System::ComponentManifestInvalidError)
    end

    it "raises for an unsupported format version" do
      data = manifest.to_h.merge("format_version" => 999)
      path = root.join("future.json")
      path.write(JSON.generate(data))

      expect { described_class.load(path) }
        .to raise_error(Dry::System::ComponentManifestInvalidError, /format version/)
    end

    it "raises for an unknown mode" do
      data = manifest.to_h.merge("mode" => "whatever")
      path = root.join("bad-mode.json")
      path.write(JSON.generate(data))

      expect { described_class.load(path) }
        .to raise_error(Dry::System::ComponentManifestInvalidError, /mode/)
    end

    it "raises when an entry is missing required fields" do
      data = manifest.to_h
      data["components"].first.delete("digest")
      path = root.join("invalid.json")
      path.write(JSON.generate(data))

      expect { described_class.load(path) }
        .to raise_error(Dry::System::ComponentManifestInvalidError, /digest/)
    end
  end

  describe "#verify!" do
    it "passes for the current container" do
      expect(manifest.verify!(container)).to be manifest
    end

    it "raises when the container root moved" do
      moved_root = Pathname(make_tmp_directory).join("app").tap(&:mkpath)
      FileUtils.cp_r(root.join("lib"), moved_root.join("lib"))
      moved_root = moved_root.realpath

      expect { manifest.verify!(container_with(root: moved_root)) }
        .to raise_error(Dry::System::ComponentManifestRootMismatchError)
    end

    it "raises when the inflector rules changed" do
      changed_inflector = Dry::Inflector.new { |inflections|
        inflections.acronym("XYZ")
      }

      expect { manifest.verify!(container_with(inflector: changed_inflector)) }
        .to raise_error(Dry::System::ComponentManifestNamingVersionError)
    end

    it "raises when a namespace configuration changed" do
      namespaced_root = root
      container_with_namespace = Class.new(Dry::System::Container) {
        configure do |config|
          config.root = namespaced_root
          config.component_dirs.add "lib" do |dir|
            dir.namespaces.add "test", key: nil
          end
        end
      }

      expect { manifest.verify!(container_with_namespace) }
        .to raise_error(Dry::System::ComponentManifestNamingVersionError)
    end
  end

  describe "#verify_entry!" do
    let(:entry) { manifest["test.dep"] }

    it "passes when the source file is unchanged" do
      expect(manifest.verify_entry!(entry)).to be entry
    end

    it "raises a digest error after the source file is modified" do
      path = root.join(entry.path)
      path.write("#{path.read}\n# changed\n")

      expect { manifest.verify_entry!(entry) }
        .to raise_error(Dry::System::ComponentManifestDigestError)
    end

    it "raises a boundary error when the path escapes the root" do
      escaped = manifest.entries.values.first
      escaped.instance_variable_set(:@path, "../../../etc/passwd.rb")

      expect { manifest.verify_entry!(escaped) }
        .to raise_error(Dry::System::ComponentManifestBoundaryError)
    end
  end

  describe "naming version stability" do
    it "is stable across builds with the same configuration" do
      expect(described_class.naming_version_for(container))
        .to eq described_class.naming_version_for(container)
    end

    it "ignores unrelated acronyms that do not affect inflector behavior" do
      baseline = described_class.naming_version_for(container)

      other_inflector = Dry::Inflector.new
      other = container_with(inflector: other_inflector)

      expect(described_class.naming_version_for(other)).to eq baseline
    end
  end

  def container_with(root: self.root, inflector: container.config.inflector)
    container_root = root
    container_inflector = inflector

    Class.new(Dry::System::Container) {
      configure do |config|
        config.root = container_root
        config.component_dirs.add "lib"
        config.inflector = container_inflector
      end
    }
  end
end
