# frozen_string_literal: true

require "json"
require "dry/system/container"

RSpec.describe "Component manifest" do
  let(:root) { Pathname(@dir).realpath }

  it "exposes the manifest path configuration (nil by default)" do
    bare = Class.new(Dry::System::Container)

    expect(bare.config.component_manifest_path).to be_nil

    bare.configure do |config|
      config.component_manifest_path = "system/components.json"
    end

    expect(bare.config.component_manifest_path).to eq "system/components.json"
  end

  let(:exporter) {
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

      write "lib/test/example.rb", <<~RUBY
        require "test/dep"

        module Test
          class Example
            def dep
              @dep ||= Test::Dep.new
            end
          end
        end
      RUBY
    end
  end

  before do
    exporter.export_component_manifest("system/components.json")
  end

  after do
    File.write("#{root}/lib/test/dep.rb", <<~RUBY)
      module Test
        class Dep
        end
      end
    RUBY
    File.delete(root.join("lib/test/stray.rb")) if File.exist?(root.join("lib/test/stray.rb"))
    File.delete(root.join("lib/test/later.rb")) if File.exist?(root.join("lib/test/later.rb"))
  end

  def strict_container(root_path = root)
    container_root = root_path

    Class.new(Dry::System::Container) {
      configure do |config|
        config.root = container_root
        config.component_dirs.add "lib"
        config.component_manifest_path = "system/components.json"
      end
    }
  end

  describe "exporting a manifest" do
    it "writes JSON recording the component key, relative path, constant name and digest" do
      exporter.export_component_manifest("system/components.json")

      data = JSON.parse(root.join("system/components.json").read)

      expect(data.fetch("root")).to eq root.to_s
      expect(data.fetch("mode")).to eq "manifest"
      expect(data.fetch("naming_version")).to match(/\A[0-9a-f]{64}\z/)

      component = data.fetch("components").find { |entry| entry["key"] == "test.example" }

      expect(component).to include(
        "key" => "test.example",
        "dir" => "lib",
        "path" => "lib/test/example.rb",
        "const_name" => "Test::Example",
        "namespace" => {"path" => nil, "key" => nil, "const" => nil}
      )
      expect(component.fetch("digest")).to match(/\A[0-9a-f]{64}\z/)
    end

    it "does not require, instantiate or execute any component while exporting" do
      features_before = $LOADED_FEATURES.dup

      exporter.export_component_manifest("system/components.json")

      loaded_components = ($LOADED_FEATURES - features_before).grep(/test\/(dep|example)\.rb/)

      expect(loaded_components).to eq []
      expect(Object.const_defined?("Test::Example")).to be false
    end

    it "returns the exported manifest" do
      manifest = exporter.export_component_manifest("system/components.json")

      expect(manifest).to be_a Dry::System::ComponentManifest
      expect(manifest.entries.keys).to eq %w[test.dep test.example]
    end

    it "rejects an unknown mode" do
      expect {
        exporter.export_component_manifest("system/components.json", mode: :nope)
      }.to raise_error(Dry::System::ComponentManifestInvalidError, /mode/)
    end

    it "requires a path when none is configured" do
      expect { exporter.export_component_manifest }
        .to raise_error(ArgumentError, /path is required/)
    end
  end

  describe "loading with a manifest" do
    after do
      File.delete(root.join("lib/test/stray.rb")) if File.exist?(root.join("lib/test/stray.rb"))
      File.delete(root.join("lib/test/later.rb")) if File.exist?(root.join("lib/test/later.rb"))
    end

    it "resolves listed components" do
      container = strict_container

      expect(container["test.example"].dep).to be_a Test::Dep
    end

    it "does not scan the directory: an unlisted component is invisible in strict mode" do
      write "#{root}/lib/test/stray.rb", <<~RUBY
        module Test
          class Stray
          end
        end
      RUBY

      expect { strict_container["test.stray"] }
        .to raise_error(Dry::Core::Container::KeyError)
    end

    it "finalizes only the listed components in strict mode" do
      write "#{root}/lib/test/stray.rb", <<~RUBY
        module Test
          class Stray
          end
        end
      RUBY

      container = strict_container
      container.finalize!

      expect(container.keys).to contain_exactly("test.dep", "test.example")
    end
  end

  describe "namespaced component dirs" do
    before do
      FileUtils.mkdir_p(root.join("lib/admin"))

      write "#{root}/lib/admin/widget.rb", <<~RUBY
        module Admin
          class Widget
          end
        end
      RUBY
    end

    after do
      File.delete(root.join("lib/admin/widget.rb"))
    end

    it "records and resolves the namespace, key, path and constant name" do
      namespaced_root = root

      namespaced = Class.new(Dry::System::Container) {
        configure do |config|
          config.root = namespaced_root
          config.component_dirs.add "lib" do |dir|
            dir.namespaces.add "admin", key: "admin", const: "admin"
          end
        end
      }

      manifest = namespaced.export_component_manifest("system/namespaced.json")
      entry = manifest["admin.widget"]

      expect(entry.path).to eq "lib/admin/widget.rb"
      expect(entry.const_name).to eq "Admin::Widget"
      expect(entry.namespace).to eq("path" => "admin", "key" => "admin", "const" => "admin")

      loading = Class.new(Dry::System::Container) {
        configure do |config|
          config.root = namespaced_root
          config.component_dirs.add "lib" do |dir|
            dir.namespaces.add "admin", key: "admin", const: "admin"
          end
          config.component_manifest_path = "system/namespaced.json"
        end
      }

      expect(loading["admin.widget"]).to be_a Admin::Widget
    end
  end

  describe "verification before require" do
    it "raises a digest error before requiring the modified component file" do
      File.write("#{root}/lib/test/dep.rb", <<~RUBY)
        module Test
          class Dep
          end
        end

        module InjectedByTampering
        end
      RUBY

      expect {
        strict_container["test.dep"]
      }.to raise_error(Dry::System::ComponentManifestDigestError)

      expect(Object.const_defined?(:InjectedByTampering)).to be false
    end

    it "raises a root mismatch error after moving the directory" do
      moved = Pathname(make_tmp_directory).join("app").tap(&:mkpath)
      FileUtils.cp_r(root.join("lib"), moved.join("lib"))
      FileUtils.mkdir_p(moved.join("system"))
      FileUtils.cp(root.join("system/components.json"), moved.join("system/components.json"))
      moved = moved.realpath

      expect {
        strict_container(moved)["test.dep"]
      }.to raise_error(Dry::System::ComponentManifestRootMismatchError)
    end

    it "raises a naming version error when the inflector changes" do
      custom_inflector = Dry::Inflector.new { |inflections|
        inflections.acronym("XYZ")
      }

      container_root = root
      container = Class.new(Dry::System::Container) {
        configure do |config|
          config.root = container_root
          config.component_dirs.add "lib"
          config.component_manifest_path = "system/components.json"
          config.inflector = custom_inflector
        end
      }

      expect {
        container["test.example"]
      }.to raise_error(Dry::System::ComponentManifestNamingVersionError)
    end

    it "raises a constant name error when the component resolves to another constant" do
      data = JSON.parse(root.join("system/components.json").read)
      data["components"].find { |entry| entry["key"] == "test.example" }["const_name"] = "Test::Other"
      root.join("system/components.json").write(JSON.generate(data))

      expect {
        strict_container["test.example"]
      }.to raise_error(Dry::System::ComponentManifestConstNameError)
    end
  end

  describe "fallback_scan mode" do
    before do
      exporter.export_component_manifest("system/components-fallback.json", mode: :fallback_scan)
    end

    after do
      File.delete(root.join("lib/test/later.rb")) if File.exist?(root.join("lib/test/later.rb"))
    end

    def fallback_container
      container_root = root

      Class.new(Dry::System::Container) {
        configure do |config|
          config.root = container_root
          config.component_dirs.add "lib"
          config.component_manifest_path = "system/components-fallback.json"
        end
      }
    end

    it "resolves listed components from the manifest" do
      expect(fallback_container["test.example"].dep).to be_a Test::Dep
    end

    it "falls back to scanning for components added after the manifest was built" do
      write "#{root}/lib/test/later.rb", <<~RUBY
        module Test
          class Later
          end
        end
      RUBY

      expect(fallback_container["test.later"]).to be_a Test::Later
    end

    it "does not ignore digest failures for listed components" do
      File.write("#{root}/lib/test/dep.rb", <<~RUBY)
        module Test
          class Dep
          end
        end
        # changed
      RUBY

      expect {
        fallback_container["test.dep"]
      }.to raise_error(Dry::System::ComponentManifestDigestError)
    end

    it "registers both listed and unlisted components when finalizing" do
      write "#{root}/lib/test/later.rb", <<~RUBY
        module Test
          class Later
          end
        end
      RUBY

      container = fallback_container
      container.finalize!

      expect(container.keys).to contain_exactly("test.dep", "test.example", "test.later")
    end
  end
end
