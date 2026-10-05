# frozen_string_literal: true

require "dry/system/component_dir"
require "dry/system/config/component_dir"
require "dry/system/component_manifest"
require "dry/system/container"

RSpec.describe Dry::System::ComponentDir, "component manifest" do
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
      write "lib/test/listed.rb", <<~RUBY
        module Test
          class Listed
          end
        end
      RUBY
    end
  end

  let(:component_dir) {
    config = Dry::System::Config::ComponentDir.new("lib")
    described_class.new(config: config, container: container, manifest: manifest)
  }

  let(:manifest) {
    Dry::System::ComponentManifest.build(container, mode: mode)
  }

  after do
    unlisted = root.join("lib/test/unlisted.rb")
    File.delete(unlisted) if File.exist?(unlisted)
  end

  describe "strict :manifest mode" do
    let(:mode) { :manifest }

    before { manifest }

    it "builds the component from the manifest entry" do
      component = component_dir.component_for_key("test.listed")

      expect(component).to be_a Dry::System::Component
      expect(component.key).to eq "test.listed"
      expect(component.file_path).to eq root.join("lib/test/listed.rb")
      expect(component.inflector.camelize(component.const_path)).to eq "Test::Listed"
    end

    it "does not scan for keys missing from the manifest" do
      write "#{root}/lib/test/unlisted.rb", <<~RUBY
        module Test
          class Unlisted
          end
        end
      RUBY

      expect(component_dir.component_for_key("test.unlisted")).to be_nil
    end

    it "enumerates only the manifest components" do
      write "#{root}/lib/test/unlisted.rb", <<~RUBY
        module Test
          class Unlisted
          end
        end
      RUBY

      expect(component_dir.each_component.map(&:key)).to eq %w[test.listed]
    end

    it "raises a digest error before requiring a modified listed component" do
      File.write("#{root}/lib/test/listed.rb", <<~RUBY)
        module Test
          class Listed
          end
        end

        module InjectedByComponentDirTampering
        end
      RUBY

      expect { component_dir.component_for_key("test.listed") }
        .to raise_error(Dry::System::ComponentManifestDigestError)

      expect(Object.const_defined?(:InjectedByComponentDirTampering)).to be false
    ensure
      File.write("#{root}/lib/test/listed.rb", <<~RUBY)
        module Test
          class Listed
          end
        end
      RUBY
    end
  end

  describe ":fallback_scan mode" do
    let(:mode) { :fallback_scan }

    before { manifest }

    it "builds listed components from the manifest" do
      expect(component_dir.component_for_key("test.listed").key).to eq "test.listed"
    end

    it "scans for unlisted keys" do
      write "#{root}/lib/test/unlisted.rb", <<~RUBY
        module Test
          class Unlisted
          end
        end
      RUBY

      expect(component_dir.component_for_key("test.unlisted").key).to eq "test.unlisted"
    end

    it "enumerates manifest components plus scanned components not listed" do
      write "#{root}/lib/test/unlisted.rb", <<~RUBY
        module Test
          class Unlisted
          end
        end
      RUBY

      expect(component_dir.each_component.map(&:key).sort).to eq %w[
        test.listed test.unlisted
      ]
    end

    after do
      File.delete(root.join("lib/test/unlisted.rb")) if File.exist?(root.join("lib/test/unlisted.rb"))
    end
  end
end
