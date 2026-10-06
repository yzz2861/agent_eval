require "spec_helper"
require "open3"
require "json"
require "rbconfig"

describe Dotenv do
  describe ".spawn_env" do
    it "distinguishes empty strings, missing values, and explicit deletion" do
      Dir.mktmpdir do |dir|
        env_file = File.join(dir, ".env")
        File.write(env_file, "EMPTY=\nFROM_FILE=file\n")

        env = Dotenv.spawn_env(
          env_file,
          inherit: %w[REMOVED EMPTY],
          overrides: {"EMPTY" => "", "REMOVED" => nil, "ADDED" => "value"},
          source: {"REMOVED" => "parent", "EMPTY" => "parent", "HIDDEN" => "secret"}
        )

        expect(env.fetch("EMPTY")).to eq("")
        expect(env).not_to have_key("UNPROVIDED")
        expect(env.fetch("REMOVED")).to be_nil
        expect(env.fetch("HIDDEN")).to be_nil
        expect(env.fetch("ADDED")).to eq("value")
        expect(env.summary[:empty]).to eq(%w[EMPTY])
        expect(env.summary[:changed]).to eq(%w[EMPTY])
        expect(env.summary[:removed]).to match_array(%w[HIDDEN REMOVED])
        expect(env.summary[:deleted]).to eq(%w[REMOVED])
      end
    end

    it "expands variables only from the selected environment view" do
      Dir.mktmpdir do |dir|
        env_file = File.join(dir, ".env")
        File.write(env_file, "EXPANDED=prefix-$ALLOWED-$BLOCKED-$MISSING\n")

        env = Dotenv.spawn_env(
          env_file,
          inherit: %w[ALLOWED],
          source: {"ALLOWED" => "visible", "BLOCKED" => "secret"}
        )

        expect(env.fetch("EXPANDED")).to eq("prefix-visible--")
      end
    end

    it "keeps command substitutions inside the same environment view" do
      Dir.mktmpdir do |dir|
        env_file = File.join(dir, ".env")
        File.write(env_file, "TEST_COMMAND=$(printf %s \"$BLOCKED\")\n")

        env = Dotenv.spawn_env(
          env_file,
          inherit: :none,
          source: {"BLOCKED" => "secret"}
        )

        expect(env.fetch("TEST_COMMAND")).to eq("")
      end
    end

    it "does not modify the parent environment" do
      Dir.mktmpdir do |dir|
        env_file = File.join(dir, ".env")
        File.write(env_file, "TEST_FILE_VALUE=file\n")
        ENV["TEST_PARENT_VALUE"] = "parent"

        snapshot = ENV.to_h
        Dotenv.spawn_env(
          env_file,
          inherit: %w[TEST_PARENT_VALUE],
          overrides: {"TEST_PARENT_VALUE" => nil, "TEST_EXPLICIT" => "value"},
          source: ENV
        )

        expect(ENV.to_h).to eq(snapshot)
      ensure
        ENV.delete("TEST_PARENT_VALUE")
      end
    end

    it "merges later files before explicit overrides" do
      Dir.mktmpdir do |dir|
        first = File.join(dir, "first.env")
        second = File.join(dir, "second.env")
        File.write(first, "SHARED=first\nFIRST=yes\n")
        File.write(second, "SHARED=second\nSECOND=yes\n")

        env = Dotenv.spawn_env(
          first,
          second,
          inherit: :none,
          overrides: {"SHARED" => "explicit"},
          source: {"PARENT" => "secret"}
        )

        expect(env.fetch("SHARED")).to eq("explicit")
        expect(env.fetch("FIRST")).to eq("yes")
        expect(env.fetch("SECOND")).to eq("yes")
        expect(env.fetch("PARENT")).to be_nil
        expect(env.summary[:changed]).to eq([])
        expect(env.summary[:added]).to match_array(%w[FIRST SECOND SHARED])
        expect(env.summary[:removed]).to eq(%w[PARENT])
      end
    end

    it "applies case-insensitive key rules without dropping values" do
      Dir.mktmpdir do |dir|
        first = File.join(dir, "first.env")
        second = File.join(dir, "second.env")
        File.write(first, "Mixed=first\nsecret=first\n")
        File.write(second, "MIXED=second\nSECRET=second\n")

        env = Dotenv.spawn_env(
          first,
          second,
          inherit: %w[PATH],
          case_sensitive: false,
          source: {"Path" => "/bin", "SECRET" => "parent-secret"}
        )

        expect(env.fetch("MIXED")).to eq("second")
        expect(env.fetch("SECRET")).to eq("second")
        expect(env["secret"]).to be_nil
        expect(env.fetch("Path")).to eq("/bin")
        expect(env["PATH"]).to be_nil
        expect(env.summary[:case_conflicts]).to include(
          "mixed" => %w[Mixed MIXED],
          "secret" => %w[secret SECRET]
        )
        expect(JSON.generate(env.summary)).not_to include("parent-secret")
      end
    end

    it "rejects invalid inheritance and key rules" do
      expect { Dotenv.spawn_env(inherit: :selected) }
        .to raise_error(ArgumentError, /Invalid value for inherit/)
      expect { Dotenv.spawn_env(case_sensitive: :windows) }
        .to raise_error(ArgumentError, /Invalid value for case_sensitive/)
    end

    it "runs two isolated short-lived child processes" do
      Dir.mktmpdir do |dir|
        first_file = File.join(dir, "first.env")
        second_file = File.join(dir, "second.env")

        File.write(first_file, <<~ENV)
          TEST_ROLE=first
          TEST_SHARED=first-only
          TEST_SECRET=first-secret
          TEST_EXPANDED=parent-$TEST_SECRET-$TEST_OTHER
        ENV

        File.write(second_file, <<~ENV)
          TEST_ROLE=second
          TEST_SHARED=second-only
          TEST_SECRET=second-secret
          TEST_EMPTY=
          TEST_EXPANDED=parent-$TEST_SECRET-$TEST_OTHER
        ENV

        parent = {
          "PATH" => ENV["PATH"],
          "TEST_SECRET" => "parent-secret",
          "TEST_OTHER" => "parent-other",
          "TEST_REMOVED" => "parent-removed"
        }

        script = <<~RUBY
          require "json"
          puts JSON.generate(
            role: ENV["TEST_ROLE"],
            shared: ENV["TEST_SHARED"],
            secret: ENV["TEST_SECRET"],
            other: ENV["TEST_OTHER"],
            removed: ENV["TEST_REMOVED"],
            empty: ENV["TEST_EMPTY"],
            expanded: ENV["TEST_EXPANDED"]
          )
        RUBY

        first_env = Dotenv.spawn_env(
          first_file,
          inherit: %w[PATH],
          overrides: {"TEST_REMOVED" => nil},
          source: parent
        )
        second_env = Dotenv.spawn_env(
          second_file,
          inherit: %w[PATH],
          overrides: {"TEST_OTHER" => nil},
          source: parent
        )

        first_stdout, first_stderr, first_wait = start_child(first_env, script)
        second_stdout, second_stderr, second_wait = start_child(second_env, script)
        first_output = finish_child(first_stdout, first_stderr, first_wait)
        second_output = finish_child(second_stdout, second_stderr, second_wait)

        expect(first_output).to eq(
          "role" => "first",
          "shared" => "first-only",
          "secret" => "first-secret",
          "other" => nil,
          "removed" => nil,
          "empty" => nil,
          "expanded" => "parent-first-secret-"
        )
        expect(second_output).to eq(
          "role" => "second",
          "shared" => "second-only",
          "secret" => "second-secret",
          "other" => nil,
          "removed" => nil,
          "empty" => "",
          "expanded" => "parent-second-secret-"
        )

        expect(JSON.generate(first_env.summary)).not_to include(first_output["secret"])
        expect(JSON.generate(second_env.summary)).not_to include(second_output["secret"])
      end
    end

    def start_child(env, script)
      stdin, stdout, stderr, wait_thread =
        Open3.popen3(env, RbConfig.ruby, "-e", script, unsetenv_others: true)
      stdin.close
      [stdout, stderr, wait_thread]
    end

    def finish_child(stdout, stderr, wait_thread)
      output = stdout.read
      error = stderr.read
      status = wait_thread.value
      expect(error).to be_empty
      expect(status).to be_success
      JSON.parse(output)
    end
  end
end
