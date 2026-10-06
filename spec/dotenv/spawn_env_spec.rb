require "spec_helper"
require "rbconfig"
require "tempfile"

describe Dotenv::SpawnEnv do
  def env_file(contents)
    file = Tempfile.new("dotenv")
    file.write(contents)
    file.close
    file.path
  end

  # Spawn a short-lived child process that echoes the given variables,
  # one per line, using inspect so unset (nil) and empty ("") differ.
  def echo_vars(env, *keys)
    code = keys.map { |key| "puts ENV[#{key.inspect}].inspect" }.join("; ")
    IO.popen([env, RbConfig.ruby, "-e", code], &:read).split("\n")
  end

  describe "building the environment" do
    it "does not modify the parent ENV" do
      file = env_file("SPAWN_TEST_LEAK=from_file\n")
      expect { Dotenv.spawn_env(file, inherit: false) }
        .not_to change { ENV.key?("SPAWN_TEST_LEAK") }
    end

    it "inherits only the selected parent variables" do
      ENV["SPAWN_TEST_IN"] = "yes"
      ENV["SPAWN_TEST_OUT"] = "no"
      env = Dotenv.spawn_env(inherit: %w[SPAWN_TEST_IN])
      expect(env["SPAWN_TEST_IN"]).to eq("yes")
      expect(env).not_to have_key("SPAWN_TEST_OUT")
    end

    it "inherits all variables with inherit: true and none with inherit: false" do
      expect(Dotenv.spawn_env(inherit: true)).to include(ENV.to_h)
      expect(Dotenv.spawn_env(inherit: false)).to be_empty
    end

    it "inherits variables matching a Regexp" do
      ENV["SPAWN_TEST_RE_A"] = "1"
      ENV["SPAWN_TEST_RE_B"] = "2"
      env = Dotenv.spawn_env(inherit: /\ASPAWN_TEST_RE_/)
      expect(env).to eq("SPAWN_TEST_RE_A" => "1", "SPAWN_TEST_RE_B" => "2")
    end

    it "layers files and explicit overrides over inherited variables" do
      ENV["SPAWN_TEST_LAYER"] = "parent"
      file = env_file("SPAWN_TEST_LAYER=file\nSPAWN_TEST_FILE=1\n")
      env = Dotenv.spawn_env(file,
        inherit: %w[SPAWN_TEST_LAYER],
        override: { "SPAWN_TEST_LAYER" => "override" })
      expect(env["SPAWN_TEST_LAYER"]).to eq("override")
      expect(env["SPAWN_TEST_FILE"]).to eq("1")
    end

    it "distinguishes empty string, unset, and deleted" do
      ENV["SPAWN_TEST_DELETE"] = "parent"
      file = env_file("SPAWN_TEST_EMPTY=\n")
      env = Dotenv.spawn_env(file,
        inherit: %w[SPAWN_TEST_DELETE],
        override: { "SPAWN_TEST_DELETE" => nil })
      expect(env["SPAWN_TEST_EMPTY"]).to eq("")
      expect(env).not_to have_key("SPAWN_TEST_UNSET")
      expect(env).to have_key("SPAWN_TEST_DELETE")
      expect(env["SPAWN_TEST_DELETE"]).to be_nil
    end

    it "raises for missing files unless ignore: true" do
      expect { Dotenv.spawn_env(".does_not_exist") }.to raise_error(Errno::ENOENT)
      expect(Dotenv.spawn_env(".does_not_exist", ignore: true, inherit: false)).to eq({})
    end
  end

  describe "variable expansion" do
    it "expands variables from the view, never from the host ENV" do
      ENV["SPAWN_TEST_HOST"] = "host"
      file = env_file(
        "SPAWN_TEST_BASE=view\n" +        "SPAWN_TEST_FROM_VIEW=${SPAWN_TEST_BASE}\n" +        "SPAWN_TEST_FROM_HOST=${SPAWN_TEST_HOST}\n"
      )
      env = Dotenv.spawn_env(file, inherit: false)
      expect(env["SPAWN_TEST_FROM_VIEW"]).to eq("view")
      expect(env["SPAWN_TEST_FROM_HOST"]).to eq("")
    end

    it "expands variables from inherited variables" do
      ENV["SPAWN_TEST_INHERITED"] = "inherited"
      file = env_file("SPAWN_TEST_USE=${SPAWN_TEST_INHERITED}\n")
      env = Dotenv.spawn_env(file, inherit: %w[SPAWN_TEST_INHERITED])
      expect(env["SPAWN_TEST_USE"]).to eq("inherited")
    end
  end

  describe "case sensitivity" do
    it "treats keys differing only in case as distinct by default" do
      env = Dotenv.spawn_env(override: { "spawn_test_case" => "a", "SPAWN_TEST_CASE" => "b" })
      expect(env.values_at("spawn_test_case", "SPAWN_TEST_CASE")).to eq(%w[a b])
    end

    it "resolves case conflicts with case_sensitive: false" do
      ENV["SPAWN_TEST_CASE"] = "parent"
      env = Dotenv.spawn_env(
        inherit: %w[SPAWN_TEST_CASE],
        override: { "spawn_test_case" => "override" },
        case_sensitive: false
      )
      expect(env).to eq("spawn_test_case" => "override")
    end

    it "deletes case-insensitively with case_sensitive: false" do
      ENV["SPAWN_TEST_CASE"] = "parent"
      env = Dotenv.spawn_env(
        inherit: %w[SPAWN_TEST_CASE],
        override: { "Spawn_Test_Case" => nil },
        case_sensitive: false
      )
      expect(env).to eq("SPAWN_TEST_CASE" => nil)
    end
  end

  describe "#summary" do
    it "lists added, changed, and removed keys without values" do
      ENV["SPAWN_TEST_CHANGED"] = "parent"
      ENV["SPAWN_TEST_REMOVED"] = "secret"
      file = env_file("SPAWN_TEST_CHANGED=file\nSPAWN_TEST_ADDED=secret\n")
      env = Dotenv.spawn_env(file,
        inherit: %w[SPAWN_TEST_CHANGED SPAWN_TEST_REMOVED],
        override: { "SPAWN_TEST_REMOVED" => nil })
      expect(env.summary).to eq(
        "added" => %w[SPAWN_TEST_ADDED],
        "changed" => %w[SPAWN_TEST_CHANGED],
        "removed" => %w[SPAWN_TEST_REMOVED]
      )
      expect(env.summary.inspect).not_to include("secret")
    end
  end

  describe "spawning children" do
    it "isolates two child processes and applies deletion" do
      ENV["SPAWN_TEST_PARENT"] = "parent"
      file_a = env_file("SPAWN_TEST_SHARED=A\nSPAWN_TEST_EMPTY=\n")
      file_b = env_file("SPAWN_TEST_SHARED=B\n")

      env_a = Dotenv.spawn_env(file_a,
        inherit: %w[PATH],
        override: { "SPAWN_TEST_PARENT" => nil })
      env_b = Dotenv.spawn_env(file_b, inherit: %w[PATH])

      keys = %w[SPAWN_TEST_SHARED SPAWN_TEST_PARENT SPAWN_TEST_EMPTY]
      expect(echo_vars(env_a, *keys)).to eq(%w["A" nil ""])
      expect(echo_vars(env_b, *keys)).to eq(%w["B" "parent" nil])

      # the parent ENV is untouched
      expect(ENV["SPAWN_TEST_PARENT"]).to eq("parent")
      expect(ENV).not_to have_key("SPAWN_TEST_SHARED")
    end
  end
end
