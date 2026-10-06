require_relative "helper"

class MergerTest < Minitest::Test
  BASE_CONFIG = <<~TOML
    environment = "production"
    ports = [80, 443]

    [settings]
    retry = 3
    timeout = 30

    [[services]]
    name = "api"
    port = 8000

    [[services]]
    name = "web"
    port = 8080
  TOML

  ENVIRONMENT_CONFIG = <<~TOML
    environment = "staging"
    ports = [8080]

    [[services]]
    name = "api"
    port = 9000

    [[services]]
    name = "worker"
    port = 9100
  TOML

  def test_three_layer_array_tables_merge_override_add_and_delete_in_order
    base = TomlRB.parse(BASE_CONFIG)
    environment_config = TomlRB.parse(ENVIRONMENT_CONFIG)
    local_config = {
      "settings" => {"timeout" => TomlRB::DELETE, "debug" => true},
      "services" => [
        TomlRB.delete_member("name", "web"),
        {"name" => "api", "host" => "127.0.0.1", "tls" => {"enabled" => true}},
        {"name" => "admin", "port" => 7000}
      ]
    }

    merged = TomlRB.merge_configs(
      base,
      environment_config,
      local_config,
      array_tables: {"services" => "name"}
    )

    expected = {
      "environment" => "staging",
      "ports" => [8080],
      "settings" => {"retry" => 3, "debug" => true},
      "services" => [
        {"name" => "api", "port" => 9000, "host" => "127.0.0.1",
         "tls" => {"enabled" => true}},
        {"name" => "worker", "port" => 9100},
        {"name" => "admin", "port" => 7000}
      ]
    }
    assert_equal expected, merged
    assert_equal %w[api worker admin], merged["services"].map { |service| service["name"] }

    dumped = TomlRB.dump(merged)
    expected_toml = <<~TOML
      environment = "staging"
      ports = [8080]
      [settings]
      debug = true
      retry = 3
      [[services]]
      host = "127.0.0.1"
      name = "api"
      port = 9000
      [services.tls]
      enabled = true
      [[services]]
      name = "worker"
      port = 9100
      [[services]]
      name = "admin"
      port = 7000
    TOML
    assert_equal expected_toml, dumped
    assert_equal expected, TomlRB.parse(dumped)
  end

  def test_merge_does_not_modify_input_layers
    original_base = TomlRB.parse(BASE_CONFIG)
    original_environment = TomlRB.parse(ENVIRONMENT_CONFIG)
    base = TomlRB.parse(BASE_CONFIG)
    environment_config = TomlRB.parse(ENVIRONMENT_CONFIG)
    local_config = {
      "settings" => {"timeout" => TomlRB::DELETE},
      "services" => [TomlRB.delete_member("name", "web")]
    }

    merged = TomlRB.merge_configs(
      base,
      environment_config,
      local_config,
      array_tables: {"services" => "name"}
    )
    merged["settings"]["retry"] = 99
    merged["services"][0]["port"] = 1

    assert_equal original_base, base
    assert_equal original_environment, environment_config
    assert_equal [TomlRB.delete_member("name", "web")], local_config["services"]
    assert_equal TomlRB::DELETE, local_config["settings"]["timeout"]
  end

  def test_explicit_delete_removes_scalars_and_nested_keys
    base = {"retry" => 3, "settings" => {"timeout" => 30, "debug" => false}}
    override = {"retry" => TomlRB::DELETE, "settings" => {"timeout" => TomlRB::DELETE}}

    merged = TomlRB.merge_configs(base, override)

    assert_equal({"settings" => {"debug" => false}}, merged)
    assert_equal({"retry" => 3, "settings" => {"timeout" => 30, "debug" => false}}, base)
  end

  def test_ordinary_arrays_are_replaced_entirely
    base = {"ports" => [80, 443], "mixed" => [{"port" => 80}, 1]}
    override = {"ports" => [8080], "mixed" => [{"port" => 8080}]}

    merged = TomlRB.merge_configs(base, override)

    assert_equal({"ports" => [8080], "mixed" => [{"port" => 8080}]}, merged)
  end

  def test_nested_array_table_rules_support_symbol_keys
    base = {config: {services: [{name: :api, port: 80}, {name: :web, port: 81}]}}
    override = {
      config: {
        services: [
          {name: :api, port: 90},
          TomlRB.delete_member(:name, :web)
        ]
      }
    }

    merged = TomlRB.merge_configs(base, override, array_tables: {[:config, :services] => :name})

    assert_equal({config: {services: [{name: :api, port: 90}]}}, merged)
  end

  def test_merge_configs_is_an_alias_for_merge
    base = {"services" => [{"name" => "api", "port" => 80}]}
    override = {"services" => [{"name" => "api", "port" => 81}]}

    merged = TomlRB.merge_configs(base, override, array_tables: {"services" => "name"})

    assert_equal({"services" => [{"name" => "api", "port" => 81}]}, merged)
  end

  def test_array_table_rules_cannot_be_declared_twice
    error = assert_raises(ArgumentError) do
      TomlRB.merge({}, {}, array_tables: {"services" => "name", :services => :id})
    end
    assert_equal "duplicate array table rule: services", error.message
  end

  def test_missing_member_identity_is_a_conflict
    base = {"services" => [{"port" => 80}]}

    error = assert_raises(TomlRB::MergeConflictError) do
      TomlRB.merge_configs(base, array_tables: {"services" => "name"})
    end
    assert_match(/\Aservices:.*missing identity field "name"/, error.message)
  end

  def test_duplicate_member_identities_are_conflicts
    [{"services" => [{"name" => "api"}, {"name" => "api"}]}].each do |layer|
      error = assert_raises(TomlRB::MergeConflictError) do
        TomlRB.merge_configs(layer, array_tables: {"services" => "name"})
      end
      assert_match(/\Aservices:.*duplicate identity "api"/, error.message)
    end

    base = {"services" => [{"name" => "api"}]}
    override = {
      "services" => [
        {"name" => "api"},
        {"name" => "api"}
      ]
    }
    error = assert_raises(TomlRB::MergeConflictError) do
      TomlRB.merge_configs(base, override, array_tables: {"services" => "name"})
    end
    assert_match(/duplicate identity "api"/, error.message)
  end

  def test_table_and_scalar_or_array_swaps_are_conflicts
    assert_conflict({"a" => 1}, {"a" => {"b" => 1}}, /\Aa: cannot replace Integer with table/)
    assert_conflict({"a" => {"b" => 1}}, {"a" => 1}, /\Aa: cannot replace table with Integer/)
  end

  def test_undeclared_arrays_replace_tables_and_vice_versa
    merged = TomlRB.merge_configs({"a" => {"b" => 1}}, {"a" => [1]})
    assert_equal({"a" => [1]}, merged)

    merged = TomlRB.merge_configs({"a" => [{"b" => 1}]}, {"a" => {"b" => 2}})
    assert_equal({"a" => {"b" => 2}}, merged)
  end

  def test_declared_array_table_cannot_swap_with_other_types
    assert_conflict(
      {"services" => {}},
      {"services" => [{"name" => "api"}]},
      /cannot replace table with array table/,
      "services" => "name"
    )
    assert_conflict(
      {"services" => [{"name" => "api"}]},
      {"services" => 1},
      /cannot replace array table with Integer/,
      "services" => "name"
    )
    assert_conflict(
      {"services" => [{"name" => "api"}]},
      {"services" => {"name" => "api"}},
      /cannot replace array table with table/,
      "services" => "name"
    )
  end

  def test_deletion_marker_is_not_valid_in_ordinary_arrays
    assert_conflict({"ports" => [1]}, {"ports" => [TomlRB::DELETE]}, /not valid in an ordinary array/)
    assert_conflict(
      {"settings" => [{"timeout" => 1}]},
      {"settings" => [{"timeout" => TomlRB::DELETE}]},
      /not valid inside an ordinary array/
    )
  end

  def test_member_deletion_must_use_configured_identity
    base = {"services" => [{"name" => "api", "id" => 1}]}
    override = {"services" => [TomlRB.delete_member("id", 1)]}

    error = assert_raises(TomlRB::MergeConflictError) do
      TomlRB.merge_configs(base, override, array_tables: {"services" => "name"})
    end
    assert_match(/deletion uses "id".*rule uses "name"/, error.message)
  end

  private

  def assert_conflict(base, override, pattern, array_tables = {})
    error = assert_raises(TomlRB::MergeConflictError) do
      TomlRB.merge_configs(base, override, array_tables: array_tables)
    end
    assert_match(pattern, error.message)
  end
end
