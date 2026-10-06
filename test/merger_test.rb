require_relative "helper"

class MergerTest < Minitest::Test
  def test_merges_array_table_members_by_declared_identity
    base = TomlRB.parse(<<-TOML.gsub(/^ {6}/, ""))
      title = "app"

      [[services]]
      name = "database"
      port = 5432

      [[services]]
      name = "cache"
      port = 6379

      [[services]]
      name = "queue"
      port = 5672
    TOML

    environment = TomlRB.parse(<<-TOML.gsub(/^ {6}/, ""))
      title = "production"

      [[services]]
      name = "database"
      host = "db.example.com"

      [[services]]
      name = "worker"
      port = 9000
    TOML

    local = deep_copy(environment)
    local["services"] << TomlRB.delete("cache")
    local["services"] << {
      "name" => "debug",
      "port" => 9100,
      "tags" => [{"name" => "dev"}, "local"]
    }

    merged = TomlRB.merge(
      base,
      environment,
      local,
      table_arrays: {"services" => "name"}
    )

    assert_equal ["database", "queue", "worker", "debug"],
      merged["services"].map { |service| service["name"] }
    assert_equal(
      {
        "name" => "database",
        "port" => 5432,
        "host" => "db.example.com"
      },
      merged["services"].first
    )
    assert_equal "production", merged["title"]
    assert_equal [{"name" => "dev"}, "local"], merged["services"].last["tags"]

    dumped = TomlRB.dump(merged)
    assert_equal merged, TomlRB.parse(dumped)
    assert_order(dumped, %w[database queue worker debug])

    assert_equal "app", base["title"]
    assert_equal ["database", "cache", "queue"], base["services"].map { |service| service["name"] }
    assert_equal ["database", "worker"], environment["services"].map { |service| service["name"] }
    local_names = local["services"].map { |service|
      service.is_a?(TomlRB::Deletion) ? "cache" : service["name"]
    }
    assert_equal ["database", "worker", "cache", "debug"], local_names
    refute_equal "production", base["title"]
  end

  def test_merges_nested_array_tables_with_array_path_rules
    base = {
      "config" => {
        "services" => [
          {"name" => "db", "ports" => [{"protocol" => "tcp", "number" => 5432}]}
        ]
      }
    }
    override = {
      "config" => {
        "services" => [
          {"name" => "db", "ports" => [{"protocol" => "tcp", "public" => true}]}
        ]
      }
    }

    merged = TomlRB.merge(
      base,
      override,
      table_arrays: {
        %w[config services] => "name",
        %w[config services ports] => "protocol"
      }
    )

    assert_equal(
      {
        "config" => {
          "services" => [
            {
              "name" => "db",
              "ports" => [{"protocol" => "tcp", "number" => 5432, "public" => true}]
            }
          ]
        }
      },
      merged
    )
  end

  def test_accepts_symbolized_identity_fields
    merged = TomlRB.merge(
      {services: [{name: :db, port: 1}]},
      {services: [{name: :db, host: "localhost"}]},
      table_arrays: {services: :name}
    )

    assert_equal [{name: :db, port: 1, host: "localhost"}], merged[:services]
  end

  def test_rejects_invalid_merge_rules
    assert_raises(ArgumentError) { TomlRB.merge({}, {}, array_tables: nil) }
    assert_raises(ArgumentError) { TomlRB.merge({}, {}, array_tables: {"services" => ""}) }
    assert_raises(ArgumentError) { TomlRB.merge({}, {}, array_tables: {"services" => 1}) }
    assert_raises(ArgumentError) do
      TomlRB.merge({}, {}, array_tables: {"services" => "name", [:services] => "id"})
    end
  end

  def test_rejects_non_hash_layers
    assert_raises(ArgumentError) { TomlRB.layered_merge([], {}) }
  end

  def test_layered_merge_and_legacy_rule_keyword_alias_work
    base = {"services" => [{"name" => "db"}]}
    override = {"services" => [{"name" => "db", "port" => 5432}]}

    expected = [{"name" => "db", "port" => 5432}]

    layered = TomlRB.layered_merge(base, override, table_arrays: {"services" => "name"})
    aliased = TomlRB.merge(base, override, array_tables: {"services" => "name"})

    assert_equal expected, layered["services"]
    assert_equal expected, aliased["services"]
  end

  def test_regular_arrays_are_replaced
    base = {"values" => [1, 2, 3], "tables" => [{"id" => 1}]}
    override = {"values" => [9], "tables" => [{"id" => 2}]}

    merged = TomlRB.merge(base, override, array_tables: {})

    assert_equal [9], merged["values"]
    assert_equal [{"id" => 2}], merged["tables"]
  end

  def test_delete_removes_tables_and_scalars
    base = {"keep" => 1, "remove" => 2, "nested" => {"keep" => 3, "remove" => 4}}
    override = {"remove" => TomlRB::DELETE, "nested" => {"remove" => TomlRB::DELETE}}

    merged = TomlRB.merge(base, override)

    refute_includes merged, "remove"
    assert_equal({"keep" => 1, "nested" => {"keep" => 3}}, merged)
    refute_includes merged["nested"], "remove"
  end

  def test_member_readded_in_a_later_layer_is_appended
    base = {
      "services" => [
        {"name" => "database", "port" => 5432},
        {"name" => "cache", "port" => 6379}
      ]
    }
    environment = {"services" => [TomlRB.delete_member("database")]}
    local = {"services" => [{"name" => "database", "port" => 5433}]}

    merged = TomlRB.merge(
      base,
      environment,
      local,
      array_tables: {"services" => "name"}
    )

    assert_equal ["cache", "database"], merged["services"].map { |service| service["name"] }
    assert_equal 5433, merged["services"].last["port"]
  end

  def test_reports_missing_identity
    base = {"services" => [{"port" => 1}]}

    error = assert_raises(TomlRB::MergeConflict) do
      TomlRB.merge(base, {}, array_tables: {"services" => "name"})
    end

    assert_match(/missing identity/, error.message)
  end

  def test_reports_duplicate_identity
    base = {"services" => [{"name" => "db", "port" => 1}, {"name" => "db", "port" => 2}]}

    error = assert_raises(TomlRB::MergeConflict) do
      TomlRB.merge(base, {}, array_tables: {"services" => "name"})
    end

    assert_match(/duplicate identity/, error.message)
  end

  def test_reports_table_and_scalar_swaps
    error = assert_raises(TomlRB::MergeConflict) do
      TomlRB.merge({"service" => {"port" => 1}}, {"service" => 2})
    end
    assert_match(/conflicting value types/, error.message)

    error = assert_raises(TomlRB::MergeConflict) do
      TomlRB.merge({"service" => 1}, {"service" => {"port" => 2}})
    end
    assert_match(/conflicting value types/, error.message)
  end

  def test_reports_conflict_between_declared_array_table_and_other_types
    error = assert_raises(TomlRB::MergeConflict) do
      TomlRB.merge(
        {"services" => [{"name" => "db"}]},
        {"services" => "disabled"},
        array_tables: {"services" => "name"}
      )
    end
    assert_match(/conflicting value types/, error.message)

    error = assert_raises(TomlRB::MergeConflict) do
      TomlRB.merge(
        {"services" => "disabled"},
        {"services" => [{"name" => "db"}]},
        array_tables: {"services" => "name"}
      )
    end
    assert_match(/conflicting value types/, error.message)
  end

  def test_reports_member_deletion_in_regular_array
    base = {"values" => [{"name" => "db"}]}
    override = {"values" => [TomlRB.delete("db")]}

    error = assert_raises(TomlRB::MergeConflict) do
      TomlRB.merge(base, override)
    end

    assert_match(/declared array table/, error.message)
  end

  private

  def deep_copy(value)
    case value
    when Hash
      value.each_with_object({}) { |(key, child), copy| copy[key] = deep_copy(child) }
    when Array
      value.map { |child| deep_copy(child) }
    else
      value
    end
  end

  def assert_order(text, names)
    blocks = text.split("[[services]]")[1..-1]
    positions = names.map do |name|
      blocks.index { |block| block.include?("name = \"#{name}\"") }
    end

    refute_includes positions, nil
    assert_equal positions, positions.sort
  end
end
