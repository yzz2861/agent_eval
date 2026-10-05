# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Language::Linker do
  def link(documents, imports = nil, **options)
    GraphQL::Language::Linker.link(documents, imports, **options).to_query_string
  end

  def assert_executable(document_string, validation_schema: schema)
    query = GraphQL.parse(document_string)
    result = GraphQL::StaticValidation::Validator.new(schema: validation_schema).validate(
      GraphQL::Query.new(validation_schema, document: query)
    )
    errors = result[:errors]
    assert_equal [], errors
  end

  let(:schema_sdl) do
    <<~GQL
      type User { id: ID!, name: String!, email: String!, avatarUrl: String }
      type Query { user(id: ID!): User, version: String }
    GQL
  end

  let(:schema) do
    sdl = <<~GQL
      type User { id: ID!, name: String!, email: String!, avatarUrl: String, x(a: String): String }
      type Query { user(id: ID!): User, me: User, version: String }
    GQL
    GraphQL::Schema.from_definition(sdl)
  end

  it "links an operation to a fragment from another module" do
    documents = {
      "query" => "query GetVersion { version ...UserFields }",
      "fragments" => "fragment UserFields on User { id name }",
    }
    imports = {
      "query" => [{ from: "fragments", name: "UserFields" }],
      "fragments" => [],
    }

    linked = link(documents, imports, operation: "GetVersion")
    expected = <<~GQL.chomp
      query GetVersion {
        version
        ...UserFields
      }

      fragment UserFields on User {
        id
        name
      }
    GQL
    assert_equal expected, linked
  end

  it "auto-selects the only operation when no name is given" do
    documents = {
      "a" => "{ version }",
    }
    linked = link(documents, { "a" => [] })
    assert_includes linked, "query {"
    assert_includes linked, "version"
  end

  it "follows transitive imports through aliases" do
    documents = {
      "query" => "{ me { ...UserCard } }",
      "cards" => "fragment Card on User { ...AvatarFields }",
      "avatars" => "fragment Avatar on User { avatarUrl }",
    }
    imports = {
      "query" => [{ from: "cards", name: "Card", as: "UserCard" }],
      "cards" => [{ from: "avatars", name: "Avatar", as: "AvatarFields" }],
      "avatars" => [],
    }

    linked = link(documents, imports)
    assert_includes linked, "fragment UserCard on User"
    assert_includes linked, "...AvatarFields"
    assert_includes linked, "fragment AvatarFields on User"
    refute_includes linked, "fragment Card on User"
    assert_executable(linked)
  end

  it "keeps same-named fragments in module scope and renames them deterministically on export" do
    documents = {
      "query" => "{ me { ...Fields } }",
      "base" => "fragment Fields on User { name }",
      "detailed" => "fragment Fields on User { email }",
    }
    imports = {
      "query" => [
        { from: "base", name: "Fields", as: "Fields" },
        { from: "detailed", name: "Fields", as: "DetailedFields" },
      ],
      "base" => [],
      "detailed" => [],
    }

    # The operation uses only the base binding, so DetailedFields is not included.
    linked = link(documents, imports)
    assert_includes linked, "fragment Fields on User"
    assert_includes linked, "name"
    refute_includes linked, "email"
    assert_executable(linked)
  end

  it "renames colliding fragments from separate modules and updates every spread" do
    documents = {
      "query" => "{ me { ...Base ...Detailed } }",
      "base" => "fragment Fields on User { name }",
      "detailed" => "fragment Fields on User { email }",
    }
    imports = {
      "query" => [
        { from: "base", name: "Fields", as: "Base" },
        { from: "detailed", name: "Fields", as: "Detailed" },
      ],
      "base" => [],
      "detailed" => [],
    }

    linked = link(documents, imports)
    assert_includes linked, "fragment Base on User"
    assert_includes linked, "fragment Detailed on User"
    assert_equal 1, linked.scan("...Base").length
    assert_equal 1, linked.scan("...Detailed").length
    assert_executable(linked)
  end

  it "deduplicates one fragment imported under multiple aliases and renames spreads consistently" do
    documents = {
      "query" => "{ me { ...A ...B } }",
      "shared" => "fragment Fields on User { id }",
    }
    imports = {
      "query" => [
        { from: "shared", name: "Fields", as: "A" },
        { from: "shared", name: "Fields", as: "B" },
      ],
      "shared" => [],
    }

    linked = link(documents, imports)
    assert_equal 1, linked.scan(/^fragment /).length
    assert_equal 2, linked.scan("...A").length
    refute_includes linked, "...B"
    assert_executable(linked)
  end

  it "only includes fragments reachable from the selected operation" do
    documents = {
      "query" => "query Q { me { ...Used } }",
      "fragments" => "fragment Used on User { name } fragment Unused on User { email } fragment UsedDep on User { id }",
    }
    imports = {
      "query" => [{ from: "fragments", name: "Used" }],
      "fragments" => [],
    }

    linked = link(documents, imports, operation: "Q")
    assert_includes linked, "fragment Used on User"
    refute_includes linked, "fragment Unused"
    refute_includes linked, "fragment UsedDep"
  end

  it "includes transitive fragment dependencies" do
    documents = {
      "query" => "{ me { ...Fields } }",
      "fragments" => "fragment Fields on User { name ...Avatar } fragment Avatar on User { avatarUrl }",
    }
    imports = {
      "query" => [{ from: "fragments", name: "Fields" }],
      "fragments" => [],
    }

    linked = link(documents, imports)
    assert_includes linked, "fragment Fields on User"
    assert_includes linked, "fragment Avatar on User"
    assert_executable(linked)
  end

  it "accepts an array of modules" do
    modules = [
      { name: "query", document: "{ me { ...F } }", imports: [{ from: "frags", name: "F" }] },
      { name: "frags", document: "fragment F on User { id }", imports: [] },
    ]
    linked = GraphQL::Language::Linker.link(modules).to_query_string
    assert_includes linked, "fragment F on User"
    assert_executable(linked)
  end

  it "renames same-named fragments deterministically when their original names collide in output" do
    documents = {
      "query" => "{ me { ...One ...Two } }",
      "a" => "fragment Fields on User { name }",
      "b" => "fragment Fields on User { email }",
    }
    imports = {
      "query" => [
        { from: "a", name: "Fields", as: "One" },
        { from: "b", name: "Fields", as: "Two" },
      ],
      "a" => [],
      "b" => [],
    }

    linked = link(documents, imports)
    assert_includes linked, "fragment One on User"
    assert_includes linked, "fragment Two on User"
    # Running twice produces the same, deterministic result.
    assert_equal linked, link(documents, imports)
    assert_executable(linked)
  end

  it "keeps renamed fragments consistent through a transitive chain" do
    documents = {
      "query" => "{ me { ...Shared } }",
      "middle" => "fragment MiddleMarker on User { id }",
      "base" => "fragment Shared on User { id ...Leaf } fragment Leaf on User { name }",
    }
    imports = {
      "query" => [{ from: "middle", name: "Shared", as: "Shared" }, { from: "middle", name: "Leaf", as: "Leaf" }],
      "middle" => [
        { from: "base", name: "Shared" },
        { from: "base", name: "Leaf" },
      ],
      "base" => [],
    }

    linked = link(documents, imports)
    assert_includes linked, "fragment Shared on User"
    assert_includes linked, "...Leaf"
    refute_includes linked, "Shared__"
    assert_executable(linked)
  end

  it "accepts variables declared by the operation when used deep inside a fragment" do
    documents = {
      "query" => "query Q($id: ID!, $note: String) { user(id: $id) { ...Outer } }",
      "frags" => "fragment Outer on User { name ...Inner } fragment Inner on User { ... on User { x(a: $note) } }",
    }
    imports = { "query" => [{ from: "frags", name: "Outer" }], "frags" => [] }
    linked = link(documents, imports, operation: "Q")
    assert_includes linked, "$id"
    assert_executable(linked)
  end

  describe "errors" do
    def assert_link_error(klass, documents, imports, **options)
      err = assert_raises(klass) do
        GraphQL::Language::Linker.link(documents, imports, **options)
      end
      err
    end

    it "raises when an import names an unknown module" do
      documents = { "query" => "{ ...F }" }
      imports = { "query" => [{ from: "nope", name: "F" }] }
      err = assert_link_error(GraphQL::Language::Linker::MissingModuleError, documents, imports)
      assert_includes err.message, "unknown module `nope`"
    end

    it "raises when an imported symbol isn't exported by the source module" do
      documents = { "query" => "{ ...F }", "frags" => "fragment G on User { id }" }
      imports = { "query" => [{ from: "frags", name: "F" }], "frags" => [] }
      err = assert_link_error(GraphQL::Language::Linker::MissingSymbolError, documents, imports)
      assert_includes err.message, "no such fragment"
    end

    it "raises when imports form a cycle" do
      documents = {
        "query" => "{ ...F }",
        "a" => "fragment F on User { ...G }",
        "b" => "fragment G on User { id }",
      }
      imports = {
        "query" => [{ from: "a", name: "F" }],
        "a" => [{ from: "b", name: "G" }],
        "b" => [{ from: "a", name: "F" }],
      }
      err = assert_link_error(GraphQL::Language::Linker::CircularImportError, documents, imports)
      assert_includes err.message, "Import cycle"
    end

    it "raises when an alias collides with a local fragment" do
      documents = { "query" => "{ ...F } fragment F on User { id }", "frags" => "fragment G on User { id }" }
      imports = { "query" => [{ from: "frags", name: "G", as: "F" }], "frags" => [] }
      err = assert_link_error(GraphQL::Language::Linker::DuplicateBindingError, documents, imports)
      assert_includes err.message, "collides with a local fragment"
    end

    it "raises when two distinct fragments bind to the same local name" do
      documents = {
        "query" => "{ ...F }",
        "a" => "fragment One on User { id }",
        "b" => "fragment Two on User { id }",
      }
      imports = {
        "query" => [
          { from: "a", name: "One", as: "F" },
          { from: "b", name: "Two", as: "F" },
        ],
        "a" => [],
        "b" => [],
      }
      assert_link_error(GraphQL::Language::Linker::DuplicateBindingError, documents, imports)
    end

    it "raises when a spread can't resolve in module scope" do
      documents = { "query" => "{ ...Missing }" }
      err = assert_link_error(GraphQL::Language::Linker::MissingFragmentError, documents, { "query" => [] })
      assert_includes err.message, "Missing"
    end

    it "raises when reachable fragments form a cycle" do
      documents = {
        "query" => "{ ...A }",
        "frags" => "fragment A on User { ...B } fragment B on User { ...A }",
      }
      imports = { "query" => [{ from: "frags", name: "A" }], "frags" => [] }
      assert_link_error(GraphQL::Language::Linker::CircularFragmentError, documents, imports)
    end

    it "raises when a fragment is defined twice in one module" do
      documents = { "frags" => "fragment F on User { id } fragment F on User { name }" }
      assert_link_error(GraphQL::Language::Linker::DuplicateFragmentError, documents, { "frags" => [] })
    end

    it "raises when the selected operation doesn't exist" do
      documents = { "query" => "{ version }" }
      err = assert_link_error(
        GraphQL::Language::Linker::OperationNotFoundError,
        documents, { "query" => [] }, operation: "Nope"
      )
      assert_includes err.message, "Nope"
    end

    it "raises when the entry module doesn't exist" do
      documents = { "query" => "{ version }" }
      assert_link_error(
        GraphQL::Language::Linker::MissingModuleError,
        documents, { "query" => [] }, root: "elsewhere"
      )
    end

    it "raises when a variable used by the operation isn't declared" do
      documents = { "query" => "{ user(id: $id) { name } }" }
      err = assert_link_error(GraphQL::Language::Linker::UndeclaredVariableError, documents, { "query" => [] })
      assert_includes err.message, "$id"
    end

    it "raises when a variable used by a reachable fragment isn't declared" do
      documents = {
        "query" => "query Q { ...F }",
        "frags" => "fragment F on User { name ... on User { x(a: $n) } }",
      }
      imports = { "query" => [{ from: "frags", name: "F" }], "frags" => [] }
      err = assert_link_error(GraphQL::Language::Linker::UndeclaredVariableError, documents, imports, operation: "Q")
      assert_includes err.message, "$n"
    end

    it "accepts variables declared by the operation when used in fragments" do
      documents = {
        "query" => "query Q($id: ID!) { user(id: $id) { ...F } }",
        "frags" => "fragment F on User { name }",
      }
      imports = { "query" => [{ from: "frags", name: "F" }], "frags" => [] }
      linked = link(documents, imports, operation: "Q")
      assert_executable(linked)
    end

    it "subclasses GraphQL::Language::Linker::Error" do
      error_classes = GraphQL::Language::Linker.constants
        .map { |name| GraphQL::Language::Linker.const_get(name) }
        .select { |constant| constant.is_a?(Class) && constant < GraphQL::Language::Linker::Error && constant != GraphQL::Language::Linker::Error }
      refute_empty error_classes
      error_classes
        .each do |error_class|
        assert_operator error_class, :<, GraphQL::Language::Linker::Error
      end
    end
  end
end
