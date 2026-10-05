# frozen_string_literal: true
require "spec_helper"

describe GraphQL::Language::DocumentLinker do
  def link(modules, imports, operation_name = nil, from: nil)
    GraphQL::Language::DocumentLinker.new(modules: modules, imports: imports).link(operation_name, from: from)
  end

  describe "linking a single module" do
    it "returns the operation with its own fragments, keeping their names" do
      result = link({
        "posts" => <<~GRAPHQL,
          query GetPost {
            post {
              title
              ...PostFields
            }
          }

          fragment PostFields on Post {
            title
            likes
          }
        GRAPHQL
      }, {}, "GetPost", from: "posts")

      assert_includes result, "query GetPost {"
      assert_includes result, "fragment PostFields on Post {"
      assert_includes result, "...PostFields"
    end

    it "only includes fragments that are reachable from the operation" do
      result = link({
        "posts" => <<~GRAPHQL,
          query GetPost {
            post {
              ...Used
            }
          }

          fragment Used on Post {
            title
          }

          fragment Unused on Post {
            secret
          }
        GRAPHQL
      }, {}, "GetPost", from: "posts")

      assert_includes result, "fragment Used on Post {"
      refute_includes result, "Unused"
    end

    it "links an anonymous operation when it is the only one" do
      result = link({
        "posts" => "{ version }",
      }, {})

      assert_equal "query {\n  version\n}", result
    end
  end

  describe "linking across modules" do
    let(:modules) do
      {
        "users" => <<~GRAPHQL,
          fragment UserFields on User {
            id
            name
          }
        GRAPHQL
        "posts" => <<~GRAPHQL,
          query GetPost($id: ID!) {
            post(id: $id) {
              title
              author {
                ...UserFields
              }
            }
          }
        GRAPHQL
      }
    end

    let(:imports) do
      { "posts" => [{ from: "users", symbols: ["UserFields"] }] }
    end

    it "renames imported fragments with a stable prefix and updates references" do
      result = link(modules, imports, "GetPost", from: "posts")

      assert_includes result, "fragment Users_UserFields on User {"
      assert_includes result, "...Users_UserFields"
      refute_includes result, "...UserFields"
    end

    it "produces identical output for identical input" do
      assert_equal link(modules, imports, "GetPost", from: "posts"), link(modules, imports, "GetPost", from: "posts")
    end

    it "also accepts the flat hash form for the import manifest" do
      result = link(modules, { "posts" => { "UserFields" => "users" } }, "GetPost", from: "posts")
      assert_includes result, "fragment Users_UserFields on User {"
    end

    it "finds the operation without from: when its name is unique" do
      result = link(modules, imports, "GetPost")
      assert_includes result, "query GetPost($id: ID!) {"
    end
  end

  describe "transitive imports" do
    it "follows imports through intermediate modules and prefixes each hop" do
      result = link({
        "core" => "fragment NodeFields on Node { id }",
        "users" => <<~GRAPHQL,
          fragment UserFields on User {
            name
            ...NodeFields
          }
        GRAPHQL
        "posts" => <<~GRAPHQL,
          query GetPost {
            post {
              author {
                ...UserFields
              }
            }
          }
        GRAPHQL
      }, {
        "posts" => [{ from: "users", symbols: ["UserFields"] }],
        "users" => [{ from: "core", symbols: ["NodeFields"] }],
      }, "GetPost", from: "posts")

      assert_includes result, "fragment Users_UserFields on User {"
      assert_includes result, "fragment Core_NodeFields on Node {"
      assert_includes result, "...Core_NodeFields"
    end
  end

  describe "same-named fragments in different modules" do
    it "keeps both, without silent overrides" do
      result = link({
        "users" => "fragment Fields on User { name }",
        "profiles" => <<~GRAPHQL,
          query GetProfile {
            viewer {
              ...Fields
              ...AdminFields
            }
          }

          fragment AdminFields on User {
            ...Fields
          }
        GRAPHQL
      }, {
        "profiles" => [{ from: "users", symbols: ["Fields"] }],
      }, "GetProfile", from: "profiles")

      assert_includes result, "fragment Users_Fields on User {"
      assert_includes result, "...Users_Fields"
      assert_includes result, "fragment AdminFields on User {"
      refute_includes result, "fragment Fields on User {"
    end
  end

  describe "same-named fragments, both imported" do
    it "gives each a distinct exported name" do
      result = link({
        "users" => "fragment Fields on User { name }",
        "admin" => "fragment Fields on User { role }",
        "profiles" => <<~GRAPHQL,
          query GetProfile {
            viewer {
              ...Fields
            }
          }

          fragment LocalFields on User {
            ...Fields
          }
        GRAPHQL
        "reports" => <<~GRAPHQL,
          query GetReport {
            viewer {
              ...Fields
            }
          }
        GRAPHQL
      }, {
        "profiles" => [{ from: "users", symbols: ["Fields"] }],
        "reports" => [{ from: "admin", symbols: ["Fields"] }],
      }, "GetReport", from: "reports")

      assert_includes result, "fragment Admin_Fields on User {"
      assert_includes result, "...Admin_Fields"
      refute_includes result, "Users_Fields"
    end
  end

  describe "import cycles" do
    it "raises ImportCycleError" do
      err = assert_raises(GraphQL::Language::DocumentLinker::ImportCycleError) do
        link({
          "a" => "query GetA { ...BFields } fragment AFields on Query { id }",
          "b" => "fragment BFields on Query { ...AFields }",
        }, {
          "a" => [{ from: "b", symbols: ["BFields"] }],
          "b" => [{ from: "a", symbols: ["AFields"] }],
        }, "GetA", from: "a")
      end
      assert_includes err.message, "a -> b -> a"
    end

    it "detects cycles through intermediate modules" do
      assert_raises(GraphQL::Language::DocumentLinker::ImportCycleError) do
        link({
          "a" => "query GetA { ...BFields } fragment Anything on Query { id }",
          "b" => "fragment BFields on Query { id }",
          "c" => "fragment CFields on Query { id }",
        }, {
          "a" => [{ from: "b", symbols: ["BFields"] }],
          "b" => [{ from: "c", symbols: ["CFields"] }],
          "c" => [{ from: "a", symbols: ["Anything"] }],
        }, "GetA", from: "a")
      end
    end
  end

  describe "missing symbols" do
    it "raises UnknownModuleError for imports from absent modules" do
      err = assert_raises(GraphQL::Language::DocumentLinker::UnknownModuleError) do
        link({
          "posts" => "query GetPost { ...UserFields }",
        }, {
          "posts" => [{ from: "users", symbols: ["UserFields"] }],
        }, "GetPost", from: "posts")
      end
      assert_includes err.message, "users"
    end

    it "raises MissingSymbolError when the source module doesn't export the symbol" do
      err = assert_raises(GraphQL::Language::DocumentLinker::MissingSymbolError) do
        link({
          "users" => "fragment UserFields on User { id }",
          "posts" => "query GetPost { ...PostFields }",
        }, {
          "posts" => [{ from: "users", symbols: ["PostFields"] }],
        }, "GetPost", from: "posts")
      end
      assert_includes err.message, "PostFields"
    end

    it "raises MissingSymbolError for spreads that are neither defined nor imported" do
      err = assert_raises(GraphQL::Language::DocumentLinker::MissingSymbolError) do
        link({
          "posts" => "query GetPost { ...Nowhere }",
        }, {}, "GetPost", from: "posts")
      end
      assert_includes err.message, "...Nowhere"
    end

    it "raises UnknownModuleError when the manifest mentions an absent module" do
      assert_raises(GraphQL::Language::DocumentLinker::UnknownModuleError) do
        GraphQL::Language::DocumentLinker.new(
          modules: { "posts" => "query GetPost { id }" },
          imports: { "comments" => [{ from: "posts", symbols: ["F"] }] },
        )
      end
    end
  end

  describe "undeclared variables" do
    it "raises UndeclaredVariableError for variables used by the operation" do
      err = assert_raises(GraphQL::Language::DocumentLinker::UndeclaredVariableError) do
        link({
          "posts" => "query GetPost { post(id: $id) { title } }",
        }, {}, "GetPost", from: "posts")
      end
      assert_includes err.message, "$id"
    end

    it "raises UndeclaredVariableError for variables used by reachable fragments" do
      err = assert_raises(GraphQL::Language::DocumentLinker::UndeclaredVariableError) do
        link({
          "users" => "fragment UserFields on User { avatar(size: $size) }",
          "posts" => <<~GRAPHQL,
            query GetPost($id: ID!) {
              post(id: $id) {
                author {
                  ...UserFields
                }
              }
            }
          GRAPHQL
        }, {
          "posts" => [{ from: "users", symbols: ["UserFields"] }],
        }, "GetPost", from: "posts")
      end
      assert_includes err.message, "$size"
    end

    it "accepts variables declared by the operation, even when used in fragments" do
      result = link({
        "users" => "fragment UserFields on User { avatar(size: $size) }",
        "posts" => <<~GRAPHQL,
          query GetPost($size: Int) {
            post {
              author {
                ...UserFields
              }
            }
          }
        GRAPHQL
      }, {
        "posts" => [{ from: "users", symbols: ["UserFields"] }],
      }, "GetPost", from: "posts")

      assert_includes result, "query GetPost($size: Int) {"
    end

    it "finds variables used inside directives" do
      assert_raises(GraphQL::Language::DocumentLinker::UndeclaredVariableError) do
        link({
          "posts" => "query GetPost { post { title @include(if: $withTitle) } }",
        }, {}, "GetPost", from: "posts")
      end
    end
  end

  describe "invalid module contents" do
    it "raises DuplicateDefinitionError for repeated fragment names in one module" do
      assert_raises(GraphQL::Language::DocumentLinker::DuplicateDefinitionError) do
        GraphQL::Language::DocumentLinker.new(
          modules: { "posts" => "fragment F on Post { id } fragment F on Post { title }" },
        )
      end
    end

    it "raises NameConflictError when a module imports a symbol it also defines" do
      err = assert_raises(GraphQL::Language::DocumentLinker::NameConflictError) do
        link({
          "users" => "fragment Fields on User { id }",
          "posts" => <<~GRAPHQL,
            query GetPost {
              post {
                ...Fields
              }
            }

            fragment Fields on Post {
              title
            }
          GRAPHQL
        }, {
          "posts" => [{ from: "users", symbols: ["Fields"] }],
        }, "GetPost", from: "posts")
      end
      assert_includes err.message, "Fields"
    end

    it "raises NameConflictError when the same symbol is imported from two modules" do
      assert_raises(GraphQL::Language::DocumentLinker::NameConflictError) do
        GraphQL::Language::DocumentLinker.new(
          modules: {
            "a" => "fragment F on Query { id }",
            "b" => "fragment F on Query { id }",
            "posts" => "query GetPost { id }",
          },
          imports: { "posts" => [{ from: "a", symbols: ["F"] }, { from: "b", symbols: ["F"] }] },
        )
      end
    end
  end

  describe "operation selection" do
    it "raises OperationNotFoundError for unknown operations" do
      assert_raises(GraphQL::Language::DocumentLinker::OperationNotFoundError) do
        link({ "posts" => "query GetPost { id }" }, {}, "Nope", from: "posts")
      end
    end

    it "raises OperationNotFoundError when the name is ambiguous without from:" do
      assert_raises(GraphQL::Language::DocumentLinker::OperationNotFoundError) do
        link({
          "a" => "query Get { id }",
          "b" => "query Get { id }",
        }, {}, "Get")
      end
    end

    it "raises OperationNotFoundError when a module has several operations and no name is given" do
      assert_raises(GraphQL::Language::DocumentLinker::OperationNotFoundError) do
        link({
          "posts" => "query A { id } query B { id }",
        }, {}, nil, from: "posts")
      end
    end

    it "raises UnknownModuleError for an unknown from: module" do
      assert_raises(GraphQL::Language::DocumentLinker::UnknownModuleError) do
        link({ "posts" => "query Get { id }" }, {}, "Get", from: "comments")
      end
    end
  end

  describe "the linked document" do
    it "can be executed by GraphQL" do
      user_type = Class.new(GraphQL::Schema::Object) do
        graphql_name "User"
        field :name, String
        field :avatar_url, String
      end

      post_type = Class.new(GraphQL::Schema::Object) do
        graphql_name "Post"
        field :title, String
        field :author, user_type
      end

      query_type = Class.new(GraphQL::Schema::Object) do
        graphql_name "Query"
        field :post, post_type

        def post
          { title: "Hello", author: { name: "Bill", avatar_url: "http://example.com/a.png" } }
        end
      end

      schema = Class.new(GraphQL::Schema) do
        query(query_type)
      end

      document = link({
        "users" => "fragment UserFields on User { name avatarUrl }",
        "posts" => <<~GRAPHQL,
          query GetPost {
            post {
              title
              author {
                ...UserFields
              }
            }
          }
        GRAPHQL
      }, {
        "posts" => [{ from: "users", symbols: ["UserFields"] }],
      }, "GetPost", from: "posts")

      result = schema.execute(document)
      assert_equal({ "post" => { "title" => "Hello", "author" => { "name" => "Bill", "avatarUrl" => "http://example.com/a.png" } } }, result["data"])
    end
  end
end
