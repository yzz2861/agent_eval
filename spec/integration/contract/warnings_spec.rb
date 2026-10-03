# frozen_string_literal: true

RSpec.describe "Contract warnings" do
  subject(:contract) { contract_class.new }

  let(:contract_class) do
    Class.new(Dry::Validation::Contract) do
      params do
        required(:email).filled(:string)
        required(:password).filled(:string, min_size?: 8)
        optional(:nums).array(:integer)
      end

      rule(:password) do
        key.warning("could be stronger") if key? && value.length < 12
      end
    end
  end

  describe "with warnings only" do
    let(:result) { contract.(email: "jane@doe.org", password: "password") }

    it "is a success" do
      expect(result).to be_success
      expect(result).not_to be_failure
    end

    it "returns no errors" do
      expect(result.errors).to be_empty
      expect(result.errors.to_h).to eql({})
    end

    it "exposes warnings separately" do
      expect(result.warnings.to_h).to eql(password: ["could be stronger"])
    end

    it "exposes warning paths" do
      expect(result.warnings.map(&:path)).to eql([[:password]])
    end

    it "reports warnings via #warning?" do
      expect(result.warning?(:password)).to be(true)
      expect(result.warning?(:email)).to be(false)
    end

    it "does not report warnings via #error?" do
      expect(result.error?(:password)).to be(false)
    end
  end

  describe "with no warnings" do
    let(:result) { contract.(email: "jane@doe.org", password: "super-secret-1") }

    it "returns an empty warning set" do
      expect(result.warnings).to be_empty
      expect(result.warnings.to_h).to eql({})
    end
  end

  describe "mixed errors and warnings" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        params do
          required(:email).filled(:string)
          required(:password).filled(:string, min_size?: 8)
        end

        rule(:email) do
          key.failure("must contain @") if key? && !value.include?("@")
        end

        rule(:password) do
          key.warning("could be stronger") if key? && value.length < 12
        end
      end
    end

    let(:result) { contract.(email: "jane", password: "password") }

    it "is a failure" do
      expect(result).to be_failure
    end

    it "keeps errors and warnings apart" do
      expect(result.errors.to_h).to eql(email: ["must contain @"])
      expect(result.warnings.to_h).to eql(password: ["could be stronger"])
    end
  end

  describe "rule skipping" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        params do
          required(:password).filled(:string, min_size?: 8)
        end

        rule(:password) do
          key.warning("could be stronger") if value.length < 12
        end

        rule(:password) do
          key.failure("cannot be a common word") if value == "password"
        end
      end
    end

    it "does not skip subsequent rules for the same key" do
      result = contract.(password: "password")

      expect(result.warnings.to_h).to eql(password: ["could be stronger"])
      expect(result.errors.to_h).to eql(password: ["cannot be a common word"])
      expect(result).to be_failure
    end
  end

  describe "base warnings" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        params do
          required(:email).filled(:string)
        end

        rule do
          base.warning("this form is deprecated")
        end
      end
    end

    it "adds a base warning" do
      result = contract.(email: "jane@doe.org")

      expect(result).to be_success
      expect(result.warnings.to_h).to eql(nil => ["this form is deprecated"])
      expect(result.warnings.first).to be_base
    end
  end

  describe "warning meta" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        params do
          required(:password).filled(:string, min_size?: 8)
        end

        rule(:password) do
          key.warning(text: "could be stronger", code: :weak_password) if value.length < 12
        end
      end
    end

    it "preserves meta on the warning message" do
      warning = contract.(password: "password").warnings.first

      expect(warning.text).to eql("could be stronger")
      expect(warning.path).to eql([:password])
      expect(warning.meta).to eql(code: :weak_password)
    end
  end

  describe "each warnings" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        params do
          required(:nums).array(:integer)
        end

        rule(:nums).each do
          key.warning("is negative") if value.negative?
          key.failure("is too small") if value < -10
        end
      end
    end

    it "adds warnings for array elements" do
      result = contract.(nums: [1, -2, 3])

      expect(result).to be_success
      expect(result.warnings.to_h).to eql(nums: {1 => ["is negative"]})
    end

    it "supports mixed severities within each" do
      result = contract.(nums: [-2, -20])

      expect(result).to be_failure
      expect(result.errors.to_h).to eql(nums: {1 => ["is too small"]})
      expect(result.warnings.to_h).to eql(nums: {0 => ["is negative"], 1 => ["is negative"]})
    end
  end

  describe "custom macro warnings" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        params do
          required(:password).filled(:string, min_size?: 8)
        end

        rule(:password).validate(:password_strength)
      end
    end

    before do
      Dry::Validation.register_macro(:password_strength) do
        key.warning("could be stronger") if value.length < 12
      end
    end

    after do
      Dry::Validation::Macros.container._container.delete("password_strength")
    end

    it "adds warnings from a macro" do
      result = contract.(password: "password")

      expect(result).to be_success
      expect(result.warnings.to_h).to eql(password: ["could be stronger"])
    end
  end

  describe "localized warnings" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        config.messages.load_paths << SPEC_ROOT.join("fixtures/messages/errors.en.yml").realpath
        config.messages.load_paths << SPEC_ROOT.join("fixtures/messages/errors.pl.yml").realpath

        params do
          required(:password).filled(:string, min_size?: 8)
        end

        rule(:password) do
          key.warning(:weak, min: 12) if value.length < 12
        end
      end
    end

    let(:result) { contract.(password: "password") }

    it "resolves message templates with tokens" do
      expect(result.warnings.to_h).to eql(password: ["should be at least 12 chars long"])
    end

    it "supports locale option" do
      expect(result.warnings(locale: :pl).to_h).to eql(
        password: ["powinno mieć co najmniej 12 znaki"]
      )
    end

    it "supports full messages" do
      expect(result.warnings(full: true).map(&:to_s)).to eql(
        ["Password should be at least 12 chars long"]
      )
    end

    it "does not leak warnings into errors" do
      expect(result.errors).to be_empty
      expect(result.errors(locale: :pl)).to be_empty
    end
  end
end
