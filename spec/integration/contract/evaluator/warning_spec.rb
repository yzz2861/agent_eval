# frozen_string_literal: true

RSpec.describe Dry::Validation::Evaluator, "warnings" do
  subject(:contract) { contract_class.new }

  let(:contract_class) do
    Class.new(Dry::Validation::Contract) do
      schema do
        required(:email).filled(:string)
        required(:password).filled(:string)
        optional(:nums).array(:integer)
      end
    end
  end

  let(:result) { contract.(email: "jane@doe.org", password: "secret") }

  context "setting a warning via key" do
    before do
      contract_class.rule(:password) do
        key.warning("could be stronger") if value.size < 12
      end
    end

    it "keeps the result successful" do
      expect(result).to be_success
      expect(result).not_to be_failure
      expect(result.errors.to_h).to be_empty
    end

    it "exposes warnings separately from errors" do
      expect(result.warnings.to_h).to eql(password: ["could be stronger"])
    end

    it "preserves the message path and severity" do
      warning = result.warnings.first

      expect(warning.path).to eql([:password])
      expect(warning.severity).to be(:warning)
      expect(warning).to be_warning
      expect(warning).not_to be_base
    end

    it "supports checking warnings by key" do
      expect(result.warning?(:password)).to be(true)
      expect(result.warning?(:email)).to be(false)
      expect(result.error?(:password)).to be(false)
    end

    it "includes warnings in inspect" do
      expect(result.inspect).to include('warnings={password: ["could be stronger"]}')
    end
  end

  context "setting a base warning" do
    before do
      contract_class.rule(:password) do
        base.warning("passwords are deprecated") if values[:password] == "secret"
      end
    end

    it "exposes it under :base and keeps the result successful" do
      expect(result).to be_success
      expect(result.warnings.to_h).to eql(nil => ["passwords are deprecated"])
      expect(result.warnings.first).to be_base
    end
  end

  context "setting a warning with meta" do
    before do
      contract_class.rule(:password) do
        key.warning(text: "could be stronger", strength: 2) if value.size < 12
      end
    end

    it "preserves meta" do
      warning = result.warnings.first

      expect(warning.text).to eql("could be stronger")
      expect(warning.meta).to eql(strength: 2)
    end
  end

  context "setting a warning using a message identifier" do
    let(:contract_class) do
      Class.new(Dry::Validation::Contract) do
        config.messages.backend = :i18n
        config.messages.load_paths << SPEC_ROOT
          .join("fixtures/messages/errors.en.yml").realpath
        config.messages.load_paths << SPEC_ROOT
          .join("fixtures/messages/errors.pl.yml").realpath

        schema do
          required(:email).filled(:string)
          required(:password).filled(:string)
        end

        rule(:email) do
          key.warning(:taken, values.to_h) if value == "jane@doe.org"
        end
      end
    end

    before do
      I18n.available_locales = %i[en pl]
    end

    it "resolves the message with tokens" do
      expect(result.warnings.to_h).to eql(email: ["looks like jane@doe.org is taken"])
    end

    it "evaluates the warning using another locale" do
      expect(result.warnings(locale: :pl).to_h).to eql(
        email: ["wygląda, że jane@doe.org jest zajęty"]
      )
      expect(result.warnings.to_h).to eql(email: ["looks like jane@doe.org is taken"])
    end

    it "supports full messages" do
      expect(result.warnings(full: true).map(&:to_s)).to eql(
        ["E-mail looks like jane@doe.org is taken"]
      )
    end
  end

  context "mixing errors and warnings" do
    before do
      contract_class.rule(:password) do
        key.failure("is way too short") if value.size < 4
        key.warning("could be stronger") if value.size < 12
      end
    end

    it "fails on errors while keeping warnings" do
      result = contract.(email: "jane@doe.org", password: "abc")

      expect(result).to be_failure
      expect(result.errors.to_h).to eql(password: ["is way too short"])
      expect(result.warnings.to_h).to eql(password: ["could be stronger"])
    end
  end

  context "setting warnings within each rule" do
    before do
      contract_class.rule(:nums).each do
        key.warning("should not be negative") if value.negative?
      end
    end

    it "sets warnings under the correct indexes" do
      result = contract.(email: "jane@doe.org", password: "secret", nums: [1, -2, -3])

      expect(result).to be_success
      expect(result.warnings.to_h).to eql(
        nums: {1 => ["should not be negative"], 2 => ["should not be negative"]}
      )
    end
  end

  context "setting warnings within a macro" do
    before do
      contract_class.register_macro(:not_common) do
        key.warning("is too common") if %w[secret qwerty].include?(value)
      end

      contract_class.rule(:password).validate(:not_common)
    end

    it "sets the warning" do
      expect(result).to be_success
      expect(result.warnings.to_h).to eql(password: ["is too common"])
    end
  end

  context "with a rule following a warning-only rule" do
    before do
      contract_class.rule(:password) do
        key.warning("could be stronger") if value.size < 12
      end

      contract_class.rule(:password) do
        key.failure("cannot be a palindrome") if value == value.reverse
      end
    end

    it "does not skip the subsequent rule" do
      result = contract.(email: "jane@doe.org", password: "abcba")

      expect(result).to be_failure
      expect(result.errors.to_h).to eql(password: ["cannot be a palindrome"])
      expect(result.warnings.to_h).to eql(password: ["could be stronger"])
    end

    it "does not treat warnings as rule errors" do
      contract_class.rule(:password) do
        key.failure("rule_error? should be false") if rule_error?
      end

      result = contract.(email: "jane@doe.org", password: "secret")

      expect(result.errors.to_h).to be_empty
      expect(result.warnings.to_h).to eql(password: ["could be stronger"])
    end
  end
end
