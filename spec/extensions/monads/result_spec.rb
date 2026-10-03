# frozen_string_literal: true

RSpec.describe Dry::Validation::Result do
  before { Dry::Validation.load_extensions(:monads) }

  let(:schema) do
    Class.new(Dry::Validation::Contract) do
      schema do
        required(:name).filled(:string, size?: 2..4)
      end
    end.new
  end

  let(:result) { schema.(input) }

  context "with valid input" do
    let(:input) { {name: "Jane"} }

    describe "#to_monad" do
      it "returns a Success value" do
        monad = result.to_monad

        expect(monad).to be_a Dry::Monads::Result
        expect(monad).to be_a_success
        expect(monad.value!).to be(result)
      end
    end
  end

  context "with invalid input" do
    let(:input) { {name: ""} }

    describe "#to_monad" do
      it "returns a Failure value" do
        monad = result.to_monad

        expect(monad).to be_a_failure
        expect(monad.failure).to eql(result)
      end
    end
  end

  context "with warnings only" do
    let(:schema) do
      Class.new(Dry::Validation::Contract) do
        schema do
          required(:name).filled(:string)
        end

        rule(:name) do
          key.warning("could be longer") if value.size < 5
        end
      end.new
    end

    let(:input) { {name: "Jane"} }

    describe "#to_monad" do
      it "returns a Success value" do
        monad = result.to_monad

        expect(monad).to be_a_success
        expect(monad.value!.warnings.to_h).to eql(name: ["could be longer"])
      end
    end
  end
end
