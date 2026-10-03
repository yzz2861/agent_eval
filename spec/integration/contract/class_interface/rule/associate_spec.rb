# frozen_string_literal: true

require "dry/validation/contract"

RSpec.describe Dry::Validation::Contract, "Rule#associate" do
  subject(:contract) { contract_class.new }

  let(:contract_class) do
    Class.new(Dry::Validation::Contract) do
      def self.name
        "SettlementContract"
      end

      params do
        required(:invoices).array(:hash) do
          required(:id).filled(:string)
          required(:amount).filled(:integer)
        end

        required(:allocations).array(:hash) do
          required(:invoice_id).filled(:string)
          required(:amount).filled(:integer)
        end
      end

      rule(:invoices, :allocations).associate(:id, :invoice_id) do |association:|
        invoice_counts = association.left_records.each_with_object(Hash.new(0)) do |(index, invoice), counts|
          next if schema_error?([:invoices, index, :id])

          counts[invoice[:id]] += 1
        end

        association.groups.each do |group|
          index = group[:left_index]
          invoice = group[:left_value]
          invoice_id = invoice[:id]

          if invoice_counts[invoice_id] > 1
            key([:invoices, index, :id]).failure("must be unique")
            next
          end

          next if schema_error?([:invoices, index, :amount])

          allocated_amount = group[:matches].sum do |match|
            next 0 if schema_error?([:allocations, match.right_index, :amount])

            match.right_value[:amount]
          end

          if allocated_amount > invoice[:amount]
            key([:invoices, index, :amount]).failure("allocations exceed invoice amount")
          end
        end

        association.unmatched_right.each do |index, _allocation|
          key([:allocations, index, :invoice_id]).failure("does not reference an invoice")
        end
      end
    end
  end

  it "keeps duplicate keys, unmatched records, and original error positions" do
    result = contract.(
      invoices: [
        {id: "inv-1", amount: 100},
        {id: "inv-2", amount: 50},
        {id: "inv-1", amount: 100},
        {id: "inv-3", amount: 10},
        {id: "inv-4", amount: 10}
      ],
      allocations: [
        {invoice_id: "inv-1", amount: 40},
        {invoice_id: "inv-1", amount: 40},
        {invoice_id: "inv-3", amount: 15},
        {invoice_id: "missing", amount: 5},
        {invoice_id: 999, amount: 5},
        {invoice_id: "inv-4", amount: "bad"}
      ]
    )

    expect(result.errors.to_h).to eql(
      invoices: {
        0 => {id: ["must be unique"]},
        2 => {id: ["must be unique"]},
        3 => {amount: ["allocations exceed invoice amount"]}
      },
      allocations: {
        3 => {invoice_id: ["does not reference an invoice"]},
        4 => {invoice_id: ["must be a string"]},
        5 => {amount: ["must be an integer"]}
      }
    )
  end

  it "exposes matched values and indexes without choosing the last duplicate key" do
    observed_association = nil

    contract_class.rule(:invoices, :allocations).associate(:id, :invoice_id) do |association:|
      observed_association = association
    end

    contract.(
      invoices: [
        {id: 1, amount: 90},
        {id: "inv-1", amount: "bad"},
        {id: "inv-1", amount: 20},
        {id: "inv-2", amount: 30}
      ],
      allocations: [
        {invoice_id: "inv-1", amount: 5},
        {invoice_id: 4, amount: 6},
        {invoice_id: "inv-3", amount: 7}
      ]
    )
    expect(observed_association.left_records.map(&:first)).to eql([1, 2, 3])
    expect(observed_association.right_records.map(&:first)).to eql([0, 2])
    expect(observed_association.matches.map { |match|
      [match.left_index, match.right_index]
    }).to eql([[1, 0], [2, 0]])
    expect(observed_association.unmatched_right).to eql([[2, {invoice_id: "inv-3", amount: 7}]])
  end

  it "does not run the association when either array itself failed schema checks" do
    ran = false

    contract_class.rule(:invoices, :allocations).associate(:id, :invoice_id) do
      ran = true
    end

    contract.(invoices: "not an array", allocations: [])

    expect(ran).to be(false)
  end
end
