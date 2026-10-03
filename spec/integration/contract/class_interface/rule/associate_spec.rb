# frozen_string_literal: true

require "dry/validation/contract"

RSpec.describe Dry::Validation::Contract, "Rule#associate" do
  subject(:contract) { contract_class.new }

  let(:contract_class) do
    Class.new(Dry::Validation::Contract) do
      def self.name
        "SettlementContract"
      end

      json do
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
        association.groups.each do |group|
          if group[:left].size > 1
            group[:left].each do |invoice|
              key(association.left_error_path(invoice.index, :id)).failure("duplicate invoice id")
            end
            next
          end

          invoice = group[:left].first
          allocated = group[:right].sum { |item| item.value[:amount] }

          if allocated > invoice.value[:amount]
            key(association.left_error_path(invoice.index, :amount)).failure("allocations exceed invoice amount")
          end
        end

        association.unmatched_right.each do |allocation|
          key(association.right_error_path(allocation.index, :invoice_id)).failure("invoice not found")
        end
      end
    end
  end

  it "keeps matched item values and original indexes, including duplicate keys" do
    captured = nil
    contract_class.rule(:invoices, :allocations).associate(:id, :invoice_id) do |association:|
      captured = association.matches
    end

    contract.(
      invoices: [{id: "inv-1", amount: 10}, {id: "inv-1", amount: 20}],
      allocations: [{invoice_id: "inv-1", amount: 1}, {invoice_id: "inv-2", amount: 2}]
    )

    expect(captured.map { |pair| [pair.key, pair.left_index, pair.right_index] }).to eql(
      [["inv-1", 0, 0], ["inv-1", 1, 0]]
    )
  end

    it "places duplicate, total, and dangling errors at their source positions" do
    result = contract.(
      invoices: [
        {id: "inv-1", amount: 10},
        {id: "inv-2", amount: 100},
        {id: "inv-2", amount: 200},
        {id: "inv-unused", amount: 30}
      ],
      allocations: [
        {invoice_id: "inv-1", amount: 4},
        {invoice_id: "inv-1", amount: 7},
        {invoice_id: "inv-2", amount: 50},
        {invoice_id: "missing", amount: 1},
        {invoice_id: nil, amount: 2}
      ]
    )

    expect(result.errors.to_h).to eql(
      invoices: {
        0 => {amount: ["allocations exceed invoice amount"]},
        1 => {id: ["duplicate invoice id"]},
        2 => {id: ["duplicate invoice id"]}
      },
      allocations: {
        3 => {invoice_id: ["invoice not found"]},
        4 => {invoice_id: ["must be a string"]}
      }
    )
    expect(result.errors.to_h[:invoices]).not_to have_key(3)
  end

  it "does not let schema-invalid items participate in the association" do
    captured = nil
    contract_class.rule(:invoices, :allocations).associate(:id, :invoice_id) do |association:|
      captured = association
    end

    contract.(
      invoices: [
        {id: "inv-1", amount: 10},
        {id: 1, amount: 20},
        {id: "inv-3", amount: "bad"}
      ],
      allocations: [
        {invoice_id: "inv-1", amount: 1},
        {invoice_id: "inv-2", amount: 2},
        {invoice_id: 1, amount: 3},
        {invoice_id: "inv-3", amount: 4}
      ]
    )

    expect(captured.groups.map { |group| [group[:key], group[:left].map(&:index), group[:right].map(&:index)] }).to eql(
      [["inv-1", [0], [0]]]
    )
    expect(captured.unmatched_right.map(&:index)).to eql([1, 3])
  end
end
