# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::DeliveryStatusReport do
  def crlf(string)
    Mail::Utilities.to_crlf(string)
  end

  describe "parsing" do
    let(:report) do
      described_class.new(crlf(<<-DSN))
Reporting-MTA: dns; mx.example.org
Received-From-MTA: dns; relay.example.org
X-Postfix-Queue-ID: ABC123

Final-Recipient: rfc822; <alice@example.org>
Original-Recipient: rfc822; alice@example.org
Action: failed
Status: 5.1.1
Remote-MTA: dns; gmail-smtp-in.l.example.com
Diagnostic-Code: smtp; 550 5.1.1 User unknown
X-Mta-Name: first

Final-Recipient: rfc822; bob@example.org
Action: delayed
Status: 4.2.0

Final-Recipient: rfc822; carol@example.org
Action: delivered
Status: 2.0.0
      DSN
    end

    it "keeps report-level fields separate from recipient blocks" do
      expect(report["reporting-mta"]).to eq "dns; mx.example.org"
      expect(report["received-from-mta"]).to eq "dns; relay.example.org"
      expect(report["x-postfix-queue-id"]).to eq "ABC123"
      expect(report.fields.map(&:name)).to eq(%w[
        Reporting-MTA Received-From-MTA X-Postfix-Queue-ID
      ])
    end

    it "returns one recipient entry per recipient block" do
      expect(report.recipients.size).to eq 3
      expect(report.recipients).to all(be_a(described_class::Recipient))
    end

    it "reads the address, action, status and diagnostic per recipient" do
      first = report.recipients.first
      expect(first.final_recipient).to eq "rfc822; <alice@example.org>"
      expect(first.address).to eq "alice@example.org"
      expect(first.address_type).to eq "rfc822"
      expect(first.action).to eq "failed"
      expect(first.status).to eq "5.1.1"
      expect(first.enhanced_status_code).to eq "5.1.1"
      expect(first.error_status).to eq "5.1.1"
      expect(first.diagnostic_code).to eq "smtp; 550 5.1.1 User unknown"
      expect(first.remote_mta).to eq "dns; gmail-smtp-in.l.example.com"
      expect(first).to be_bounced
      expect(first).not_to be_retryable
    end

    it "keeps values aligned to their own recipient block" do
      addresses = report.recipients.map(&:address)
      actions = report.recipients.map(&:action)
      statuses = report.recipients.map(&:status)

      expect(addresses).to eq %w[alice@example.org bob@example.org carol@example.org]
      expect(actions).to eq %w[failed delayed delivered]
      expect(statuses).to eq %w[5.1.1 4.2.0 2.0.0]
    end

    it "leaves unknown extension fields in their original block" do
      expect(report["x-postfix-queue-id"]).to eq "ABC123"
      expect(report.recipients.first["x-mta-name"]).to eq "first"
      expect(report.recipients[1]["x-mta-name"]).to be_nil
      expect(report.recipients.first.field?("x-mta-name")).to eq true
    end

    it "unfolds wrapped field lines" do
      folded = "Reporting-MTA: dns; mx.example.org\r\n\r\n" \
               "Final-Recipient: rfc822; alice@example.org\r\n" \
               "Diagnostic-Code: smtp; 550-5.1.1 line one\r\n" \
               "    550 5.1.1 line two\r\n"
      recipient = described_class.new(folded).recipients.first
      expect(recipient.diagnostic_code).to eq "smtp; 550-5.1.1 line one    550 5.1.1 line two"
    end

    it "accepts LF separated input without a report-level block" do
      report = described_class.new("Final-Recipient: rfc822; alice@example.org\n" \
                                   "Action: failed\nStatus: 5.1.1")
      expect(report.fields).to be_empty
      expect(report.recipients.size).to eq 1
      expect(report.recipients.first.address).to eq "alice@example.org"
    end
  end

  describe "missing fields" do
    let(:report) do
      described_class.new(crlf(<<-DSN))
Reporting-MTA: dns; mx.example.org

Final-Recipient: rfc822; alice@example.org
Action: failed
      DSN
    end

    it "represents absent optional fields with nil and no errors" do
      recipient = report.recipients.first
      expect(recipient.diagnostic_code).to be_nil
      expect(recipient.remote_mta).to be_nil
      expect(recipient.field?("diagnostic-code")).to eq false
      expect(recipient.errors).to be_empty
      expect(report["arrival-date"]).to be_nil
      expect(report.errors).to be_empty
    end

    it "treats an absent status as retryable" do
      expect(report.recipients.first).to be_retryable
    end
  end

  describe "syntax errors" do
    let(:report) do
      described_class.new(crlf(<<-DSN))
Reporting-MTA: dns; mx.example.org
this is not a field

Final-Recipient: broken-value
Action: bounced
Status: 9.9.9
Diagnostic-Code: missing-semicolon
also not a field
      DSN
    end

    it "keeps malformed raw values and reports them separately from missing fields" do
      recipient = report.recipients.first

      expect(recipient.final_recipient).to eq "broken-value"
      expect(recipient.address).to be_nil
      expect(recipient.address_type).to be_nil
      expect(recipient.action).to eq "bounced"
      expect(recipient.status).to eq "9.9.9"
      expect(recipient.diagnostic_code).to eq "missing-semicolon"

      field_names = recipient.errors.map(&:field_name)
      expect(field_names).to include("Final-Recipient", "Action", "Status", "Diagnostic-Code", nil)
      expect(recipient.errors.map(&:reason)).to include("invalid field line")
    end

    it "keeps report-level syntax errors on the report" do
      expect(report.fields.map(&:name)).to eq ["Reporting-MTA"]
      expect(report.errors.size).to eq 1
      expect(report.errors.first.field_name).to be_nil
      expect(report.errors.first.value).to eq "this is not a field"
    end

    it "does not confuse a missing field with an invalid field" do
      recipient = report.recipients.first
      expect(recipient["remote-mta"]).to be_nil
      expect(recipient.errors.map(&:field_name)).not_to include("Remote-Mta")
    end
  end
end
