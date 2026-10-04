# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::DeliveryStatusParser do
  def parse(body)
    described_class.new(Mail::Utilities.to_crlf(body))
  end

  describe "report level fields" do
    it "collects the first field group as report fields" do
      dsn = parse(<<-DSN)
Reporting-MTA: dns; mx.example.org
Received-From-MTA: dns; relay.example.net
Arrival-Date: Mon, 02 Feb 2009 17:30:00 +0000

Final-Recipient: rfc822; user@example.org
Action: failed
Status: 5.1.1
      DSN

      expect(dsn.report_group).not_to be_nil
      expect(dsn.report_fields['reporting-mta']).to eq 'dns; mx.example.org'
      expect(dsn.report_fields['received-from-mta']).to eq 'dns; relay.example.net'
      expect(dsn.report_fields['arrival-date']).to eq 'Mon, 02 Feb 2009 17:30:00 +0000'
    end

    it "keeps unknown extension fields in the report group" do
      dsn = parse(<<-DSN)
Reporting-MTA: dns; mx.example.org
X-Postfix-Queue-ID: 1A2B3C4D
X-Postfix-Sender: rfc822; sender@example.org

Final-Recipient: rfc822; user@example.org
Action: failed
Status: 5.1.1
      DSN

      expect(dsn.report_fields['x-postfix-queue-id']).to eq '1A2B3C4D'
      expect(dsn.report_fields['x-postfix-sender']).to eq 'rfc822; sender@example.org'
    end

    it "returns an empty report hash and no report group when the body has no report block" do
      dsn = parse(<<-DSN)
Final-Recipient: rfc822; user@example.org
Action: failed
Status: 5.1.1
      DSN

      expect(dsn.report_group).to be_nil
      expect(dsn.report_fields).to eq({})
      expect(dsn.recipients.length).to eq 1
    end
  end

  describe "recipients" do
    let(:multi_recipient_body) do
      <<-DSN
Reporting-MTA: dns; mx.example.org

Final-Recipient: rfc822; first@example.org
Action: failed
Status: 5.1.1
Diagnostic-Code: smtp; 550 no such user

Final-Recipient: rfc822; second@example.org
Action: delayed
Status: 4.2.2
Diagnostic-Code: smtp; 452 mailbox full
      DSN
    end

    it "returns one object per recipient block in document order" do
      dsn = parse(multi_recipient_body)
      expect(dsn.recipients.map(&:address)).to eq %w[first@example.org second@example.org]
    end

    it "returns the action and enhanced status for each recipient independently" do
      dsn = parse(multi_recipient_body)
      first, second = dsn.recipients

      expect(first.action).to eq 'failed'
      expect(first.status).to eq '5.1.1'
      expect(first.diagnostic_code).to eq 'smtp; 550 no such user'

      expect(second.action).to eq 'delayed'
      expect(second.status).to eq '4.2.2'
      expect(second.diagnostic_code).to eq 'smtp; 452 mailbox full'
    end

    it "strips only the type marker, leaving the raw Final-Recipient available" do
      dsn = parse(<<-DSN)
Final-Recipient: RFC822; User@Example.org
Action: delivered
Status: 2.0.0
      DSN
      recipient = dsn.recipients.first

      expect(recipient.final_recipient).to eq 'RFC822; User@Example.org'
      expect(recipient.address).to eq 'User@Example.org'
    end

    it "keeps each recipient's own extension fields inside its block" do
      dsn = parse(<<-DSN)
Reporting-MTA: dns; mx.example.org

Final-Recipient: rfc822; first@example.org
Action: failed
Status: 5.1.1
X-Local-Tag: one

Final-Recipient: rfc822; second@example.org
Action: failed
Status: 5.1.1
X-Local-Tag: two
      DSN
      first, second = dsn.recipients

      expect(first.fields['x-local-tag']).to eq 'one'
      expect(second.fields['x-local-tag']).to eq 'two'
    end

    it "does not require recipients to be aligned by array position" do
      dsn = parse(multi_recipient_body)
      first = dsn.recipients.first

      aggregate_failures do
        expect(first.address).to eq 'first@example.org'
        expect(first.action).to eq 'failed'
        expect(first.status).to eq '5.1.1'
        expect(first.diagnostic_code).to include '550'
      end
    end

    it "unfolds folded fields" do
      dsn = parse(<<-DSN)
Reporting-MTA: dns; mx.example.org

Final-Recipient: rfc822; user@example.org
Action: failed
Status: 5.1.1
Diagnostic-Code: smtp; 550-5.1.1 The account
    does not exist
      DSN

      expect(dsn.recipients.first.diagnostic_code).to eq(
        'smtp; 550-5.1.1 The account does not exist'
      )
    end
  end

  describe "missing fields versus syntax errors" do
    it "returns nil for a field that is absent" do
      dsn = parse(<<-DSN)
Reporting-MTA: dns; mx.example.org

Final-Recipient: rfc822; user@example.org
Action: delayed
Status: 4.2.2
      DSN
      recipient = dsn.recipients.first

      expect(recipient.diagnostic_code).to be_nil
      expect(recipient.key?('diagnostic-code')).to be false
      expect(recipient.errors).to eq []
    end

    it "still returns an invalid action and records the syntax error" do
      dsn = parse(<<-DSN)
Final-Recipient: rfc822; user@example.org
Action: bounced
Status: 5.1.1
      DSN
      recipient = dsn.recipients.first

      expect(recipient.action).to eq 'bounced'
      expect(recipient.errors.map(&:first)).to include 'action'
    end

    it "still returns an invalid enhanced status code and records it" do
      dsn = parse(<<-DSN)
Final-Recipient: rfc822; user@example.org
Action: failed
Status: 9.9.9
      DSN
      recipient = dsn.recipients.first

      expect(recipient.status).to eq '9.9.9'
      expect(recipient.errors).to include(
        ['status', '9.9.9', an_instance_of(String)]
      )
    end

    it "records a recipient address that lacks its type marker" do
      dsn = parse(<<-DSN)
Final-Recipient: user@example.org
Action: failed
Status: 5.1.1
      DSN
      recipient = dsn.recipients.first

      expect(recipient.address).to eq 'user@example.org'
      expect(recipient.errors.map(&:first)).to include 'final-recipient'
    end

    it "reports structural lines that are not fields separately" do
      dsn = parse(<<-DSN)
Reporting-MTA: dns; mx.example.org
this is not a field

Final-Recipient: rfc822; user@example.org
Action: failed
Status: 5.1.1
      DSN

      expect(dsn.recipients.first.errors).to eq []
      expect(dsn.errors.map(&:last)).to include 'line is not a field'
    end
  end

  describe "real multi-recipient fixture" do
    let(:mail) do
      Mail.read(fixture_path('emails', 'multipart_report_emails', 'multi_address_bounce1.eml'))
    end

    it "parses every recipient block" do
      recipients = mail.delivery_status_part.delivery_status.recipients

      expect(recipients.length).to eq 5
      expect(recipients.first.address).to eq 'bbbbvhvbbvkjbhfbvbvjhb@gmail.com'
      expect(recipients.first.action).to eq 'failed'
      expect(recipients.first.status).to eq '5.1.1'
      expect(recipients.last.address).to eq 'qfvhgsvhgsduiohncdhcvhsdfvsfygusd@gmail.com'
    end

    it "keeps unknown report fields" do
      report_fields = mail.delivery_status_part.delivery_status.report_fields

      expect(report_fields['x-postfix-queue-id']).to eq '9B7841BC027'
      expect(report_fields['reporting-mta']).to eq 'dns; lvmail01.LL.com'
    end
  end
end
