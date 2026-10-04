# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe Mail::DisplayBody do
  def mail_with(body)
    Mail.new(body.gsub(/^ +/, '').gsub(/\n/, "\r\n"))
  end

  describe "simple messages" do
    it "selects the message itself when it is displayable" do
      mail = mail_with(<<-MAIL)
        Content-Type: text/plain

        Hello
      MAIL
      result = mail.display_body(%w[text/html text/plain])
      expect(result).to be_found
      expect(result.part).to eq mail
      expect(result.resources).to eq []
    end

    it "treats a missing content type as text/plain" do
      mail = mail_with(<<-MAIL)
        Subject: no content type

        Hello
      MAIL
      expect(mail.display_body(%w[text/plain])).to be_found
      expect(mail.display_body(%w[text/html])).to be_empty
    end

    it "returns an empty result when the type is not supported" do
      mail = mail_with(<<-MAIL)
        Content-Type: text/calendar

        BEGIN:VCALENDAR
      MAIL
      result = mail.display_body(%w[text/html text/plain])
      expect(result).to be_empty
      expect(result.part).to be_nil
      expect(result.resources).to eq []
    end
  end

  describe "multipart/alternative" do
    let(:mail) do
      mail_with(<<-MAIL)
        Content-Type: multipart/alternative; boundary=alt

        --alt
        Content-Type: text/plain

        plain body
        --alt
        Content-Type: text/html

        <p>html body</p>
        --alt--
      MAIL
    end

    it "honors the caller's preference order" do
      result = mail.display_body(%w[text/html text/plain])
      expect(result.part.mime_type).to eq 'text/html'

      result = mail.display_body(%w[text/plain text/html])
      expect(result.part.mime_type).to eq 'text/plain'
    end

    it "falls back to the next supported type" do
      result = mail.display_body(%w[text/calendar text/plain])
      expect(result.part.mime_type).to eq 'text/plain'
    end
  end

  describe "attachments" do
    it "never selects an explicit attachment as the body" do
      mail = mail_with(<<-MAIL)
        Content-Type: multipart/mixed; boundary=mix

        --mix
        Content-Type: text/html
        Content-Disposition: attachment; filename=page.html

        <p>attachment, not body</p>
        --mix
        Content-Type: text/plain

        real body
        --mix--
      MAIL
      result = mail.display_body(%w[text/html text/plain])
      expect(result.part.mime_type).to eq 'text/plain'
      expect(result.part.decoded).to match(/real body/)
    end

    it "returns an empty result when only attachments are displayable types" do
      mail = mail_with(<<-MAIL)
        Content-Type: multipart/mixed; boundary=mix

        --mix
        Content-Type: text/html
        Content-Disposition: attachment; filename=page.html

        <p>attachment</p>
        --mix--
      MAIL
      expect(mail.display_body(%w[text/html text/plain])).to be_empty
    end
  end

  describe "multipart/related" do
    it "collects the CID resources of the selected branch" do
      mail = mail_with(<<-MAIL)
        Content-Type: multipart/related; boundary=rel

        --rel
        Content-Type: text/html

        <p><img src="cid:logo"></p>
        --rel
        Content-Type: image/png
        Content-ID: <logo>
        Content-Disposition: inline

        PNGDATA
        --rel--
      MAIL
      result = mail.display_body(%w[text/html])
      expect(result.part.mime_type).to eq 'text/html'
      expect(result.resources.length).to eq 1
      expect(result.resources.first.content_id).to eq '<logo>'
    end

    it "uses the start parameter to find the root part" do
      mail = mail_with(<<-MAIL)
        Content-Type: multipart/related; boundary=rel; start="<root>"

        --rel
        Content-Type: image/png
        Content-ID: <logo>

        PNGDATA
        --rel
        Content-Type: text/html
        Content-ID: <root>

        <p>html body</p>
        --rel--
      MAIL
      result = mail.display_body(%w[text/html])
      expect(result.part.mime_type).to eq 'text/html'
      expect(result.resources.map(&:content_id)).to eq ['<logo>']
    end

    it "excludes attachments from the resources" do
      mail = mail_with(<<-MAIL)
        Content-Type: multipart/related; boundary=rel

        --rel
        Content-Type: text/html

        <p>html body</p>
        --rel
        Content-Type: image/png
        Content-ID: <logo>
        Content-Disposition: attachment; filename=logo.png

        PNGDATA
        --rel--
      MAIL
      result = mail.display_body(%w[text/html])
      expect(result).to be_found
      expect(result.resources).to eq []
    end

    it "does not mix resources from other alternative branches" do
      mail = mail_with(<<-MAIL)
        Content-Type: multipart/alternative; boundary=alt

        --alt
        Content-Type: multipart/related; boundary=rel1

        --rel1
        Content-Type: text/html

        <p>branch one</p>
        --rel1
        Content-Type: image/png
        Content-ID: <one>

        PNG1
        --rel1--
        --alt
        Content-Type: multipart/related; boundary=rel2

        --rel2
        Content-Type: text/html

        <p>branch two</p>
        --rel2
        Content-Type: image/png
        Content-ID: <two>

        PNG2
        --rel2--
        --alt--
      MAIL
      result = mail.display_body(%w[text/html])
      expect(result.part.decoded).to match(/branch one/)
      expect(result.resources.map(&:content_id)).to eq ['<one>']
    end
  end

  describe "nested message/rfc822" do
    let(:mail) do
      mail_with(<<-MAIL)
        Content-Type: multipart/mixed; boundary=mix

        --mix
        Content-Type: text/plain

        see attached
        --mix
        Content-Type: message/rfc822

        Content-Type: text/html

        <p>nested html</p>
        --mix--
      MAIL
    end

    it "does not descend into nested messages by default" do
      result = mail.display_body(%w[text/html])
      expect(result).to be_empty
    end

    it "descends into nested messages when search_nested is true" do
      result = mail.display_body(%w[text/html], search_nested: true)
      expect(result).to be_found
      expect(result.part.decoded).to match(/nested html/)
    end
  end

  describe "multipart/mixed with nested alternative" do
    it "finds the body through the mixed container" do
      mail = mail_with(<<-MAIL)
        Content-Type: multipart/mixed; boundary=mix

        --mix
        Content-Type: multipart/alternative; boundary=alt

        --alt
        Content-Type: text/plain

        plain body
        --alt
        Content-Type: text/html

        <p>html body</p>
        --alt--
        --mix
        Content-Type: application/pdf
        Content-Disposition: attachment; filename=doc.pdf

        PDFDATA
        --mix--
      MAIL
      result = mail.display_body(%w[text/html text/plain])
      expect(result.part.mime_type).to eq 'text/html'
      expect(result.resources).to eq []
    end
  end

  describe "empty results" do
    it "returns an empty result for an empty type list" do
      mail = mail_with("Content-Type: text/plain\n\nHello\n")
      expect(mail.display_body([])).to be_empty
    end

    it "returns an empty result when nothing is displayable" do
      mail = mail_with(<<-MAIL)
        Content-Type: multipart/mixed; boundary=mix

        --mix
        Content-Type: application/pdf
        Content-Disposition: attachment; filename=doc.pdf

        PDFDATA
        --mix--
      MAIL
      result = mail.display_body(%w[text/html text/plain])
      expect(result).to be_empty
      expect(result).not_to be_found
      expect(result.part).to be_nil
      expect(result.resources).to eq []
    end
  end
end
