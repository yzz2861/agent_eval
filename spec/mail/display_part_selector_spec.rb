# encoding: utf-8
# frozen_string_literal: true
require 'spec_helper'

RSpec.describe 'Display part selection' do
  def make_part(content_type, body, headers = {})
    Mail::Part.new(headers.merge(content_type: content_type, body: body))
  end

  it 'selects a single supported part by caller priority' do
    mail = Mail.new
    mail.content_type = 'multipart/alternative'
    mail.add_part(make_part('text/html', '<p>HTML</p>'))
    mail.add_part(make_part('text/plain', 'plain'))

    selection = mail.display_part('text/html', 'text/plain')

    expect(selection.part.body.decoded).to eq '<p>HTML</p>'
    expect(selection.resources).to eq []
    expect(selection).not_to be_empty
    expect(mail.display_body_part('text/html', 'text/plain').part).to eq selection.part
  end

  it 'skips explicitly attached text/html and chooses another display part' do
    mail = Mail.new
    mail.content_type = 'multipart/mixed'
    mail.add_part(make_part('text/html', 'attachment html', content_disposition: 'attachment'))
    mail.add_part(make_part('text/plain', 'display plain'))

    selection = mail.display_part('text/html', 'text/plain')

    expect(selection.part.body.decoded).to eq 'display plain'
  end

  it 'chooses an alternative branch without mixing resources from other branches' do
    plain_cid = make_part('image/png', 'plain image', content_id: '<plain@example>')
    html_cid = make_part('image/png', 'html image', content_id: '<html@example>')
    plain_branch = make_part('multipart/related', nil)
    html_branch = make_part('multipart/related', nil)
    plain_branch.add_part(make_part('text/plain', 'plain'))
    plain_branch.add_part(plain_cid)
    html_branch.add_part(make_part('text/html', '<p>html</p>'))
    html_branch.add_part(html_cid)
    mail = Mail.new
    mail.content_type = 'multipart/alternative'
    mail.add_part(plain_branch)
    mail.add_part(html_branch)

    selection = mail.display_part('text/html', 'text/plain')

    expect(selection.part.body.decoded).to eq '<p>html</p>'
    expect(selection.resources).to eq [html_cid]
    expect(selection.cid_resources).to eq [html_cid]
  end

  it 'does not treat a CID resource MIME type as the alternative root type' do
    html_resource = make_part('text/html', 'resource html', content_id: '<resource@example>')
    plain_related = make_part('multipart/related', nil)
    plain_related.add_part(make_part('text/plain', 'plain root'))
    plain_related.add_part(html_resource)
    html_related = make_part('multipart/related', nil)
    html_related.add_part(make_part('text/html', '<p>html root</p>'))
    mail = Mail.new
    mail.content_type = 'multipart/alternative'
    mail.add_part(plain_related)
    mail.add_part(html_related)

    selection = mail.display_part('text/html', 'text/plain')

    expect(selection.part.body.decoded).to eq '<p>html root</p>'
    expect(selection.resources).to eq []
  end

  it 'uses the related start parameter as the display root' do
    root = make_part('text/html', '<p>root</p>', content_id: '<root@example>')
    other = make_part('text/html', '<p>not root</p>')
    image = make_part('image/png', 'image', content_id: '<image@example>')
    mail = Mail.new
    mail.content_type = 'multipart/related; start="<root@example>"'
    mail.add_part(other)
    mail.add_part(root)
    mail.add_part(image)

    selection = mail.display_part('text/html')

    expect(selection.part).to eq root
    expect(selection.resources).to eq [image]
  end

  it 'accepts a cid URI in the related start parameter' do
    root = make_part('text/html', '<p>root</p>', content_id: '<root@example>')
    mail = Mail.new
    mail.content_type = 'multipart/related; start=cid:<root@example>'
    mail.add_part(make_part('text/html', '<p>not root</p>'))
    mail.add_part(root)

    selection = mail.display_part('text/html')

    expect(selection.part).to eq root
  end

  it 'does not fall back when the related start parameter does not resolve' do
    image = make_part('image/png', 'image', content_id: '<image@example>')
    mail = Mail.new
    mail.content_type = 'multipart/related; start="<missing@example>"'
    mail.add_part(make_part('text/html', '<p>html</p>'))
    mail.add_part(image)

    selection = mail.display_part('text/html')

    expect(selection).to be_empty
  end

  it 'does not use an attachment referenced by the related start parameter' do
    attachment = make_part('text/html', 'attached', content_id: '<attachment@example>',
                                      content_disposition: 'attachment')
    mail = Mail.new
    mail.content_type = 'multipart/related; start="<attachment@example>"'
    mail.add_part(attachment)
    mail.add_part(make_part('text/html', '<p>html</p>'))

    selection = mail.display_part('text/html')

    expect(selection).to be_empty
  end

  it 'falls back to the first related part when start is missing' do
    root = make_part('text/plain', 'plain')
    image = make_part('image/png', 'image', content_id: '<image@example>')
    mail = Mail.new
    mail.content_type = 'multipart/related'
    mail.add_part(root)
    mail.add_part(image)

    selection = mail.display_part('text/html', 'text/plain')

    expect(selection.part).to eq root
    expect(selection.resources).to eq [image]
  end

  it 'does not collect explicit attachments as CID resources' do
    attachment = make_part('image/png', 'attached', content_id: '<attachment@example>',
                                      content_disposition: 'attachment')
    inline = make_part('image/png', 'inline', content_id: '<inline@example>',
                                  content_disposition: 'inline')
    mail = Mail.new
    mail.content_type = 'multipart/related'
    mail.add_part(make_part('text/html', '<p>html</p>'))
    mail.add_part(attachment)
    mail.add_part(inline)

    selection = mail.display_part('text/html')

    expect(selection.resources).to eq [inline]
  end

  it 'collects only CID resources from the selected nested alternative branch' do
    plain = make_part('text/plain', 'plain', content_id: '<plain@example>')
    html = make_part('text/html', '<p>html</p>', content_id: '<html@example>')
    nested_alternative = make_part('multipart/alternative', nil)
    nested_alternative.add_part(plain)
    nested_alternative.add_part(html)
    mail = Mail.new
    mail.content_type = 'multipart/related'
    mail.add_part(make_part('text/html', '<p>root</p>'))
    mail.add_part(nested_alternative)

    selection = mail.display_part('text/html', 'text/plain')

    expect(selection.resources).to eq [html]
  end

  it 'collects CID resources from a generic multipart root wrapper' do
    image = make_part('image/png', 'image', content_id: '<image@example>')
    root_wrapper = make_part('multipart/mixed', nil)
    root_wrapper.add_part(make_part('text/html', '<p>html</p>'))
    root_wrapper.add_part(image)
    mail = Mail.new
    mail.content_type = 'multipart/related'
    mail.add_part(root_wrapper)

    selection = mail.display_part('text/html')

    expect(selection.part.body.decoded).to eq '<p>html</p>'
    expect(selection.resources).to eq [image]
  end

  it 'returns a CID multipart resource without entering its alternatives' do
    plain = make_part('text/plain', 'plain', content_id: '<plain@example>')
    html = make_part('text/html', '<p>html</p>', content_id: '<html@example>')
    nested_alternative = make_part('multipart/alternative', nil,
                                   content_id: '<alternative@example>')
    nested_alternative.add_part(plain)
    nested_alternative.add_part(html)
    mail = Mail.new
    mail.content_type = 'multipart/related'
    mail.add_part(make_part('text/html', '<p>root</p>'))
    mail.add_part(nested_alternative)

    selection = mail.display_part('text/html', 'text/plain')

    expect(selection.resources).to eq [nested_alternative]
  end

  it 'does not search inside nested message/rfc822 parts' do
    nested = make_part('message/rfc822', "Content-Type: text/html\r\n\r\n<p>nested</p>")
    mail = Mail.new
    mail.content_type = 'multipart/mixed'
    mail.add_part(nested)

    selection = mail.display_part('text/html')

    expect(selection).to be_empty
    expect(selection.part).to be_nil
    expect(selection.resources).to eq []
  end

  it 'can select a supported message/rfc822 part without descending into it' do
    nested = make_part('message/rfc822', "Content-Type: text/html\r\n\r\n<p>nested</p>")
    mail = Mail.new
    mail.add_part(nested)

    part_selection, resources = mail.display_part('message/rfc822')

    expect(part_selection).to eq nested
    expect(resources).to eq []
  end

  it 'returns an explicit empty result when no supported display part exists' do
    mail = Mail.new
    mail.content_type = 'multipart/mixed'
    mail.add_part(make_part('application/pdf', 'pdf', content_disposition: 'attachment'))

    selection = mail.display_part('text/html', 'text/plain')

    expect(selection).to be_empty
    expect(selection.to_a).to eq [nil, []]
  end

  it 'traverses an untyped container that actually has parts' do
    container = make_part('multipart/mixed', nil)
    container.header['content-type'] = nil
    container.add_part(make_part('text/plain', 'plain'))
    mail = Mail.new
    mail.add_part(container)

    selection = mail.display_part('text/plain')

    expect(selection.part.body.decoded).to eq 'plain'
  end

  it 'does not select an empty supported part' do
    mail = Mail.new("Subject: Empty\r\n\r\n")

    selection = mail.display_part('text/plain')

    expect(selection).to be_empty
  end

  it 'requires at least one displayable MIME type' do
    expect { Mail.new.display_part }.to raise_error(ArgumentError)
  end

  it 'accepts supported types as an array' do
    mail = Mail.new
    mail.content_type = 'multipart/alternative'
    mail.add_part(make_part('text/plain', 'plain'))
    mail.add_part(make_part('text/html', '<p>html</p>'))

    selection = mail.display_part(['text/html', 'text/plain'])

    expect(selection.part.body.decoded).to eq '<p>html</p>'
  end
end
