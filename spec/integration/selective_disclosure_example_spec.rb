# frozen_string_literal: true

RSpec.describe 'examples/selective_disclosure.rb' do
  it 'runs the offline issue / present / verify flow' do
    script = File.expand_path('../../examples/selective_disclosure.rb', __dir__)
    output = IO.popen(['ruby', script], err: %i[child out], &:read)

    expect($?).to be_success
    expect(output).to include('1) Issued', '2) Holder', '3) Verified')
    expect(output).to include('"given_name": "Ada"')
    expect(output).to include('"FR"')
    verified_section = output.split('3) Verified').last.split('Revealed keys').first
    expect(verified_section).not_to include('Lovelace', 'Calculator Row')
    expect(verified_section).to include('"FR"')
    expect(verified_section).to match(/"nationalities":\s*\[\s*"FR"\s*\]/)
    expect(output).to include('Ordinary JWT.decode rejects the format')
  end
end
