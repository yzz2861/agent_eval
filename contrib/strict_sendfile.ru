# frozen_string_literal: true

# Demonstration of Rack::Sendfile strict mapping mode.
#
# The application declares exactly one allowed directory and the internal
# URI prefix the proxy maps it to. Request headers cannot widen the mapping,
# symlinks escaping the directory are rejected, and anything outside the
# declared roots falls back or is rejected depending on +on_miss+.
#
# Run a self-contained demonstration:
#
#   ruby contrib/strict_sendfile.ru
#
# Or serve it behind a real proxy:
#
#   rackup contrib/strict_sendfile.ru
#
# Matching nginx configuration:
#
#   location /files/ {
#     internal;
#     alias /path/to/demo/files/;
#   }

require 'fileutils'
require_relative '../lib/rack'

# Keep the demo tree next to this file so File.realpath can always resolve
# it, even in sandboxes where the system temp dir is restricted.
DEMO_ROOT = File.join(__dir__, 'tmp', 'strict-sendfile-demo')
FileUtils.rm_rf DEMO_ROOT
FILES_DIR = File.join(DEMO_ROOT, 'files')
FileUtils.mkdir_p FILES_DIR

File.write(File.join(FILES_DIR, 'hello.txt'), "served from the declared root\n")
File.write(File.join(FILES_DIR, '报告 final%.txt'), "unicode, space and percent in name\n")
File.write(File.join(DEMO_ROOT, 'secret.txt'), "outside the declared root\n")
File.symlink(File.join(DEMO_ROOT, 'secret.txt'), File.join(FILES_DIR, 'secret-link.txt'))

app = Rack::Sendfile.new(
  # Use a binary-encoded root so non-ASCII request paths join cleanly even
  # when the working directory itself contains non-ASCII characters.
  Rack::Files.new(FILES_DIR.b),
  'x-accel-redirect',
  [[FILES_DIR, '/files/']],
  strict: true,
  on_miss: :reject
)

run app if respond_to?(:run)

if __FILE__ == $0
  at_exit { FileUtils.remove_entry_secure DEMO_ROOT }

  show = lambda do |path|
    status, headers, body = app.call(Rack::MockRequest.env_for(path))
    body.close if body.respond_to?(:close)
    puts format('%-28s -> %d  x-accel-redirect: %s', path, status, headers['x-accel-redirect'].inspect)
  end

  puts "Declared root: #{FILES_DIR} -> /files/"
  show.call('/hello.txt')
  show.call(Rack::Utils.escape_path('/报告 final%.txt'))
  show.call('/secret-link.txt')
  show.call('/../secret.txt')
end
