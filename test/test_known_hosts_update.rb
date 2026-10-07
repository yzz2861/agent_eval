require_relative './common'
require 'tmpdir'

class TestKnownHostsUpdate < NetSSHTest
  HOST = 'rotated.example.com'
  OTHER = 'other.example.com'

  def setup
    @dir = Dir.mktmpdir('net-ssh-known-hosts')
    @file = File.join(@dir, 'known_hosts')
  end

  def teardown
    FileUtils.remove_entry(@dir) if @dir && File.directory?(@dir)
  end

  def make_key
    OpenSSL::PKey::RSA.new(2048)
  end

  def blob(key)
    [key.to_blob].pack('m*').gsub(/\s/, '')
  end

  def line(host, key)
    "#{host} #{key.ssh_type} #{blob(key)}\n"
  end

  def write_known_hosts(content)
    File.write(@file, content)
  end

  def read_known_hosts
    File.read(@file)
  end

  def test_replace_removes_old_key_for_host_and_adds_new
    old_key = make_key
    new_key = make_key
    write_known_hosts(line(HOST, old_key))

    result = Net::SSH::KnownHosts.new(@file).replace_keys(HOST, [new_key], [old_key])

    assert(result)
    content = read_known_hosts
    refute_includes(content, blob(old_key))
    assert_includes(content, blob(new_key))
    assert_equal(1, content.lines.count)
  end

  def test_replace_preserves_unrelated_host_keys
    old_key = make_key
    new_key = make_key
    other_key = make_key
    write_known_hosts(line(HOST, old_key) + line(OTHER, other_key))

    Net::SSH::KnownHosts.new(@file).replace_keys(HOST, [new_key], [old_key])

    content = read_known_hosts
    assert_includes(content, blob(other_key))
    assert_includes(content, OTHER)
    refute_includes(content, blob(old_key))
  end

  def test_replace_preserves_shared_alias_line
    # A line listing the rotated host together with an unrelated alias must
    # never be deleted: not all of its patterns belong to the target host.
    old_key = make_key
    new_key = make_key
    shared = make_key
    write_known_hosts("#{HOST},#{OTHER} #{shared.ssh_type} #{blob(shared)}\n" + line(HOST, old_key))

    Net::SSH::KnownHosts.new(@file).replace_keys(HOST, [new_key], [old_key, shared])

    content = read_known_hosts
    assert_includes(content, blob(shared))
    assert_includes(content, "#{HOST},#{OTHER}")
  end

  def test_replace_removes_hashed_host_entry
    old_key = make_key
    new_key = make_key
    hashed = hashed_host_line(HOST, old_key)
    write_known_hosts(hashed + line(OTHER, make_key))

    Net::SSH::KnownHosts.new(@file).replace_keys(HOST, [new_key], [old_key])

    content = read_known_hosts
    refute_includes(content, blob(old_key))
    assert_includes(content, blob(new_key))
    assert_includes(content, OTHER)
  end

  def test_replace_does_not_remove_hashed_entry_for_other_host
    old_key = make_key
    new_key = make_key
    hashed = hashed_host_line(OTHER, old_key)
    write_known_hosts(hashed)

    Net::SSH::KnownHosts.new(@file).replace_keys(HOST, [new_key], [old_key])

    content = read_known_hosts
    assert_includes(content, blob(old_key))
  end

  def test_replace_scoped_to_nonstandard_port
    old_key = make_key
    new_key = make_key
    write_known_hosts(line(HOST, old_key) + line("[#{HOST}]:2222", old_key))

    Net::SSH::KnownHosts.new(@file).replace_keys("[#{HOST}]:2222", [new_key], [old_key])

    content = read_known_hosts
    assert_includes(content, "#{HOST} #{old_key.ssh_type}")
    port_lines = content.lines.select { |line| line.start_with?("[#{HOST}]:2222 ") }
    assert_equal(1, port_lines.count)
    assert_includes(port_lines.first, blob(new_key))
    refute_includes(port_lines.first, blob(old_key))
  end

  def test_replace_without_changes_returns_false_and_keeps_file
    key = make_key
    write_known_hosts(line(HOST, key))
    original = read_known_hosts

    result = Net::SSH::KnownHosts.new(@file).replace_keys(HOST, [], [])

    refute(result)
    assert_equal(original, read_known_hosts)
  end

  def test_replace_does_not_duplicate_existing_new_key
    old_key = make_key
    write_known_hosts(line(HOST, old_key) + line(HOST, make_key))
    present_key = Net::SSH::KnownHosts.new(@file).keys_for(HOST).last

    Net::SSH::KnownHosts.new(@file).replace_keys(HOST, [present_key], [old_key])

    content = read_known_hosts
    assert_equal(1, content.lines.count { |line| line.include?(blob(present_key)) })
  end

  def test_class_replace_only_touches_file_that_knows_host
    old_key = make_key
    new_key = make_key
    write_known_hosts(line(HOST, old_key))
    options = { user_known_hosts_file: [@file], global_known_hosts_file: [] }

    result = Net::SSH::KnownHosts.replace(HOST, [new_key], [old_key], options)

    assert(result)
    assert_includes(read_known_hosts, blob(new_key))
  end

  def test_class_replace_raises_when_all_writes_fail_and_keeps_file
    old_key = make_key
    new_key = make_key
    write_known_hosts(line(HOST, old_key))
    File.chmod(0o444, @file)
    File.chmod(0o555, @dir) unless Process.uid.zero?
    options = { user_known_hosts_file: [@file], global_known_hosts_file: [] }

    if Process.uid.zero?
      skip 'cannot make known_hosts file unwritable in this environment'
    end

    assert_raises(SystemCallError) do
      Net::SSH::KnownHosts.replace(HOST, [new_key], [old_key], options)
    end
    File.chmod(0o755, @dir)
    File.chmod(0o644, @file)
    assert_includes(read_known_hosts, blob(old_key))
    refute_includes(read_known_hosts, blob(new_key))
  ensure
    begin
      File.chmod(0o755, @dir)
      File.chmod(0o644, @file)
    rescue SystemCallError
      nil
    end
  end

  private

  def hashed_host_line(host, key)
    salt = OpenSSL::Random.random_bytes(20)
    hmac = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha1'), salt, host)
    hashed = "|1|#{[salt].pack('m0')}|#{[hmac].pack('m0')}"
    "#{hashed} #{key.ssh_type} #{blob(key)}\n"
  end
end
