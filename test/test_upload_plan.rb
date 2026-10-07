# Standalone tests for Net::SFTP::Operations::UploadPlan and its Executor.
#
# These tests deliberately avoid the net-ssh/mocha based harness in
# test/common.rb: they build real directory trees (with symlinks and hard
# links) in a temporary directory and drive the executor with a fake SFTP
# session whose responses can be completed in any order.

require 'minitest/autorun'
require 'tmpdir'

$LOAD_PATH.unshift File.expand_path('../../lib', __FILE__)
require 'net/sftp/operations/upload_plan'

class UploadPlanTest < Minitest::Test
  UploadPlan = Net::SFTP::Operations::UploadPlan

  # A fake SFTP session that queues every request and lets the test
  # complete them in any order, simulating concurrent, out-of-order
  # server responses.
  class FakeSftp
    Request = Struct.new(:action, :args, :callback)

    class Response
      def initialize(ok, data={})
        @ok, @data = ok, data
      end

      def ok?; @ok; end
      def [](key); @data[key]; end
      def code; @ok ? 0 : 4; end
      def message; @ok ? "" : "failure"; end
    end

    attr_reader :issued, :pending

    def initialize
      @issued = [] # [[action, args], ...] in issue order
      @pending = []
      @handle_seq = 0
    end

    def mkdir(path, &cb)           issue(:mkdir, [path], cb) end
    def rmdir(path, &cb)           issue(:rmdir, [path], cb) end
    def remove(path, &cb)          issue(:remove, [path], cb) end
    def setstat(path, attrs, &cb)  issue(:setstat, [path, attrs], cb) end
    def symlink(target, link, &cb) issue(:symlink, [target, link], cb) end
    def link(new, existing, symlink, &cb) issue(:link, [new, existing, symlink], cb) end
    def open(path, flags, &cb)     issue(:open, [path, flags], cb) end
    def write(handle, offset, data, &cb) issue(:write, [handle, offset, data], cb) end
    def close(handle, &cb)         issue(:close, [handle], cb) end

    def issue(action, args, cb)
      @issued << [action, args]
      request = Request.new(action, args, cb)
      @pending << request
      request
    end

    def complete(request, ok=true)
      @pending.delete(request) or raise "request not pending: #{request.inspect}"
      data = request.action == :open ? { :handle => "handle#{@handle_seq += 1}" } : {}
      request.callback.call(Response.new(ok, data))
    end

    def complete_next(action=nil, ok=true)
      request = action ? @pending.find { |r| r.action == action } : @pending.first
      raise "no pending request for #{action.inspect}" unless request
      complete(request, ok)
    end

    def pending_for(action)
      @pending.select { |r| r.action == action }
    end

    def run_until_idle
      complete_next until @pending.empty?
    end

    def issued_actions
      @issued.map { |action, _| action }
    end
  end

  def with_tree
    Dir.mktmpdir do |dir|
      yield dir
    end
  end

  def steps_of(plan, klass)
    plan.steps.select { |s| s.is_a?(klass) }
  end

  def test_symlinks_are_preserved_verbatim_and_loops_do_not_recurse
    with_tree do |dir|
      File.write(File.join(dir, "target.txt"), "data")
      File.symlink("target.txt", File.join(dir, "rel_link"))
      File.symlink("loop_b", File.join(dir, "loop_a"))
      File.symlink("loop_a", File.join(dir, "loop_b"))
      Dir.mkdir(File.join(dir, "subdir"))
      File.symlink("subdir", File.join(dir, "dir_link"))

      plan = UploadPlan.build(dir, "/remote/root", :mkdir => true)
      symlinks = steps_of(plan, UploadPlan::Symlink)
      assert_equal 4, symlinks.length

      targets = {}
      symlinks.each { |s| targets[s.remote] = s.target }
      assert_equal "target.txt", targets["/remote/root/rel_link"]
      assert_equal "loop_b", targets["/remote/root/loop_a"]
      assert_equal "loop_a", targets["/remote/root/loop_b"]
      assert_equal "subdir", targets["/remote/root/dir_link"]

      # the symlink loop was not followed: nothing below the links
      refute plan.steps.any? { |s| s.respond_to?(:remote) && s.remote.include?("loop_a/") }
      assert_equal 1, steps_of(plan, UploadPlan::Mkdir).count { |s| s.remote == "/remote/root/subdir" }

      fake = FakeSftp.new
      executor = plan.execute(fake)
      fake.run_until_idle
      refute executor.failed?

      sent = fake.issued.select { |action, _| action == :symlink }.map { |_, args| args }
      assert_equal 4, sent.length
      assert_includes sent, ["loop_b", "/remote/root/loop_a"]
      assert_includes sent, ["loop_a", "/remote/root/loop_b"]
      assert_includes sent, ["target.txt", "/remote/root/rel_link"]
      assert_equal 1, fake.issued.count { |action, _| action == :open },
        "only the real file may be uploaded; links must not be followed"
    end
  end

  def test_hardlink_aliases_upload_one_entity_then_link
    with_tree do |dir|
      File.write(File.join(dir, "orig.txt"), "shared contents")
      File.link(File.join(dir, "orig.txt"), File.join(dir, "alias1.txt"))
      File.link(File.join(dir, "orig.txt"), File.join(dir, "alias2.txt"))

      plan = UploadPlan.build(dir, "/r")
      uploads = steps_of(plan, UploadPlan::UploadFile)
      links = steps_of(plan, UploadPlan::Hardlink)
      assert_equal 1, uploads.length
      assert_equal 2, links.length
      links.each do |link|
        assert_includes link.dependencies, uploads.first
        assert_equal uploads.first.remote, link.existing
      end

      fake = FakeSftp.new
      executor = plan.execute(fake)
      fake.run_until_idle
      refute executor.failed?

      assert_equal 1, fake.issued.count { |action, _| action == :open },
        "inode must be uploaded exactly once"
      sent = fake.issued.select { |action, _| action == :link }.map { |_, args| args }
      assert_equal 2, sent.length
      aliases = links.map(&:remote).sort
      sent.each do |new_path, existing, symlink_flag|
        assert_equal uploads.first.remote, existing
        assert_equal false, symlink_flag
        assert_includes aliases, new_path
      end

      close_index = fake.issued_actions.index(:close)
      fake.issued_actions.each_with_index do |action, i|
        assert i > close_index, "hard link issued before entity upload finished" if action == :link
      end
    end
  end

  def test_hardlink_strategy_upload_degrades_aliases_to_independent_files
    with_tree do |dir|
      File.write(File.join(dir, "orig.txt"), "shared contents")
      File.link(File.join(dir, "orig.txt"), File.join(dir, "alias.txt"))

      plan = UploadPlan.build(dir, "/r", :hardlinks => :upload)
      assert_equal 2, steps_of(plan, UploadPlan::UploadFile).length
      assert_equal 0, steps_of(plan, UploadPlan::Hardlink).length

      fake = FakeSftp.new
      plan.execute(fake)
      fake.run_until_idle
      assert_equal 2, fake.issued.count { |action, _| action == :open }
      refute fake.issued_actions.include?(:link)
    end
  end

  def test_resolve_hardlink_strategy
    assert_equal :link, UploadPlan.resolve_hardlink_strategy(true, :error)
    assert_equal :link, UploadPlan.resolve_hardlink_strategy(true, nil)
    assert_equal :upload, UploadPlan.resolve_hardlink_strategy(false, :upload)
    assert_equal :upload, UploadPlan.resolve_hardlink_strategy(true, :upload)
    assert_raises(UploadPlan::Error) { UploadPlan.resolve_hardlink_strategy(false, :error) }
    assert_raises(UploadPlan::Error) { UploadPlan.resolve_hardlink_strategy(false, nil) }
    assert_raises(ArgumentError) { UploadPlan.resolve_hardlink_strategy(true, :bogus) }
  end
  def test_failed_entity_upload_skips_dependent_links
    with_tree do |dir|
      File.write(File.join(dir, "a.txt"), "shared")
      File.link(File.join(dir, "a.txt"), File.join(dir, "b.txt"))
      File.write(File.join(dir, "c.txt"), "independent")

      plan = UploadPlan.build(dir, "/r")
      events = []
      fake = FakeSftp.new
      executor = plan.execute(fake, :requests => 4) { |event, _, *| events << event }

      # both entity uploads start concurrently
      assert_equal 2, fake.pending_for(:open).length
      fake.complete_next(:open) # a.txt -> issues write
      fake.complete_next(:open) # c.txt -> issues write

      # the entity upload of the a.txt/b.txt inode group fails mid-write
      fake.complete_next(:write, false)
      fake.run_until_idle

      assert executor.failed?
      hardlink = steps_of(plan, UploadPlan::Hardlink).first
      assert_equal :skipped, hardlink.state
      refute fake.issued_actions.include?(:link), "dependent hard link must never be issued"
      assert_includes events, :skip

      # the independent file still finished uploading
      assert fake.issued.any? { |action, args| action == :open && args[0] == "/r/c.txt" }
      assert fake.issued.any? { |action, args| action == :setstat && args[0] == "/r/c.txt" }

      error = assert_raises(UploadPlan::ExecutionFailed) { executor.raise_if_failed }
      assert_match(/write/, error.message)
      refute executor.active?
    end
  end

  def test_concurrent_completion_order_is_respected
    with_tree do |dir|
      File.write(File.join(dir, "f1.txt"), "one")
      File.link(File.join(dir, "f1.txt"), File.join(dir, "f1_alias.txt"))
      File.write(File.join(dir, "f2.txt"), "two")
      File.link(File.join(dir, "f2.txt"), File.join(dir, "f2_alias.txt"))

      plan = UploadPlan.build(dir, "/r")
      fake = FakeSftp.new
      executor = plan.execute(fake, :requests => 8)

      # both entity files open concurrently
      assert_equal 2, fake.pending_for(:open).length
      fake.complete_next(:open) # f1.txt gets handle1
      fake.complete_next(:open) # f2.txt gets handle2
      fake.complete_next(:write)
      fake.complete_next(:write)

      # complete f2's close before f1's (out of order)
      close_f2 = fake.pending_for(:close).find { |r| r.args == ["handle2"] }
      fake.complete(close_f2)

      links = fake.issued.select { |action, _| action == :link }.map { |_, args| args }
      assert_equal 1, links.length
      assert_equal ["/r/f2_alias.txt", "/r/f2.txt", false], links.first
      refute fake.issued.any? { |action, args| action == :link && args[0] == "/r/f1_alias.txt" },
        "f1's alias must wait for f1's own upload to finish"

      fake.run_until_idle
      refute executor.failed?
      links = fake.issued.select { |action, _| action == :link }.map { |_, args| args }
      assert_equal 2, links.length
      assert_includes links, ["/r/f1_alias.txt", "/r/f1.txt", false]
    end
  end

  def test_directories_first_and_permissions_last
    with_tree do |dir|
      Dir.mkdir(File.join(dir, "sub"))
      File.write(File.join(dir, "sub", "inner.txt"), "inner")
      File.write(File.join(dir, "top.txt"), "top")

      plan = UploadPlan.build(dir, "/r", :mkdir => true)
      fake = FakeSftp.new
      executor = plan.execute(fake)
      fake.run_until_idle
      refute executor.failed?

      actions = fake.issued_actions
      root_mkdir = fake.issued.index { |a, args| a == :mkdir && args[0] == "/r" }
      sub_mkdir = fake.issued.index { |a, args| a == :mkdir && args[0] == "/r/sub" }
      inner_open = fake.issued.index { |a, args| a == :open && args[0] == "/r/sub/inner.txt" }
      assert root_mkdir < sub_mkdir, "parent directory must be created first"
      assert sub_mkdir < inner_open, "directory must exist before its contents"

      last_content = [:open, :write, :close, :mkdir].map { |a| actions.rindex(a) }.compact.max
      first_chmod = actions.index(:setstat)
      assert first_chmod > last_content, "permissions must be applied after all content"

      mode = File.stat(File.join(dir, "top.txt")).mode & 07777
      assert fake.issued.any? { |a, args| a == :setstat && args[0] == "/r/top.txt" && args[1] == { :permissions => mode } }
      assert fake.issued.any? { |a, args| a == :setstat && args[0] == "/r/sub" }
    end
  end

  def test_remote_type_conflict_is_removed_first_by_default
    with_tree do |dir|
      File.write(File.join(dir, "file.txt"), "contents")
      Dir.mkdir(File.join(dir, "subdir"))

      remote = { "/r/file.txt" => :directory, "/r/subdir" => :file }
      probe = lambda { |path| remote[path] }
      plan = UploadPlan.build(dir, "/r", :remote_type => probe)

      removes = steps_of(plan, UploadPlan::RemoveRemote)
      assert_equal 2, removes.length

      remove_dir = removes.find { |r| r.remote == "/r/file.txt" }
      assert_equal :directory, remove_dir.type
      upload = steps_of(plan, UploadPlan::UploadFile).first
      assert_includes upload.dependencies, remove_dir

      remove_file = removes.find { |r| r.remote == "/r/subdir" }
      assert_equal :file, remove_file.type
      mkdir = steps_of(plan, UploadPlan::Mkdir).find { |m| m.remote == "/r/subdir" }
      assert_includes mkdir.dependencies, remove_file

      fake = FakeSftp.new
      plan.execute(fake)
      fake.run_until_idle
      assert_includes fake.issued, [:rmdir, ["/r/file.txt"]]
      assert_includes fake.issued, [:remove, ["/r/subdir"]]
      assert fake.issued.index { |a, _| a == :rmdir } < fake.issued.index { |a, _| a == :open },
        "conflicting object must be removed before its replacement is created"
    end
  end

  def test_remote_type_conflict_with_error_policy_raises
    with_tree do |dir|
      File.write(File.join(dir, "file.txt"), "contents")
      probe = lambda { |path| path == "/r/file.txt" ? :directory : nil }

      error = assert_raises(UploadPlan::ConflictError) do
        UploadPlan.build(dir, "/r", :remote_type => probe, :on_conflict => :error)
      end
      assert_equal 1, error.conflicts.length
      assert_match(%r{/r/file.txt}, error.message)
      assert_match(/directory/, error.message)
    end
  end

  def test_existing_remote_directory_needs_no_mkdir
    with_tree do |dir|
      File.write(File.join(dir, "file.txt"), "contents")
      probe = lambda { |path| path == "/r" ? :directory : nil }
      plan = UploadPlan.build(dir, "/r", :mkdir => true, :remote_type => probe)
      refute steps_of(plan, UploadPlan::Mkdir).any? { |m| m.remote == "/r" }
    end
  end

  def test_unsupported_special_file_raises
    with_tree do |dir|
      assert system("mkfifo", File.join(dir, "pipe")), "mkfifo failed"
      assert_raises(UploadPlan::Error) { UploadPlan.build(dir, "/r") }
    end
  end

  def test_progress_events_are_reported
    with_tree do |dir|
      File.write(File.join(dir, "file.txt"), "contents")
      File.link(File.join(dir, "file.txt"), File.join(dir, "alias.txt"))
      File.symlink("file.txt", File.join(dir, "link"))

      events = []
      plan = UploadPlan.build(dir, "/r", :mkdir => true)
      fake = FakeSftp.new
      executor = plan.execute(fake) { |event, _, *| events << event }
      fake.run_until_idle
      refute executor.failed?

      [:mkdir, :open, :put, :close, :symlink, :link, :chmod].each do |event|
        assert_includes events, event
      end
      assert_equal :finish, events.last
    end
  end

  def test_readable_plan_rendering
    with_tree do |dir|
      File.write(File.join(dir, "index.html"), "<html></html>")
      Dir.mkdir(File.join(dir, "logs"))
      File.write(File.join(dir, "logs", "current.log"), "log")
      File.link(File.join(dir, "logs", "current.log"), File.join(dir, "logs", "archive.log"))
      File.symlink("logs/current.log", File.join(dir, "latest"))

      plan = UploadPlan.build(dir, "/var/www/site", :mkdir => true)
      text = plan.to_s

      assert_match(/^upload plan: #{Regexp.escape(dir)} -> \/var\/www\/site \(\d+ steps\)/, text)
      assert_includes text, "symlink   /var/www/site/latest -> logs/current.log"
      # archive.log sorts before current.log, so it becomes the uploaded entity
      assert_includes text, "hardlink  /var/www/site/logs/current.log => /var/www/site/logs/archive.log"
      assert_match(/hardlink.*\[after \d+, \d+\]/, text)
      assert_match(/chmod     0\d{3} \/var\/www\/site/, text)

      # a readable example of a generated plan, visible in test output:
      puts "", text
    end
  end
end
