require "tmpdir"
require "fileutils"
require "common"

class UploadLinksTest < Net::SFTP::TestCase
  class FakeProtocol
    attr_reader :version

    def initialize(version)
      @version = version
    end
  end

  class FakeRequest
    attr_reader :type, :id
    attr_accessor :response

    def initialize(sftp, type, callback)
      @sftp = sftp
      @type = type
      @callback = callback
      @id = sftp.next_id
      @properties = {}
    end

    def [](key)
      @properties[key.to_sym]
    end

    def []=(key, value)
      @properties[key.to_sym] = value
    end

    def session
      @sftp
    end

    def invoke(response)
      @response = response
      @callback.call(response)
    end
  end

  class FakeResponse
    include Net::SFTP::Constants::StatusCodes

    Attrs = Struct.new(:permissions) do
      def symbolic_type
        value = permissions || 0
        if value & 0o120000 == 0o120000
          :symlink
        elsif value & 0o40000 == 0o40000
          :directory
        elsif value & 0o100000 == 0o100000
          :regular
        else
          :unknown
        end
      end
    end

    attr_reader :code, :request

    def initialize(request, code, data={})
      @request = request
      @code = code
      @data = data
    end

    def [](key)
      @data[key.to_sym]
    end

    def ok?
      code == FX_OK
    end

    def message
      nil
    end
  end

  class FakeSFTP
    Attrs = FakeResponse::Attrs

    attr_reader :protocol, :extensions, :calls, :entries, :handles, :contents, :fail_open
    attr_accessor :reverse_completion

    def initialize(version=6, extensions={}, fail_open=[])
      @protocol = FakeProtocol.new(version)
      @extensions = extensions
      @fail_open = fail_open
      @reverse_completion = false
      @entries = {}
      @handles = {}
      @contents = {}
      @calls = []
      @id = 0
      @queued = []
      @logger = Logger.new(nil)
    end

    def logger
      @logger
    end

    def next_id
      @id += 1
    end

    def loop
      until @queued.empty?
        pending = @queued
        @queued = []
        pending = pending.reverse if reverse_completion
        pending.each(&:call)
      end
    end

    def lstat(path, flags=nil, &callback)
      record(:lstat, path)
      enqueue(callback) do |request|
        entry = entries[path]
        if entry
          FakeResponse.new(request, 0, :attrs => Attrs.new(entry[:mode]))
        else
          FakeResponse.new(request, Net::SFTP::Constants::StatusCodes::FX_NO_SUCH_FILE)
        end
      end
    end

    def mkdir(path, attrs={}, &callback)
      record(:mkdir, path, attrs)
      enqueue(callback) do |request|
        entries[path] = { :type => :directory, :mode => 0o40700 }
        FakeResponse.new(request, 0)
      end
    end

    def open(path, flags="r", options={}, &callback)
      record(:open, path, flags, options)
      enqueue(callback) do |request|
        if fail_open.include?(path)
          FakeResponse.new(request, Net::SFTP::Constants::StatusCodes::FX_FAILURE)
        else
          handle = "h#{next_id}"
          handles[handle] = path
          contents[path] = String.new
          entries[path] = { :type => :regular, :mode => 0o100644 }
          FakeResponse.new(request, 0, :handle => handle)
        end
      end
    end

    def write(handle, offset, data, &callback)
      record(:write, handles[handle], offset, data)
      enqueue(callback) do |request|
        contents[handles[handle]][offset, data.bytesize] = data
        FakeResponse.new(request, 0)
      end
    end

    def close(handle, &callback)
      path = handles.delete(handle)
      record(:close, path)
      enqueue(callback) { |request| FakeResponse.new(request, 0) }
    end

    def remove(path, &callback)
      record(:remove, path)
      enqueue(callback) do |request|
        entries.delete(path)
        FakeResponse.new(request, 0)
      end
    end

    def symlink(target, link, &callback)
      record(:symlink, link, target)
      enqueue(callback) do |request|
        entries[link] = { :type => :symlink, :mode => 0o120777, :target => target }
        FakeResponse.new(request, 0)
      end
    end

    def link(link, target, symlink=true, &callback)
      record(symlink ? :symlink : :hardlink, link, target)
      enqueue(callback) do |request|
        if symlink
          entries[link] = { :type => :symlink, :mode => 0o120777, :target => target }
        else
          entries[link] = entries.fetch(target).merge(:alias_for => target)
        end
        FakeResponse.new(request, 0)
      end
    end

    def hardlink(link, target, &callback)
      link(link, target, false, &callback)
    end

    def hardlink_supported?
      protocol.version >= 6 || extensions.any?
    end

    def setstat(path, attrs, &callback)
      record(:setstat, path, attrs)
      enqueue(callback) do |request|
        entries[path][:mode] = 0o100000 | attrs[:permissions] if entries.dig(path, :type) == :regular
        entries[path][:mode] = 0o40000 | attrs[:permissions] if entries.dig(path, :type) == :directory
        FakeResponse.new(request, 0)
      end
    end

    private
      def record(*call)
        @calls << call
      end

      def enqueue(callback)
        request = FakeRequest.new(self, :fake, callback)
        @queued << proc { request.invoke(yield(request)) }
        request
      end
  end

  def test_plan_preserves_link_loops_relative_symlinks_and_hard_link_aliases
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      destination = "/remote/root"
      create_linked_tree(source)
      sftp = FakeSFTP.new(6)

      upload = Net::SFTP::Operations::Upload.new(sftp, source, destination, :mkdir => true, :requests => 2)
      assert_match(%r{symlink.*rel-self -> ../a}, upload.plan.to_s)
      assert_match(%r{hardlink .*b => .*a}, upload.plan.to_s)

      sftp.reverse_completion = true
      upload.wait

      assert_empty sftp.handles
      assert_equal "../a", sftp.entries[File.join(destination, "loop", "rel-self")][:target]
      assert_equal "loop", sftp.entries[File.join(destination, "loop", "self-dir")][:target]
      assert_equal File.join(destination, "a"), sftp.entries[File.join(destination, "nested", "b")][:alias_for]
      assert_equal 0o40755, sftp.entries[destination][:mode]
      assert_equal 0o40750, sftp.entries[File.join(destination, "nested")][:mode]
      assert_equal 0o100644, sftp.entries[File.join(destination, "a")][:mode]
    end
  end

  def test_plan_is_readable_before_execution
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      create_linked_tree(source)
      plan = Net::SFTP::Operations::Upload::Plan.build(source, "/remote/root", :create_root => true)
      output = plan.to_s

      assert_includes output, "mkdir    /remote/root"
      assert_includes output, "upload   #{File.join(source, 'a')} -> /remote/root/a"
      assert_includes output, "hardlink /remote/root/nested/b => /remote/root/a"
      assert_includes output, "symlink  /remote/root/loop/rel-self -> ../a"
      assert_includes output, "setstat  /remote/root mode 0755"
    end
  end

  def test_hard_links_can_explicitly_degrade_to_independent_files_on_v3
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      create_linked_tree(source)
      sftp = FakeSFTP.new(3)

      upload = Net::SFTP::Operations::Upload.new(sftp, source, "/remote/root",
        :mkdir => true, :on_unsupported_hard_links => :copy)
      upload.wait

      refute_includes sftp.calls.map(&:first), :hardlink
      assert_includes sftp.calls.map { |call| call[1] if call[0] == :open }, "/remote/root/a"
      assert_includes sftp.calls.map { |call| call[1] if call[0] == :open }, "/remote/root/nested/b"
      assert_equal "content", sftp.contents["/remote/root/a"]
      assert_equal :regular, sftp.entries["/remote/root/nested/b"][:type]
    end
  end

  def test_unsupported_hard_links_raise_before_remote_execution
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      create_linked_tree(source)
      sftp = FakeSFTP.new(3)

      error = assert_raises(NotImplementedError) do
        Net::SFTP::Operations::Upload.new(sftp, source, "/remote/root", :mkdir => true)
      end
      assert_match(/hard links/, error.message)
      assert_empty sftp.calls
    end
  end

  def test_remote_type_conflict_aborts_before_mutation
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      create_linked_tree(source)
      sftp = FakeSFTP.new(6)
      sftp.entries["/remote/root/a"] = { :type => :directory, :mode => 0o40755 }

      upload = Net::SFTP::Operations::Upload.new(sftp, source, "/remote/root", :mkdir => true)
      error = assert_raises(Net::SFTP::RemoteTypeConflict) { upload.wait }
      assert_equal "/remote/root/a", error.path
      refute_includes sftp.calls.map(&:first), :mkdir
    end
  end

  def test_existing_same_type_symlink_is_replaced_before_recreated
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      create_linked_tree(source)
      sftp = FakeSFTP.new(6)
      target = File.join("/remote/root", "loop", "rel-self")
      sftp.entries[target] = { :type => :symlink, :mode => 0o120777, :target => "old" }

      Net::SFTP::Operations::Upload.new(sftp, source, "/remote/root", :mkdir => true).wait

      actions = sftp.calls.select { |call| call[1] == target }.map(&:first)
      assert_equal [:lstat, :remove, :symlink], actions
      assert_equal "../a", sftp.entries[target][:target]
    end
  end

  def test_existing_directory_skips_mkdir_but_sets_final_permissions
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      create_linked_tree(source)
      sftp = FakeSFTP.new(6)
      sftp.entries["/remote/root/nested"] = { :type => :directory, :mode => 0o40555 }

      Net::SFTP::Operations::Upload.new(sftp, source, "/remote/root", :mkdir => true).wait

      refute_includes sftp.calls.map { |call| [call[0], call[1]] }, [:mkdir, "/remote/root/nested"]
      nested = sftp.calls.find { |call| call[0] == :setstat && call[1] == "/remote/root/nested" }
      assert_equal 0o750, nested[2][:permissions]
    end
  end

  def test_root_conflict_is_detected_when_mkdir_requested
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      create_linked_tree(source)
      sftp = FakeSFTP.new(6)
      sftp.entries["/remote/root"] = { :type => :regular, :mode => 0o100644 }

      upload = Net::SFTP::Operations::Upload.new(sftp, source, "/remote/root", :mkdir => true)
      assert_raises(Net::SFTP::RemoteTypeConflict) { upload.wait }
      refute_includes sftp.calls.map(&:first), :mkdir
    end
  end

  def test_mkdir_false_requires_existing_remote_root_directory
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      create_linked_tree(source)
      sftp = FakeSFTP.new(6)
      upload = Net::SFTP::Operations::Upload.new(sftp, source, "/remote/root", :mkdir => false)

      error = assert_raises(Net::SFTP::Exception) { upload.wait }
      assert_match(/does not exist/, error.message)
      refute_includes sftp.calls.map(&:first), :mkdir
    end
  end

  def test_failed_entity_upload_skips_dependent_hard_link_and_permissions
    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      create_linked_tree(source)
      sftp = FakeSFTP.new(6, {}, ["/remote/root/a"])
      sftp.reverse_completion = true
      upload = Net::SFTP::Operations::Upload.new(sftp, source, "/remote/root", :mkdir => true)

      assert_raises(Net::SFTP::StatusException) { upload.wait }
      refute_includes sftp.calls.map { |call| [call[0], call[1]] }, [:hardlink, "/remote/root/nested/b"]
      refute_includes sftp.calls.map { |call| [call[0], call[1]] }, [:setstat, "/remote/root/a"]
    end
  end

  private

  def create_linked_tree(source)
    FileUtils.mkdir_p(File.join(source, "nested"))
    FileUtils.mkdir_p(File.join(source, "loop"))
    File.write(File.join(source, "a"), "content")
    File.link(File.join(source, "a"), File.join(source, "nested", "b"))
    File.chmod(0o755, source)
    File.chmod(0o750, File.join(source, "nested"))
    File.chmod(0o644, File.join(source, "a"))
    Dir.chdir(File.join(source, "loop")) do
      File.symlink("../a", "rel-self")
      File.symlink("loop", "self-dir")
    end
  end
end
