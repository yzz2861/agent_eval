require 'net/sftp/errors'

module Net; module SFTP; module Operations

  # An explicit, inspectable plan for recursively uploading a local
  # directory tree to a remote server, preserving links.
  #
  # The plan is built entirely from local information (via +lstat+, so
  # symlinks are never followed) plus an optional caller-supplied probe of
  # the remote side. It describes, in dependency order, every operation
  # that the upload will perform:
  #
  # * directories are created before their contents;
  # * symlinks are recreated as symlinks, with the target text stored
  #   verbatim (relative targets are kept relative and never resolved);
  # * hard-linked files are grouped by local device+inode: the first
  #   member of a group is uploaded as a regular file and every other
  #   member becomes a hard-link step that depends on that upload;
  # * remote objects whose type conflicts with the local entry are either
  #   removed first (default) or reported as an error;
  # * permission bits are applied last, after the content they govern.
  #
  # A plan can be inspected (or simply printed) before anything is sent:
  #
  #   plan = Net::SFTP::Operations::UploadPlan.build("/local/dir", "/remote/dir",
  #             :mkdir => true, :remote_type => lambda { |path| probe(path) })
  #   puts plan
  #   plan.execute(sftp).wait
  #
  # The following options are supported:
  #
  # * <tt>:mkdir</tt> - create the remote root directory itself (default
  #   false, matching Net::SFTP::Operations::Upload).
  # * <tt>:permissions</tt> - apply local permission bits on the remote
  #   side after the content is in place (default true).
  # * <tt>:hardlinks</tt> - <tt>:link</tt> (default) creates remote hard
  #   links for additional aliases of an already-uploaded inode;
  #   <tt>:upload</tt> uploads every alias as an independent file. Use
  #   UploadPlan.resolve_hardlink_strategy to pick a value based on what
  #   the server supports.
  # * <tt>:remote_type</tt> - an optional callable that maps a remote path
  #   to <tt>:file</tt>, <tt>:directory</tt>, <tt>:symlink</tt> or +nil+
  #   (absent). Used to detect same-name type conflicts.
  # * <tt>:on_conflict</tt> - <tt>:replace</tt> (default) removes a
  #   conflicting remote object before creating the new one;
  #   <tt>:error</tt> raises a ConflictError while the plan is built.
  class UploadPlan

    # Base class for all plan-specific errors.
    class Error < Net::SFTP::Exception; end

    # Describes a single remote object whose type conflicts with the
    # corresponding local entry.
    class Conflict
      attr_reader :remote, :found, :expected

      def initialize(remote, found, expected)
        @remote, @found, @expected = remote, found, expected
      end

      def to_s
        "#{remote}: remote object is a #{found}, but local entry is a #{expected}"
      end
    end

    # Raised when the plan is built with <tt>:on_conflict => :error</tt>
    # and at least one remote object conflicts with a local entry.
    class ConflictError < Error
      attr_reader :conflicts

      def initialize(conflicts)
        @conflicts = conflicts
        super("remote type conflicts detected:\n  " + conflicts.map(&:to_s).join("\n  "))
      end
    end

    # Records a single step failure during execution.
    StepError = Struct.new(:step, :response, :message)

    # Raised (via Executor#raise_if_failed) when one or more steps failed.
    # Steps that depended on a failed step are skipped, never executed.
    class ExecutionFailed < Error
      attr_reader :errors

      def initialize(errors)
        @errors = errors
        details = errors.map { |e| "#{e.step.action} #{e.step.detail} (#{e.message})" }
        super("#{errors.length} step(s) failed during upload: #{details.join('; ')}")
      end
    end

    # The base class of all plan steps. A step carries explicit
    # dependencies; it becomes runnable only once every dependency has
    # completed successfully, and it is skipped (never executed) if any
    # dependency failed or was itself skipped.
    class Step
      attr_reader :dependencies, :dependents
      attr_accessor :state # :pending, :running, :done, :failed, :skipped

      def initialize
        @dependencies = []
        @dependents = []
        @state = :pending
      end

      def depends_on(other)
        return unless other
        @dependencies << other
        other.dependents << self
      end

      def blocked?
        @dependencies.any? { |d| d.state == :failed || d.state == :skipped }
      end

      def runnable?
        @state == :pending && @dependencies.all? { |d| d.state == :done }
      end

      def action
        self.class.name.split("::").last.downcase
      end

      def detail
        ""
      end
    end

    # Creates a remote directory.
    class Mkdir < Step
      attr_reader :remote, :mode

      def initialize(remote, mode)
        super()
        @remote, @mode = remote, mode
      end

      def detail
        mode ? "#{remote} (mode #{mode_string})" : remote
      end

      private

      def mode_string
        "0" + sprintf("%03o", @mode)
      end
    end

    # Uploads a local file's contents to a remote path.
    class UploadFile < Step
      attr_reader :local, :remote, :size, :mode

      def initialize(local, remote, size, mode)
        super()
        @local, @remote, @size, @mode = local, remote, size, mode
      end

      def action
        "upload"
      end

      def detail
        "#{local} -> #{remote} (#{size} bytes)"
      end
    end

    # Creates a remote symbolic link. The target text is stored verbatim
    # and may be relative; it is never resolved against the local tree.
    class Symlink < Step
      attr_reader :remote, :target

      def initialize(remote, target)
        super()
        @remote, @target = remote, target
      end

      def detail
        "#{remote} -> #{target}"
      end
    end

    # Creates a remote hard link at +remote+ pointing to +existing+ (the
    # remote path of the already-uploaded entity for this inode group).
    class Hardlink < Step
      attr_reader :remote, :existing

      def initialize(remote, existing)
        super()
        @remote, @existing = remote, existing
      end

      def detail
        "#{remote} => #{existing}"
      end
    end

    # Removes a conflicting remote object (rmdir for directories, remove
    # otherwise) so that a differently-typed object can take its place.
    class RemoveRemote < Step
      attr_reader :remote, :type

      def initialize(remote, type)
        super()
        @remote, @type = remote, type
      end

      def detail
        "#{remote} (#{type})"
      end
    end

    # Applies permission bits to a remote path. Always scheduled after
    # the steps that create the content it governs.
    class Chmod < Step
      attr_reader :remote, :mode

      def initialize(remote, mode)
        super()
        @remote, @mode = remote, mode
      end

      def detail
        sprintf("0%03o %s", @mode, @remote)
      end
    end
    # Decides how hard-link aliases should be handled, given whether the
    # server supports hard links (SFTP protocol version 6+) and the
    # caller's preference:
    #
    # * <tt>:error</tt> (default) - raise unless hard links are supported.
    # * <tt>:upload</tt> - upload every alias as an independent file.
    #
    # Returns either <tt>:link</tt> or <tt>:upload</tt>, suitable for the
    # <tt>:hardlinks</tt> plan option.
    def self.resolve_hardlink_strategy(supported, requested)
      requested ||= :error
      case requested
      when :error
        return :link if supported
        raise Error, "the server does not support hard links (SFTP protocol " \
          "version 6 or higher is required); pass :hardlinks => :upload to " \
          "upload each alias as a separate file"
      when :upload
        :upload
      else
        raise ArgumentError, "invalid :hardlinks strategy #{requested.inspect} (expected :error or :upload)"
      end
    end

    # Builds a plan for uploading the directory tree at +local_root+ to
    # +remote_root+. See the class documentation for the supported options.
    def self.build(local_root, remote_root, options={})
      new(local_root, remote_root, options)
    end

    attr_reader :local_root, :remote_root, :steps, :conflicts

    def initialize(local_root, remote_root, options={})
      @local_root  = local_root
      @remote_root = remote_root
      @options     = options
      @steps       = []
      @conflicts   = []
      @entities    = {} # [dev, ino] => UploadFile step
      @anchors     = {} # remote dir => step its children must wait for (or nil)
      @dir_modes   = [] # [remote, mode] in scan order (parents first)
      @file_modes  = [] # [UploadFile step, mode]

      scan_root

      if @conflicts.any? && conflict_policy == :error
        raise ConflictError.new(@conflicts)
      end

      append_permission_steps if permissions?
    end

    # Starts executing this plan over the given SFTP session and returns
    # the Executor. See Executor for the supported options.
    def execute(sftp, options={}, &progress)
      Executor.new(sftp, self, options, &progress)
    end

    # A human-readable rendering of the plan, one line per step, with
    # cross-references to the steps each step must wait for.
    def to_s
      lines = ["upload plan: #{local_root} -> #{remote_root} (#{@steps.length} steps)"]
      @steps.each_with_index do |step, i|
        deps = step.dependencies.map { |d| @steps.index(d) + 1 }
        suffix = deps.empty? ? "" : "  [after #{deps.join(', ')}]"
        lines << sprintf("  %2d. %-9s %s%s", i + 1, step.action, step.detail, suffix)
      end
      lines.join("\n")
    end

    private

      def permissions?
        @options.has_key?(:permissions) ? @options[:permissions] : true
      end

      def conflict_policy
        policy = @options[:on_conflict] || :replace
        unless [:replace, :error].include?(policy)
          raise ArgumentError, "invalid :on_conflict policy #{policy.inspect} (expected :replace or :error)"
        end
        policy
      end

      def hardlink_strategy
        @options[:hardlinks] || :link
      end

      def remote_type_of(remote)
        probe = @options[:remote_type]
        probe ? probe.call(remote) : nil
      end

      def add_step(step)
        @steps << step
        step
      end

      def scan_root
        stat = ::File.lstat(@local_root)
        raise Error, "not a directory: #{@local_root}" unless stat.directory?

        if @options[:mkdir]
          add_mkdir(@remote_root, stat.mode)
        else
          @anchors[@remote_root] = nil
          @dir_modes << [@remote_root, stat.mode & 07777]
        end

        scan_directory(@local_root, @remote_root)
      end

      def scan_directory(local_dir, remote_dir)
        ::Dir.entries(local_dir).sort.each do |entry|
          next if entry == "." || entry == ".."
          lpath = ::File.join(local_dir, entry)
          rpath = ::File.join(remote_dir, entry)
          stat = ::File.lstat(lpath)

          if stat.symlink?
            add_symlink(lpath, rpath)
          elsif stat.directory?
            add_mkdir(rpath, stat.mode)
            scan_directory(lpath, rpath)
          elsif stat.file?
            add_file(lpath, rpath, stat)
          else
            raise Error, "unsupported file type (not a file, directory, or symlink): #{lpath}"
          end
        end
      end

      def add_mkdir(remote, mode)
        parent_anchor = @anchors[::File.dirname(remote)]
        type = remote_type_of(remote)

        if type == :directory
          # Already there remotely; nothing to create.
          @anchors[remote] = parent_anchor
        elsif type.nil?
          step = add_step(Mkdir.new(remote, mode & 07777))
          step.depends_on(parent_anchor)
          @anchors[remote] = step
        else
          anchor = resolve_conflict(remote, :directory, parent_anchor)
          step = add_step(Mkdir.new(remote, mode & 07777))
          step.depends_on(anchor)
          @anchors[remote] = step
        end

        @dir_modes << [remote, mode & 07777]
      end

      def add_symlink(lpath, remote)
        anchor = resolve_conflict(remote, :symlink, @anchors[::File.dirname(remote)])
        step = add_step(Symlink.new(remote, ::File.readlink(lpath)))
        step.depends_on(anchor)
      end

      def add_file(lpath, remote, stat)
        anchor = resolve_conflict(remote, :file, @anchors[::File.dirname(remote)])
        entity = stat.nlink > 1 ? @entities[[stat.dev, stat.ino]] : nil

        if entity && hardlink_strategy == :link
          step = add_step(Hardlink.new(remote, entity.remote))
          step.depends_on(entity)
          step.depends_on(anchor)
        else
          step = add_step(UploadFile.new(lpath, remote, stat.size, stat.mode & 07777))
          step.depends_on(anchor)
          @entities[[stat.dev, stat.ino]] = step if stat.nlink > 1
          @file_modes << [step, stat.mode & 07777]
        end
      end

      # Returns the anchor step that a new object at +remote+ should
      # depend on, emitting a RemoveRemote step first when the remote
      # object conflicts with the wanted type.
      def resolve_conflict(remote, wanted, anchor)
        existing = remote_type_of(remote)
        return anchor if existing.nil?
        return anchor if existing == wanted && wanted != :symlink

        if conflict_policy == :error
          @conflicts << Conflict.new(remote, existing, wanted)
          return anchor
        end

        remove = add_step(RemoveRemote.new(remote, existing))
        remove.depends_on(anchor)
        remove
      end

      # Permission bits are applied only after the content they govern:
      # a file's chmod waits for its upload, and a directory's chmod waits
      # for every step that creates something inside it.
      def append_permission_steps
        @file_modes.each do |upload, mode|
          chmod = add_step(Chmod.new(upload.remote, mode))
          chmod.depends_on(upload)
        end

        @dir_modes.reverse_each do |remote, mode|
          chmod = add_step(Chmod.new(remote, mode))
          chmod.depends_on(@anchors[remote])
          @steps.each do |step|
            next if step.equal?(chmod) || step.is_a?(Chmod)
            step_remote = step.respond_to?(:remote) ? step.remote : nil
            chmod.depends_on(step) if step_remote && step_remote.start_with?(remote + "/")
          end
        end
      end

  end

  # Drives an UploadPlan over an SFTP session. Steps run asynchronously
  # (like Net::SFTP::Operations::Upload, the SSH event loop must be
  # pumping for progress to be made), at most +:requests+ of them at a
  # time, and always after every step they depend on has completed
  # successfully. When a step fails, the steps that depend on it are
  # skipped (never sent to the server), independent steps are allowed to
  # finish, and the collected errors are raised by #wait (or
  # #raise_if_failed) once the executor drains.
  #
  # The following options are supported:
  #
  # * <tt>:requests</tt> - the maximum number of steps to run
  #   concurrently (default 16).
  # * <tt>:read_size</tt> - the maximum number of bytes to read from a
  #   local file at a time (default 32,000).
  # * <tt>:progress</tt> - a block or handler object receiving progress
  #   events, just like Net::SFTP::Operations::Upload, except that file
  #   events yield the UploadFile step and the additional events
  #   <tt>:mkdir</tt>, <tt>:symlink</tt>, <tt>:link</tt>, <tt>:remove</tt>,
  #   <tt>:chmod</tt> and <tt>:skip</tt> may be reported.
  class UploadPlan::Executor

    # The default # of bytes to read from disk at a time.
    DEFAULT_READ_SIZE   = 32_000

    # The default maximum number of steps running at any given time.
    DEFAULT_CONCURRENCY = 16

    attr_reader :sftp, :plan, :options, :errors

    def initialize(sftp, plan, options={}, &progress)
      @sftp      = sftp
      @plan      = plan
      @options   = options
      @progress  = progress || options[:progress]
      @limit     = (options[:requests] || DEFAULT_CONCURRENCY).to_i
      @read_size = options[:read_size] || DEFAULT_READ_SIZE
      @errors    = []
      @in_flight = 0
      @finished  = false
      @aborted   = false

      pump
    end

    # Returns true while the executor still has work in flight or waiting.
    def active?
      !@finished
    end

    # Returns true if any step has failed.
    def failed?
      @errors.any?
    end

    # Stops scheduling new steps. Steps already in flight are allowed to
    # complete.
    def abort!
      @aborted = true
      check_finished
    end

    # Runs the SSH event loop until the executor drains, then raises an
    # UploadPlan::ExecutionFailed if any step failed.
    def wait
      sftp.loop { active? }
      raise_if_failed
      self
    end

    # Raises an UploadPlan::ExecutionFailed if any step failed.
    def raise_if_failed
      raise UploadPlan::ExecutionFailed.new(@errors) if failed?
    end

    private

      # Schedules runnable steps until the concurrency limit is reached,
      # skipping steps whose dependencies failed.
      def pump
        return if @aborted || @finished

        made_progress = true
        while made_progress && @in_flight < @limit
          made_progress = false
          @plan.steps.each do |step|
            next unless step.state == :pending
            if step.blocked?
              skip_step(step)
              made_progress = true
            elsif step.runnable?
              break if @in_flight >= @limit
              execute(step)
              made_progress = true
              break # rescan from the top to keep ordering deterministic
            end
          end
        end

        check_finished
      end

      def execute(step)
        step.state = :running
        @in_flight += 1

        case step
        when UploadPlan::Mkdir
          update_progress(:mkdir, step)
          sftp.mkdir(step.remote) { |response| complete_simple(step, response, "mkdir #{step.remote}") }
        when UploadPlan::RemoveRemote
          update_progress(:remove, step)
          if step.type == :directory
            sftp.rmdir(step.remote) { |response| complete_simple(step, response, "rmdir #{step.remote}") }
          else
            sftp.remove(step.remote) { |response| complete_simple(step, response, "remove #{step.remote}") }
          end
        when UploadPlan::Symlink
          update_progress(:symlink, step)
          sftp.symlink(step.target, step.remote) { |response| complete_simple(step, response, "symlink #{step.remote}") }
        when UploadPlan::Hardlink
          update_progress(:link, step)
          sftp.link(step.remote, step.existing, false) { |response| complete_simple(step, response, "link #{step.remote}") }
        when UploadPlan::Chmod
          update_progress(:chmod, step)
          sftp.setstat(step.remote, :permissions => step.mode) { |response| complete_simple(step, response, "chmod #{step.remote}") }
        when UploadPlan::UploadFile
          open_upload(step)
        else
          fail_step(step, nil, "unknown step type: #{step.class}")
        end
      end

      def open_upload(step)
        io = ::File.open(step.local, "rb")
        update_progress(:open, step)
        sftp.open(step.remote, "w") do |response|
          if response.ok?
            write_chunk(step, io, response[:handle])
          else
            io.close
            fail_step(step, response, "open #{step.remote}")
          end
        end
      rescue => error
        fail_step(step, nil, "open #{step.local}: #{error.message}")
      end

      def write_chunk(step, io, handle)
        offset = io.pos
        data = io.read(@read_size)
        if data.nil?
          update_progress(:close, step)
          sftp.close(handle) do |response|
            io.close
            if response.ok?
              step_done(step)
            else
              fail_step(step, response, "close #{step.remote}")
            end
          end
        else
          update_progress(:put, step, offset, data)
          sftp.write(handle, offset, data) do |response|
            if response.ok?
              write_chunk(step, io, handle)
            else
              io.close
              fail_step(step, response, "write #{step.remote}")
            end
          end
        end
      end

      def complete_simple(step, response, message)
        if response.ok?
          step_done(step)
        else
          fail_step(step, response, message)
        end
      end

      def step_done(step)
        step.state = :done
        @in_flight -= 1
        pump
      end

      def fail_step(step, response, message)
        step.state = :failed
        @in_flight -= 1
        @errors << UploadPlan::StepError.new(step, response, message)
        pump
      end

      def skip_step(step)
        step.state = :skipped
        cause = step.dependencies.find { |d| d.state == :failed || d.state == :skipped }
        update_progress(:skip, step, cause)
      end

      def check_finished
        return if @finished
        if @aborted
          @finished = true if @in_flight.zero?
        elsif @in_flight.zero? && @plan.steps.none? { |s| s.state == :pending || s.state == :running }
          @finished = true
          update_progress(:finish)
        end
      end

      def update_progress(event, *args)
        on = "on_#{event}"
        if @progress.respond_to?(on)
          @progress.send(on, self, *args)
        elsif @progress.respond_to?(:call)
          @progress.call(event, self, *args)
        end
      end

  end

end; end; end
