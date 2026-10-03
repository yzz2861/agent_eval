# :markup: markdown

module HTTP
  autoload :Cookie, "http/cookie"
end

##
# This class is used to manage the Cookies that have been returned from
# any particular website.

class HTTP::CookieJar

  attr_reader :store

  def get_impl(base, value, *args)
    case value
    when base
      value
    when Symbol
      begin
        base.implementation(value).new(*args)
      rescue IndexError => e
        raise ArgumentError, e.message
      end
    when Class
      if base >= value
        value.new(*args)
      else
        raise TypeError, 'not a subclass of %s: %s' % [base, value]
      end
    else
      raise TypeError, 'invalid object: %s' % value.inspect
    end
  end
  private :get_impl

  # Generates a new cookie jar.
  #
  # Available option keywords are as below:
  #
  # :store
  # : The store class that backs this jar. (default: `:hash`)
  # A symbol addressing a store class, a store class, or an instance
  # of a store class is accepted.  Symbols are mapped to store
  # classes, like `:hash` to HTTP::CookieJar::HashStore and `:mozilla`
  # to HTTP::CookieJar::MozillaStore.
  #
  # :accept_policy
  # : The cookie acceptance policy. (default: `:rfc6265`)
  # A symbol addressing a policy, a policy class, or a policy
  # instance is accepted.  Symbols are mapped to policy classes in
  # HTTP::CookieJar::AcceptPolicy:
  #
  #   * `:rfc6265` (default) keeps the historical lenient behaviour.
  #   * `:browser_secure` enforces the `__Secure-`/`__Host-` name
  #     prefix constraints and prevents an insecure origin from
  #     overwriting a stored Secure cookie.  See
  #     HTTP::CookieJar::AcceptPolicy::BrowserSecurePolicy for the
  #     list of rejection reasons.
  #
  # :on_reject
  # : An optional Proc (or any object responding to `call`) invoked
  # with `(cookie, reason)` whenever the acceptance policy rejects a
  # cookie.  `reason` is a symbol; see
  # HTTP::CookieJar::AcceptPolicy::BrowserSecurePolicy for possible
  # values under the `:browser_secure` policy.
  #
  # :logger
  # : A logger object; rejections are also reported to it as warnings
  # when this is given.
  #
  # Any options given are passed through to the initializer of the
  # specified store class.  For example, the `:mozilla`
  # (HTTP::CookieJar::MozillaStore) store class requires a `:filename`
  # option.  See individual store classes for details.
  def initialize(options = nil)
    opthash = {
      :store => :hash,
    }
    opthash.update(options) if options
    @accept_policy = get_accept_policy(opthash[:accept_policy])
    @on_reject = opthash[:on_reject]
    @logger = opthash[:logger]
    store_options = opthash.reject { |key, _| key == :accept_policy || key == :on_reject }
    @store = get_impl(AbstractStore, store_options[:store], store_options)
  end

  # The copy constructor.  Not all backend store classes support cloning.
  def initialize_copy(other)
    @store = other.instance_eval { @store.dup }
    @accept_policy = other.instance_variable_get(:@accept_policy)
    @on_reject = other.instance_variable_get(:@on_reject)
    @logger = other.instance_variable_get(:@logger)
  end

  # The acceptance policy object used by this jar.
  attr_reader :accept_policy

  # Adds a cookie to the jar if it is acceptable, and returns self in
  # any case.  A given cookie must have domain and path attributes
  # set, or ArgumentError is raised.
  #
  # Whether a cookie with the `for_domain` flag on overwrites another
  # with the flag off or vice versa depends on the store used.  See
  # individual store classes for that matter.
  #
  # ### Compatibility Note for Mechanize::Cookie users
  #
  # In HTTP::Cookie, each cookie object can store its origin URI
  # (cf. #origin).  While the origin URI of a cookie can be set
  # manually by #origin=, one is typically given in its generation.
  # To be more specific, HTTP::Cookie.new takes an `:origin` option
  # and HTTP::Cookie.parse takes one via the second argument.
  #
  #       # Mechanize::Cookie
  #       jar.add(origin, cookie)
  #       jar.add!(cookie)    # no acceptance check is performed
  #
  #       # HTTP::Cookie
  #       jar.origin = origin
  #       jar.add(cookie)     # acceptance check is performed
  def add(cookie)
    add_if_accepted(cookie)
    self
  end
  alias << add

  # Deletes a cookie that has the same name, domain and path as a
  # given cookie from the jar and returns self.
  #
  # How the `for_domain` flag value affects the set of deleted cookies
  # depends on the store used.  See individual store classes for that
  # matter.
  def delete(cookie)
    @store.delete(cookie)
    self
  end

  # Gets an array of cookies sorted by the path and creation time.  If
  # `url` is given, only ones that should be sent to the URL/URI are
  # selected, with the access time of each of them updated.
  def cookies(url = nil)
    each(url).sort
  end

  # Tests if the jar is empty.  If `url` is given, tests if there is
  # no cookie for the URL.
  def empty?(url = nil)
    if url
      each(url) { return false }
      return true
    else
      @store.empty?
    end
  end

  # Iterates over all cookies that are not expired in no particular
  # order.
  #
  # An optional argument `uri` specifies a URI/URL indicating the
  # destination of the cookies being selected.  Every cookie yielded
  # should be good to send to the given URI,
  # i.e. cookie.valid_for_uri?(uri) evaluates to true.
  #
  # If (and only if) the `uri` option is given, last access time of
  # each cookie is updated to the current time.
  def each(uri = nil, &block) # :yield: cookie
    block_given? or return enum_for(__method__, uri)

    if uri
      uri = HTTP::Cookie::URIParser.parse(uri)
      return self unless URI::HTTP === uri && uri.host
    end

    @store.each(uri, &block)
    self
  end
  include Enumerable

  # Parses a Set-Cookie field value `set_cookie` assuming that it is
  # sent from a source URL/URI `origin`, and adds the cookies parsed
  # as valid and considered acceptable to the jar.  Returns an array
  # of cookies that have been added.
  #
  # If a block is given, it is called for each cookie and the cookie
  # is added only if the block returns a true value.
  #
  # `jar.parse(set_cookie, origin)` is a shorthand for this:
  #
  #         HTTP::Cookie.parse(set_cookie, origin) { |cookie|
  #           jar.add(cookie)
  #         }
  #
  # See HTTP::Cookie.parse for available options.
  def parse(set_cookie, origin, options = nil) # :yield: cookie
    HTTP::Cookie.parse(set_cookie, origin, options).tap { |cookies|
      cookies.select! { |cookie|
        (!block_given? || yield(cookie)) && add_if_accepted(cookie)
      }
    }
  end

  # call-seq:
  #   jar.save(filename_or_io, **options)
  #   jar.save(filename_or_io, format = :yaml, **options)
  #
  # Saves the cookie jar into a file or an IO in the format specified
  # and returns self.  If a given object responds to #write it is
  # taken as an IO, or taken as a filename otherwise.
  #
  # Available option keywords are below:
  #
  # * `:format`
  #
  #     Specifies the format for saving.  A saver class, a symbol
  #     addressing a saver class, or a pre-generated instance of a
  #     saver class is accepted.
  #
  #     <dl class="rdoc-list note-list">
  #       <dt>:yaml</dt>
  #       <dd>YAML structure (default)</dd>
  #       <dt>:cookiestxt</dt>
  #       <dd>Mozilla's cookies.txt format</dd>
  #     </dl>
  #
  # * `:session`
  #
  #     <dl class="rdoc-list note-list">
  #       <dt>true</dt>
  #       <dd>Save session cookies as well.</dd>
  #       <dt>false</dt>
  #       <dd>Do not save session cookies. (default)</dd>
  #     </dl>
  #
  # All options given are passed through to the underlying cookie
  # saver module's constructor.
  def save(writable, *options)
    opthash = {
      :format => :yaml,
      :session => false,
    }
    case options.size
    when 0
    when 1
      case options = options.first
      when Symbol
        opthash[:format] = options
      else
        if hash = Hash.try_convert(options)
          opthash.update(hash)
        end
      end
    when 2
      opthash[:format], options = options
      if hash = Hash.try_convert(options)
        opthash.update(hash)
      end
    else
      raise ArgumentError, 'wrong number of arguments (%d for 1-3)' % (1 + options.size)
    end

    saver = get_impl(AbstractSaver, opthash[:format], opthash)

    if writable.respond_to?(:write)
      saver.save(writable, self)
    else
      File.open(writable, 'w') { |io|
        saver.save(io, self)
      }
    end

    self
  end

  # call-seq:
  #   jar.load(filename_or_io, **options)
  #   jar.load(filename_or_io, format = :yaml, **options)
  #
  # Loads cookies recorded in a file or an IO in the format specified
  # into the jar and returns self.  If a given object responds to
  # \#read it is taken as an IO, or taken as a filename otherwise.
  #
  # Available option keywords are below:
  #
  # * `:format`
  #
  #     Specifies the format for loading.  A saver class, a symbol
  #     addressing a saver class, or a pre-generated instance of a
  #     saver class is accepted.
  #
  #     <dl class="rdoc-list note-list">
  #       <dt>:yaml</dt>
  #       <dd>YAML structure (default)</dd>
  #       <dt>:cookiestxt</dt>
  #       <dd>Mozilla's cookies.txt format</dd>
  #     </dl>
  #
  # All options given are passed through to the underlying cookie
  # saver module's constructor.
  def load(readable, *options)
    opthash = {
      :format => :yaml,
      :session => false,
    }
    case options.size
    when 0
    when 1
      case options = options.first
      when Symbol
        opthash[:format] = options
      else
        if hash = Hash.try_convert(options)
          opthash.update(hash)
        end
      end
    when 2
      opthash[:format], options = options
      if hash = Hash.try_convert(options)
        opthash.update(hash)
      end
    else
      raise ArgumentError, 'wrong number of arguments (%d for 1-3)' % (1 + options.size)
    end

    saver = get_impl(AbstractSaver, opthash[:format], opthash)

    if readable.respond_to?(:write)
      saver.load(readable, self)
    else
      File.open(readable, 'r') { |io|
        saver.load(io, self)
      }
    end

    self
  end

  # Clears the cookie jar and returns self.
  def clear
    @store.clear
    self
  end

  # Removes expired cookies and returns self.  If `session` is true,
  # all session cookies are removed as well.
  def cleanup(session = false)
    @store.cleanup session
    self
  end

  private

  def get_accept_policy(value)
    case value
    when nil
      AcceptPolicy::RFC6265Policy.new
    when Symbol
      begin
        AcceptPolicy.implementation(value).new
      rescue IndexError => e
        raise ArgumentError, e.message
      end
    when Class
      if value <= AcceptPolicy && value != AcceptPolicy
        value.new
      else
        raise TypeError, 'not an acceptance policy class: %s' % value.inspect
      end
    else
      if value.respond_to?(:rejection_reason)
        value
      else
        raise TypeError, 'invalid acceptance policy object: %s' % value.inspect
      end
    end
  end

  # Tests if the cookie passes both the RFC 6265 acceptance check and
  # the jar's acceptance policy.  Reports the policy's rejection
  # reason to the #on_reject callback and the logger, if given.
  # Returns true if the cookie was stored, false otherwise.
  def add_if_accepted(cookie)
    cookie.acceptable?
  rescue RuntimeError => e
    raise ArgumentError, e.message
  else
    if reason = @accept_policy.rejection_reason(cookie, self)
      if @on_reject
        @on_reject.call(cookie, reason)
      end
      @logger.warn("Cookie rejected (#{reason}): #{cookie.inspect}") if @logger
      false
    else
      @store.add(cookie)
      true
    end
  end
end

require 'http/cookie_jar/abstract_store'
require 'http/cookie_jar/abstract_saver'
require 'http/cookie_jar/accept_policy'
