# encoding: UTF-8

module TZInfo

  # A {Timezone} based on a {DataSources::TimezoneInfo}.
  #
  # @abstract
  class InfoTimezone < Timezone
    # Initializes a new {InfoTimezone}.
    #
    # {InfoTimezone} instances should not normally be created directly. Use
    # the {Timezone.get} method to obtain {Timezone} instances.
    #
    # @param info [DataSources::TimezoneInfo] a {DataSources::TimezoneInfo}
    #   instance supplied by a {DataSource} that will be used as the source of
    #   data for this {InfoTimezone}.
    # @param data_source [DataSource] the {DataSource} this {InfoTimezone} is
    #   explicitly bound to, or `nil` for the process-wide default.
    def initialize(info, data_source = nil)
      super()
      @info = info
      @bound_data_source = data_source
    end

    # (see Timezone#identifier)
    def identifier
      @info.identifier
    end

    protected

    # @return [DataSources::TimezoneInfo] the {DataSources::TimezoneInfo} this
    #   {InfoTimezone} is based on.
    def info
      @info
    end
  end
end
