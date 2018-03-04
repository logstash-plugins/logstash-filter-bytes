# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This filter will parse a given string as a computer storage
# value (e.g. "123 MB" or "5.3GB") and add a new numeric field with
# size in bytes
#
class LogStash::Filters::Bytes < LogStash::Filters::Base

  PREFIX_POWERS = {
    'k' => 1, # 1 kilobyte = 1024 ^ 1 bytes
    'm' => 2, # 1 megabyte = 1024 ^ 2 bytes
    'g' => 3, # 1 gigabyte = 1024 ^ 3 bytes
    't' => 4, # 1 terabyte = 1024 ^ 4 bytes
    'p' => 5, # 1 petabyte = 1024 ^ 5 bytes
  }.freeze

  VALID_PREFIX_SYSTEMS = [ "binary", "metric" ]

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   bytes {
  #     source => "123 MB"
  #     target => "num_bytes"
  #   }
  # }
  #
  config_name "bytes"
  
  # Source string, e.g. "123 MB", "5.3GB", etc.
  config :source, :validate => :string, :default => "message"

  # Target field name
  config :target, :validate => :string

  # Prefix system, either "binary" (1K = 1024B) or "metric" (1K = 1000B)
  config :prefix_system, :validate => :string, :default => "binary"

  # Append values to the `tags` field when there has been no
  # successful match
  config :tag_on_failure, :validate => :array, :default => ["_bytesparsefailure"]

  public
  def register
    # Add instance variables 
  end # def register

  public
  def filter(event)

    source = event.get(@source)

    if !VALID_PREFIX_SYSTEMS.include?(@prefix_system)
      raise LogStash::ConfigurationError, "Base '#{@prefix_system}' is invalid! Pick one of #{VALID_PREFIX_SYSTEMS}"
    end

    if !source
      @tag_on_failure.each{|tag| event.tag(tag)}
      return
    end
    source.strip!

    # Parse the source into the number part (e.g. 123),
    # the unit prefix part (e.g. M), and the unit suffix part (e.g. B)
    match = source.match(/^([0-9\,\.]*)\s*([kKmMgGtTpPeE]?)([bB]?)$/)
    if !match
      @tag_on_failure.each{|tag| event.tag(tag)}
      return
    end

    number, prefix, suffix = match.captures
    # Take out any commas (thousand separator) from the number
    number.tr!('^0-9.', '')

    if number == ''
      @tag_on_failure.each{|tag| event.tag(tag)}
      return
    end

    if suffix == ''
      suffix = 'B'
    end

    # Convert the number to bytes
    result = number.to_f
    if prefix != ''
      if @prefix_system == 'binary'
        result *= (1024 ** PREFIX_POWERS[prefix.downcase])
      else
        result *= (1000 ** PREFIX_POWERS[prefix.downcase])
      end
    end

    event.set(@target, result)

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Bytes
