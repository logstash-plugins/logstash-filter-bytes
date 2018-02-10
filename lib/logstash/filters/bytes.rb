# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This filter will parse a given string as a computer storage
# value (e.g. "123 MB" or "5.3GB") and add a new numeric field with
# size in bytes
#
class LogStash::Filters::Bytes < LogStash::Filters::Base

  @@prefix_powers = {
    'k' => 1, # 1 kilobyte = 1024 ^ 1 bytes
    'm' => 2, # 1 megabyte = 1024 ^ 2 bytes
    'g' => 3, # 1 gigabyte = 1024 ^ 3 bytes
    't' => 4, # 1 terabyte = 1024 ^ 4 bytes
    'p' => 5, # 1 petabyte = 1024 ^ 5 bytes
    'e' => 6  # 1 exabyte = 1024 ^ 6 bytes
  }

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

  public
  def register
    # Add instance variables 
  end # def register

  public
  def filter(event)

    source = event.get(@source)

    if !source
      return
    end
    source.strip!

    # Parse the source into the number part (e.g. 123),
    # the unit prefix part (e.g. M), and the unit base part (e.g. B)
    match = source.match(/^([0-9\,\.]*)\s*([kKmMgGtTpPeE]?)([bB]?)$/)
    if !match
      event.set(@target, 0)
      return
    end

    number, prefix, base = match.captures
    # Take out any non-numeric characters or periods (e.g. delimiters) from
    # the number
    # TODO: i18n
    number.tr!('^0-9.', '')

    if number == ''
      event.set(@target, 0)
      return
    end

    if base == ''
      base = 'B'
    end

    # Convert the number to bytes
    result = number.to_f
    if prefix != ''
      result *= (1024 ** @@prefix_powers[prefix.downcase])
    end

    # If prefix is absent and base is 'b'
    if prefix == '' && /[[:lower:]]/.match(base)
      result /= 8
    end

    # If prefix is uppercase (e.g. M) and base is 'b', the we've been given bits
    if /[[:upper:]]/.match(prefix) && /[[:lower:]]/.match(base)
      result /= 8
    end

    event.set(@target, result)

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Bytes
