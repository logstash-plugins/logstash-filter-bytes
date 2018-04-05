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

  VALID_CONVERSION_METHODS = [ "binary", "metric" ]

  DIGIT_GROUP_SEPARATORS = " _,."

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

  # Conversion method, either "binary" (1K = 1024B) or "metric" (1K = 1000B)
  config :conversion_method, :validate => :string, :default => "binary"

  # Decimal separator
  config :decimal_separator, :validate => :string, :default => "."

  # Append values to the `tags` field when there has been no
  # successful match
  config :tag_on_failure, :validate => :array, :default => ["_bytesparsefailure"]

  private
  def normalize_number_with_decimal_separator_position(number, decimal_separator_position)
    # Normalized number is:
    # - digits to left of the decimal separator all smooshed together (ignoring any non-digits), plus
    # - the decimal separator (normalized to '.'), plus
    # - the digits to the right of the decimal separator
    return number[0, decimal_separator_position].tr('^0-9', '') \
      + '.' \
      + number[decimal_separator_position + 1 .. -1].to_s
  end

  private
  def normalize_number(number)
    # Assume decimal separator can be either . or ,. Count the number of these.
    num_separators = number.count(".,")

    # If there are no separators, we're good as-is
    if num_separators == 0
      return number
    end

    decimal_separator_position = [ number.rindex('.') || -1, number.rindex(',') || -1].max

    # If there's more than one, then the rightmost one is the decimal separator. The rest
    # are digit group separators
    if num_separators > 1
      return normalize_number_with_decimal_separator_position(number, decimal_separator_position)
    end

    # There's only one separator so we need to do some further checking

    # If the number of digits to the right of the separator is less than or greater than 3
    # then we can assume it's a decimal separator
    right_of_separator = number[decimal_separator_position + 1 .. -1]
    if right_of_separator.length != 3
      return normalize_number_with_decimal_separator_position(number, decimal_separator_position)
    end

    # There are exactly 3 digits to the right of the separator. We can't be sure if it's a decimal
    # separator or digit groups separator (e.g. is 1,333mb == 1333mb or 1333kb?). So we look at the
    # decimal_separator option to disambiguate
    decimal_separator_position = number.index(@decimal_separator) || number.length
    return normalize_number_with_decimal_separator_position(number, decimal_separator_position)
  end

  public
  def register
    # Add instance variables 
  end # def register

  public
  def filter(event)

    source = event.get(@source)

    if !VALID_CONVERSION_METHODS.include?(@conversion_method)
      raise LogStash::ConfigurationError, "Conversion method '#{@conversion_method}' is invalid! Pick one of #{VALID_CONVERSION_METHODS}"
    end

    if !source
      @tag_on_failure.each{|tag| event.tag(tag)}
      return
    end
    source.strip!

    # Parse the source into the number part (e.g. 123),
    # the unit prefix part (e.g. M), and the unit suffix part (e.g. B)
    match = source.match(/^([0-9#{DIGIT_GROUP_SEPARATORS}#{@decimal_separator}]*)\s*([kKmMgGtTpPeE]?)([bB]?)$/)
    if !match
      @tag_on_failure.each{|tag| event.tag(tag)}
      return
    end

    number, prefix, suffix = match.captures
    number = normalize_number(number.strip)

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
      if @conversion_method == 'binary'
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
