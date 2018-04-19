# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/bytes"

describe LogStash::Filters::Bytes do
  let(:config) do <<-CONFIG
    filter {
      bytes {
        target => dest
        tag_on_failure => [ "boom", "_bytesparsefailure" ]
      }
    }
  CONFIG
  end

  describe "empty" do
    sample("") do
      expect(subject.get('tags')).to eq(["boom", "_bytesparsefailure"])
    end
  end

  describe "garbage" do
    sample("abcdef") do
      expect(subject.get('tags')).to eq(["boom", "_bytesparsefailure"])
    end
  end

  describe "no number, only units" do
    sample("mb") do
      expect(subject.get('tags')).to eq(["boom", "_bytesparsefailure"])
    end
  end

  describe "no units" do
    sample("0") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(0)
    end

    sample("123") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(123)
    end

    sample("12.3") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(12)
    end
  end

  describe "from bytes" do
    sample("32.8B") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(33)
    end
  end

  describe "from kilobytes" do
    sample("32kB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024)
    end

    sample("32KB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024)
    end
  end

  describe "from megabytes" do
    sample("32mB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024)
    end

    sample("32mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024)
    end

    sample("32MB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024)
    end
  end

  describe "from gigabytes" do
    sample("32gB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024)
    end

    sample("32gb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024)
    end

    sample("32GB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024)
    end
  end

  describe "from terabytes" do
    sample("32tB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 * 1024)
    end

    sample("32tb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 * 1024)
    end

    sample("32TB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 * 1024)
    end
  end

  describe "from petabytes" do
    sample("32pB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 * 1024 * 1024)
    end

    sample("32pb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 * 1024 * 1024)
    end

    sample("32PB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 * 1024 * 1024)
    end
  end

  describe "from exabytes" do
    sample("32eB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024)
    end

    sample("32eb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024)
    end

    sample("32EB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024)
    end
  end

  describe "with spaces" do
    sample("32 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024)
    end

    sample("32\tmb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024)
    end
  end

  describe "using metric conversion system" do
    let(:config) do <<-CONFIG
      filter {
        bytes {
          target => dest
          conversion_method => metric
        }
      }
    CONFIG
    end

    sample("32 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1000 * 1000)
    end
  end

  describe "no decimal separator" do
    sample("3 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(3 * 1024 * 1024)
    end      

    sample("3,124 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(3124 * 1024 * 1024)
    end      
  end

  describe "digits only to right of decimal separator" do
    sample(".3124 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq((0.3124 * 1024 * 1024).round)
    end
  end

  describe "digits only to left of decimal separator" do
    sample("3. mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(3 * 1024 * 1024)
    end      

    sample("3,124. mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(3124 * 1024 * 1024)
    end      
  end

  describe "digits on both sides of decimal separator" do
    sample("3.56 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq((3.56 * 1024 * 1024).round)
    end      

    sample("3,124.56 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq((3124.56 * 1024 * 1024).round)
    end      
  end

  describe "non-default decimal separator" do
    let(:config) do <<-CONFIG
      filter {
        bytes {
          target => dest
          decimal_separator => ','
        }
      }
    CONFIG
    end

    sample("3,9 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq((3.9 * 1024 * 1024).round)
    end

    sample("1.9 kb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq((19 * 1024).round)
    end
  end

  describe "with two decimal separators" do
    sample("1.000.000 mb") do
      expect(subject.get('tags')).to eq(["boom", "_bytesparsefailure"])
    end

    context "non-default decimal separator" do
      let(:config) do <<-CONFIG
        filter {
          bytes {
            target => dest
            decimal_separator => ','
            tag_on_failure => [ "boom", "_bytesparsefailure" ]
          }
        }
      CONFIG
      end

      sample("1,000,000 mb") do
        expect(subject.get('tags')).to eq(["boom", "_bytesparsefailure"])
      end
    end
  end
end
