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
      expect(subject.get('dest')).to eq(12.3)
    end
  end

  describe "from bytes" do
    sample("32.8B") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32.8)
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

  describe "using metric system for prefix" do
    let(:config) do <<-CONFIG
      filter {
        bytes {
          target => dest
          prefix_system => metric
        }
      }
    CONFIG
    end

    sample("32 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1000 * 1000)
    end
  end

  describe "using invalid system for prefix" do
    let(:config) { Hash.new }
    subject { described_class.new(config) }

    let(:config) do
      {
        "target" => "dest",
        "prefix_system" => "garbage"
      }
    end

    let(:event) { LogStash::Event.new("message" => "100KB") }

    it "raises exception" do
      subject.register
      expected_message = "Prefix system 'garbage' is invalid! Pick one of [\"binary\", \"metric\"]"
      expect { subject.filter(event) }.to raise_error(LogStash::ConfigurationError, expected_message)
    end
  end

  describe "0 digits to right of rightmost separator" do
    sample("3, mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(3 * 1024 * 1024)
    end

    sample("1. kb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(1 * 1024)
    end
  end

  describe "1 digit to right of rightmost separator" do
    sample("3,9 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(3.9 * 1024 * 1024)
    end

    sample("1.9 kb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(1.9 * 1024)
    end

    describe "with non-default decimal separator" do
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
        expect(subject.get('dest')).to eq(3.9 * 1024 * 1024)
      end

      sample("1.9 kb") do
        expect(subject).to include("dest")
        expect(subject.get('dest')).to eq(1.9 * 1024)
      end
    end
  end

  describe "2 digits to right of rightmost separator" do
    sample("3,98 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(3.98 * 1024 * 1024)
    end

    sample("1.98 kb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(1.98 * 1024)
    end

    describe "with non-default decimal separator" do
      let(:config) do <<-CONFIG
        filter {
          bytes {
            target => dest
            decimal_separator => ','
          }
        }
      CONFIG
      end

      sample("3,98 mb") do
        expect(subject).to include("dest")
        expect(subject.get('dest')).to eq(3.98 * 1024 * 1024)
      end

      sample("1.98 kb") do
        expect(subject).to include("dest")
        expect(subject.get('dest')).to eq(1.98 * 1024)
      end
    end
  end

  describe "3 digits to right of rightmost separator" do
    sample("3,987 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(3987 * 1024 * 1024)
    end

    sample("1.987 kb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(1.987 * 1024)
    end

    describe "with non-default decimal separator" do
      let(:config) do <<-CONFIG
        filter {
          bytes {
            target => dest
            decimal_separator => ','
          }
        }
      CONFIG
      end

      sample("3,987 mb") do
        expect(subject).to include("dest")
        expect(subject.get('dest')).to eq(3.987 * 1024 * 1024)
      end

      sample("1.987 kb") do
        expect(subject).to include("dest")
        expect(subject.get('dest')).to eq(1987 * 1024)
      end
    end
  end

  describe "4 digits to right of rightmost separator" do
    sample("3,9876 mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(3.9876 * 1024 * 1024)
    end

    sample("1.9876 kb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(1.9876 * 1024)
    end

    describe "with non-default decimal separator" do
      let(:config) do <<-CONFIG
        filter {
          bytes {
            target => dest
            decimal_separator => ','
          }
        }
      CONFIG
      end

      sample("3,9876 mb") do
        expect(subject).to include("dest")
        expect(subject.get('dest')).to eq(3.9876 * 1024 * 1024)
      end

      sample("1.9876 kb") do
        expect(subject).to include("dest")
        expect(subject.get('dest')).to eq(1.9876 * 1024)
      end
    end
  end
end
