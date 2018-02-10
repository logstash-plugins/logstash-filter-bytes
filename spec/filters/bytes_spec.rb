# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/bytes"

describe LogStash::Filters::Bytes do
  let(:config) do <<-CONFIG
    filter {
      bytes {
        target => dest
      }
    }
  CONFIG
  end

  describe "empty" do
    sample("") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(0)
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

  describe "from bits" do
    sample("32b") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(4)
    end
  end

  describe "from kilobytes" do
    sample("32kB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024)
    end

    sample("32kb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024)
    end

    sample("32KB") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024)
    end
  end

  describe "from kilobits" do
    sample("32Kb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 / 8)
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

  describe "from megabits" do
    sample("32Mb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 / 8)
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

  describe "from gigabits" do
    sample("32Gb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 / 8)
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

  describe "from terabits" do
    sample("32Tb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 * 1024 / 8)
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

  describe "from petabits" do
    sample("32Pb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 * 1024 * 1024 / 8)
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

  describe "from exabits" do
    sample("32Eb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024 / 8)
    end
  end

  describe "with spaces" do
    sample("32 kb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024)
    end

    sample("32\tkb") do
      expect(subject).to include("dest")
      expect(subject.get('dest')).to eq(32 * 1024)
    end
  end
end
