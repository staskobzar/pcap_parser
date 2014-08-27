require 'spec_helper'

describe Stream do

  describe "#new" do
    context "little endian pcap file with microseconds" do
      let(:stream) do
        Stream.new(StringIO.new vector_le_usec)
      end
      it{expect(stream).to be_little_endian}
      it{expect(stream.sec_subt).to eq(1.0/1_000_000)}
    end
    context "little endian pcap file with nanoseconds" do
      let(:stream) do
        Stream.new(StringIO.new vector_le_nsec)
      end
      it{expect(stream).to be_little_endian}
      it{expect(stream.sec_subt).to eq(1.0/1_000_000_000)}
    end
    context "big endian pcap file with microseconds" do
      let(:stream) do
        Stream.new(StringIO.new vector_be_usec)
      end
      it{expect(stream).to be_big_endian}
      it{expect(stream.sec_subt).to eq(1.0/1_000_000)}
    end
    context "big endian pcap file with nanoseconds" do
      let(:stream) do
        Stream.new(StringIO.new vector_be_nsec)
      end
      it{expect(stream).to be_big_endian}
      it{expect(stream.sec_subt).to eq(1.0/1_000_000_000)}
    end

  end
end
