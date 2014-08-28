require 'spec_helper'

describe Packet do
  describe "#new" do
    context "little-endians" do
      context "with microseconds" do
        let(:packet) do
          stream=Stream.new(StringIO.new sample_packhdr_le_usec)
          Packet.new stream
        end
        it{expect(packet.sec).to be(1406296714)}
        it{expect(packet.usec).to be(944159)}
        it{expect(packet.nsec).to be(944159000)}
        it{expect(packet.cap_len).to be(358)}
        it{expect(packet.orig_len).to be(358)}
      end
      context "with nanoseconds" do
        let(:packet) do
          stream=Stream.new(StringIO.new sample_packhdr_le_nsec)
          Packet.new stream
        end
        it{expect(packet.sec).to be(1409183271)}
        it{expect(packet.usec).to be(691446)}
        it{expect(packet.nsec).to be(691445801)}
        it{expect(packet.cap_len).to be(543)}
        it{expect(packet.orig_len).to be(543)}
      end
    end
    context "big-endians" do
      context "with microseconds" do
        let(:packet) do
          stream=Stream.new(StringIO.new sample_packhdr_be_usec)
          Packet.new stream
        end
        it{expect(packet.sec).to be(1406296714)}
        it{expect(packet.usec).to be(944159)}
        it{expect(packet.nsec).to be(944159000)}
        it{expect(packet.cap_len).to be(358)}
        it{expect(packet.orig_len).to be(358)}
      end
      context "with nanoseconds" do
        let(:packet) do
          stream=Stream.new(StringIO.new sample_packhdr_be_nsec)
          Packet.new stream
        end
        it{expect(packet.sec).to be(1409183271)}
        it{expect(packet.usec).to be(691446)}
        it{expect(packet.nsec).to be(691445801)}
        it{expect(packet.cap_len).to be(543)}
        it{expect(packet.orig_len).to be(543)}
      end
    end
  end
end
