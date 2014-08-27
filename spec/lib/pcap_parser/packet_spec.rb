require 'spec_helper'

describe Packet do
  describe "#new" do
    context "little-endians", focus:true do
      let(:packet) do
        stream=Stream.new(StringIO.new sample_packhdr_le_usec)
        Packet.new stream
      end
      it{expect(packet.sec).to be(1406296714)}
      it{expect(packet.usec).to be(944159)}
      it{expect(packet.cap_len).to be(358)}
      it{expect(packet.orig_len).to be(358)}
    end
  end
end
