require 'spec_helper'

describe Linktype::Ethernet do
  describe "#new" do
    let(:ethernet) do
      stream = Stream.new(StringIO.new sample_linktype_ether_le_usec)
      linktype = Linktype::Ethernet.new stream
      linktype.read
    end
    it { expect(ethernet.mac_dest_raw).to eq([0x0, 0x11, 0xaa, 0x1a, 0x22, 0x2b]) }
    it { expect(ethernet.mac_dest).to eq('00:11:aa:1a:22:2b') }
    it { expect(ethernet.mac_src_raw).to eq([0xcc, 0xc9, 0xdd, 0xd8, 0x0, 0x7]) }
    it { expect(ethernet.mac_src).to eq('cc:c9:dd:d8:00:07') }
    it { expect(ethernet.ether_type).to eq(0x0800) }
  end
end
