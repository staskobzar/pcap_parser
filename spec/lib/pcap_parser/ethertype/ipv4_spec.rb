require 'spec_helper'
describe Ethertype::IPv4 do
  describe "#new" do
    context "IPv4 without options" do
      let(:ipv4) do
        Ethertype::IPv4.new "E\x10\x01X\x00\x00@\x00@\x11\xF4I\n\x82\b\x14\n\x84(\""
      end
      it{expect(ipv4.version).to eq(4)}
      it{expect(ipv4.header_len).to eq(20)}
      it{expect(ipv4.has_opts?).to be_falsey}
      it{expect(ipv4.tos).to eq(4)}
      it{expect(ipv4.congestion?).to be_falsey}
      it{expect(ipv4.length).to eq(344)}
      it{expect(ipv4.id).to eq(0)}
      it{expect(ipv4.flag).to eq(2)}
      it{expect(ipv4.frag_offset).to eq(0)}
      it{expect(ipv4.ttl).to eq(64)}
      it{expect(ipv4.proto).to eq(0x11)}
      it{expect(ipv4.chsum).to eq(0xf449)}
      it{expect(ipv4).to be_valid}
      it{expect(ipv4).to be_proto_supported}
      it{expect(ipv4.ip_src).to eq('10.130.8.20')}
      it{expect(ipv4.ip_src_long).to eq(176293908)}
      it{expect(ipv4.ip_dst).to eq('10.132.40.34')}
      it{expect(ipv4.ip_dst_long).to eq(176433186)}
    end
  end
end
