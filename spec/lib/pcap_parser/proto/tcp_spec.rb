require 'spec_helper'
describe Proto::TCP do
  context "with flags ACK and PSH true" do
    describe "#new" do
      let(:tcp){Proto::TCP.new sample_tcp_packet_1}
      it{expect(tcp.port_src).to eq(55615)}
      it{expect(tcp.port_dst).to eq(80)}
      it{expect(tcp.seq).to eq(0xd3196993)}
      it{expect(tcp.acknum).to eq(0x11ad9d2d)}
      it{expect(tcp.header_len).to eq(32)}
      it{expect(tcp[:NS]).to be_falsey}
      it{expect(tcp[:CWR]).to be_falsey}
      it{expect(tcp[:ECE]).to be_falsey}
      it{expect(tcp[:URG]).to be_falsey}
      it{expect(tcp[:ACK]).to be_truthy}
      it{expect(tcp[:PSH]).to be_truthy}
      it{expect(tcp[:RST]).to be_falsey}
      it{expect(tcp[:SYN]).to be_falsey}
      it{expect(tcp[:FIN]).to be_falsey}
      it{expect(tcp.win_size).to eq(8280)}
      it{expect(tcp.chsum).to eq(0x97bc)}
      it{expect(tcp.has_opts?).to be_truthy}
      it{expect(tcp.data).to match(%r{^GET /wiki/Transmission_Control_Protocol HTTP/1\.1})}
      it{expect(tcp.data).to match(%r{16:41:06 GMT\r\n\r\n$})}
    end
  end
  context "with " do
    describe "#new" do
      let(:tcp){Proto::TCP.new sample_tcp_packet_2}
      it{expect(tcp.port_src).to eq(55615)}
      it{expect(tcp.port_dst).to eq(80)}
      it{expect(tcp.seq).to eq(0xd3196993)}
      it{expect(tcp.acknum).to eq(0x11ad9d2d)}
      it{expect(tcp.header_len).to eq(20)}
      it{expect(tcp[:NS]).to be_truthy}
      it{expect(tcp[:CWR]).to be_falsey}
      it{expect(tcp[:ECE]).to be_truthy}
      it{expect(tcp[:URG]).to be_falsey}
      it{expect(tcp[:ACK]).to be_falsey}
      it{expect(tcp[:PSH]).to be_truthy}
      it{expect(tcp[:RST]).to be_falsey}
      it{expect(tcp[:SYN]).to be_truthy}
      it{expect(tcp[:FIN]).to be_falsey}
      it{expect(tcp.win_size).to eq(8280)}
      it{expect(tcp.chsum).to eq(0x97bc)}
      it{expect(tcp.has_opts?).to be_falsey}
    end
  end
end
