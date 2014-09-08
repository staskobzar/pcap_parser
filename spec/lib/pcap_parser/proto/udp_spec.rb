require 'spec_helper'
describe Proto::UDP do
  describe "#new" do
    let(:udp) { Proto::UDP.new sample_udp_packet }
    it { expect(udp.port_src).to eq(5060) }
    it { expect(udp.port_dst).to eq(5060) }
    it { expect(udp.length).to eq(324) }
    it { expect(udp.chsum).to eq(18_065) }
    it { expect(udp).to be_valid }
    it { expect(udp.data).to match(%r{^SIP/2\.0 200 OK}) }
    it { expect(udp.data).to match(%r{Content-Length: 0\r\n\r\n$}) }
  end
end
