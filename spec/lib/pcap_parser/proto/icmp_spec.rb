require 'spec_helper'
describe Proto::TCP do
  describe "#new" do
    context "echo packet type" do
      let(:icmp) { Proto::ICMP.new sample_icmp_echo }
      it { expect(icmp.type).to eq(8) }
      it { expect(icmp.code).to eq(0) }
      it { expect(icmp.chsum).to eq(0x1548) }
      it { expect(icmp).to be_valid }
    end
    context "ttl exceeded packet type" do
      let(:icmp) { Proto::ICMP.new sample_icmp_ttle }
      it { expect(icmp.type).to eq(11) }
      it { expect(icmp.code).to eq(0) }
      it { expect(icmp.chsum).to eq(0xc775) }
      it { expect(icmp).to be_valid }
    end
  end
end
