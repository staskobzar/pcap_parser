require 'spec_helper'

describe SaveFile do
  describe "#new" do

    it { expect { sample_none_pcap_file }.to raise_error(InvalidPcapFile) }

    context "pcap file is too short" do
      before do
        io = StringIO.new "\xD4\xC3\xB2\xA1\x02\x00\x04\x00"
        expect(File).to receive(:open).and_return io
      end
      it { expect { SaveFile.new "somefile.pcap" }.to raise_error(PcapFileTooShort) }
    end

    context "little endian pcap file with microseconds" do
      let(:savefile) { sample_little_endian_usec }
      it { expect(savefile.version).to eq("2.4") }
      it { expect(savefile.tz_offset).to be(0) }
      it { expect(savefile.tz_accur).to be(0) }
      it { expect(savefile.snaplen).to be(65_535) }
      it { expect(savefile.network).to be(1) }
    end
    context "little endian pcap file with nanoseconds" do
      let(:savefile) { sample_little_endian_nsec }
      it { expect(savefile.version).to eq("2.4") }
      it { expect(savefile.tz_offset).to be(0) }
      it { expect(savefile.tz_accur).to be(0) }
      it { expect(savefile.snaplen).to be(65_535) }
      it { expect(savefile.network).to be(1) }
    end
    context "big endian pcap file with microseconds" do
      let(:savefile) { sample_big_endian_usec }
      it { expect(savefile.version).to eq("2.4") }
      it { expect(savefile.tz_offset).to be(0) }
      it { expect(savefile.tz_accur).to be(0) }
      it { expect(savefile.snaplen).to be(65_535) }
      it { expect(savefile.network).to be(1) }
    end
    context "big endian pcap file with nanoseconds" do
      let(:savefile) { sample_big_endian_nsec }
      it { expect(savefile.version).to eq("2.4") }
      it { expect(savefile.tz_offset).to be(0) }
      it { expect(savefile.tz_accur).to be(0) }
      it { expect(savefile.snaplen).to be(65_535) }
      it { expect(savefile.network).to be(1) }
    end
  end
  describe "#read_packet" do
    let(:pcap) do
      savefile = SaveFile.new pcap_sample("udp_sip")
      savefile.read_packet
    end
    it { expect(pcap.packet.sec).to eq(1_409_205_286) }
    it { expect(pcap.packet.usec).to eq(509_412) }
    it { expect(pcap.packet.nsec).to eq(509_412_000) }
    it { expect(pcap.packet.cap_len).to eq(820) }
    it { expect(pcap.packet.orig_len).to eq(820) }
    it { expect(ETHER_TYPE[pcap.linktype.ether_type]).to eq(Ethertype::IPv4) }
    it { expect(pcap.linktype.mac_src).to eq('00:0f:35:9a:c4:00') }
    it { expect(pcap.linktype.mac_dest).to eq('00:50:56:bc:4f:b4') }
    it { expect(pcap.ethertype.version).to eq(4) }
    it { expect(pcap.ethertype.header_len).to eq(20) }
    it { expect(pcap.ethertype.length).to eq(806) }
    it { expect(pcap.ethertype).to be_proto_supported }
    it { expect(pcap.ethertype).to be_valid }
    it { expect(pcap.ethertype.ip_src).to eq('10.132.88.62') }
    it { expect(pcap.ethertype.ip_dst).to eq('10.130.8.20') }
    it { expect(pcap.proto.port_src).to eq(5060) }
    it { expect(pcap.proto.port_dst).to eq(5060) }
    it { expect(pcap.proto.length).to eq(786) }
    it { expect(pcap.proto.data).to match(/^REGISTER /) }
    it { expect(pcap.proto.data).to match(/Call-ID: ced7ac50-1eb55938-114fc070@10\.132\.88\.62/) }
    it { expect(pcap.proto.data).to match(/Content-Length: 0\r\n\r\n$/) }
  end

  describe "#each_packet" do
    it "read file ethernet udp and count of packets is 5" do
      savefile = SaveFile.new pcap_sample("udp_sip")
      ips = %w{10.132.88.62 10.130.8.20 10.164.121.7 10.160.160.71 10.130.8.20}
      ports = [5060,5060,53353,59416,5060]
      frames = 0
      savefile.each_packet do |packet|
        expect(packet.ethertype.ip_src).to eq(ips.shift)
        expect(packet.proto.port_src).to eq(ports.shift)
        frames = frames.succ
      end
      expect(frames).to eq(5)
    end
  end
end
