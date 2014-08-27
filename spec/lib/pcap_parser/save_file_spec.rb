require 'spec_helper'

describe SaveFile do
  describe "#new" do

    it{expect{sample_none_pcap_file}.to raise_error(InvalidPcapFile)}

    context "pcap file is too short" do
      before do
        io = StringIO.new "\xD4\xC3\xB2\xA1\x02\x00\x04\x00"
        expect(File).to receive(:open).and_return io
      end
      it{expect{SaveFile.new "somefile.pcap"}.to raise_error(PcapFileTooShort)}
    end

    context "little endian pcap file with microseconds" do
      let(:savefile){sample_little_endian_usec}
      it{expect(savefile.version).to eq("2.4")}
      it{expect(savefile.tz_offset).to be(0)}
      it{expect(savefile.tz_accur).to be(0)}
      it{expect(savefile.snaplen).to be(65535)}
      it{expect(savefile.network).to be(1)}
    end
    context "little endian pcap file with nanoseconds" do
      let(:savefile){sample_little_endian_nsec}
      it{expect(savefile.version).to eq("2.4")}
      it{expect(savefile.tz_offset).to be(0)}
      it{expect(savefile.tz_accur).to be(0)}
      it{expect(savefile.snaplen).to be(65535)}
      it{expect(savefile.network).to be(1)}
    end
    context "big endian pcap file with microseconds" do
      let(:savefile){sample_big_endian_usec}
      it{expect(savefile.version).to eq("2.4")}
      it{expect(savefile.tz_offset).to be(0)}
      it{expect(savefile.tz_accur).to be(0)}
      it{expect(savefile.snaplen).to be(65535)}
      it{expect(savefile.network).to be(1)}
    end
    context "big endian pcap file with nanoseconds" do
      let(:savefile){sample_big_endian_nsec}
      it{expect(savefile.version).to eq("2.4")}
      it{expect(savefile.tz_offset).to be(0)}
      it{expect(savefile.tz_accur).to be(0)}
      it{expect(savefile.snaplen).to be(65535)}
      it{expect(savefile.network).to be(1)}
    end
  end
end
