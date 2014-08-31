def new_savefile(header)
  io = StringIO.new header
  expect(File).to receive(:open).and_return io
  SaveFile.new "file.pcap"
end

def vector_le_usec
  "\xD4\xC3\xB2\xA1\x02\x00\x04\x00" +
  "\x00\x00\x00\x00\x00\x00\x00\x00" +
  "\xFF\xFF\x00\x00\x01\x00\x00\x00"
end

def sample_little_endian_usec
  header= vector_le_usec
  new_savefile header
end

def vector_le_nsec
  "\x4D\x3C\xB2\xA1\x02\x00\x04\x00" +
  "\x00\x00\x00\x00\x00\x00\x00\x00" +
  "\xFF\xFF\x00\x00\x01\x00\x00\x00"
end

def sample_little_endian_nsec
  header= vector_le_nsec
  new_savefile header
end

def vector_be_usec
  "\xA1\xB2\xC3\xD4\x00\x02\x00\x04" +
  "\x00\x00\x00\x00\x00\x00\x00\x00" +
  "\x00\x00\xFF\xFF\x00\x00\x00\x01"
end

def sample_big_endian_usec
  header= vector_be_usec
  new_savefile header
end

def vector_be_nsec
  "\xA1\xB2<M\x00\x02\x00\x04" +
  "\x00\x00\x00\x00\x00\x00\x00\x00" +
  "\x00\x00\xFF\xFF\x00\x00\x00\x01"
end

def sample_big_endian_nsec
  header= vector_be_nsec
  new_savefile header
end

def sample_none_pcap_file
  header= "\x1A\xB2\x3C\xD4\x00\x00\x00\x00" +
          "\x00\x00\x00\x00\x00\x00\x00\x00" +
          "\x00\x00\xFF\xFF\x00\x00\x00\x01"
  new_savefile header
end

def sample_packhdr_le_usec
  "\xD4\xC3\xB2\xA1" +
  "\x8Ab\xD2S\x1Fh\x0E\x00f\x01\x00\x00f\x01\x00\x00"+
  "\x00\x00\xFF\xFF\x00\x00\x00\x01" # padding
end

def sample_packhdr_be_usec
  "\xA1\xB2\xC3\xD4" +
  "S\xD2b\x8A\x00\x0Eh\x1F\x00\x00\x01f\x00\x00\x01f"+
  "\x00\x00\xFF\xFF\x00\x00\x00\x01" # padding
end

def sample_packhdr_le_nsec
  "\x4D\x3C\xB2\xA1" +
  "'n\xFES)\xA06)\x1F\x02\x00\x00\x1F\x02\x00\x00" +
  "\x00\x00\xFF\xFF\x00\x00\x00\x01" # padding
end

def sample_packhdr_be_nsec
  "\xA1\xB2<M" +
  "S\xFEn')6\xA0)\x00\x00\x02\x1F\x00\x00\x02\x1F" +
  "\x00\x00\xFF\xFF\x00\x00\x00\x01" # padding
end

def sample_linktype_ether_le_usec
  "\xD4\xC3\xB2\xA1" +
  "\x00\x11\xAA\x1A\"+\xCC\xC9\xDD\xD8\x00\a\b\x00" +
  "\x00\x00\xFF\xFF\x00\x00\x00\x01" # padding
end

def sample_udp_packet
  "\x13\xC4\x13\xC4\x01DF\x91SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.132.40.34:5060;branc" +
  "h=z9hG4bK33062aaec5ca2abf9\r\nFrom: <sip:8487@campus.voip.etsmtl.c" +
  "a>;tag=a9c94de2c7\r\nTo: <sip:7889@campus.voip.etsmtl.ca>;tag=29e0" +
  "49bfbfc261e1c7d62e77ae8573f0.9028\r\nCall-ID: 2b12ce4a4f805824\r\nCS" +
  "eq: 24065 SUBSCRIBE\r\nServer: ETS voip service\r\nContent-Length: 0" +
  "\r\n\r\n"
end
