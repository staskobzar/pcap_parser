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

def sample_packhdr_le_msec
   # ts_sec:   1406296714
   # ts_msec:  944159
   # incl_len: 358
   # orig_len: 358
  "\x8Ab\xD2S\x1Fh\x0E\x00f\x01\x00\x00f\x01\x00\x00"
end

def sample_packhdr_be_msec
  "S\xD2b\x8A\x00\x0Eh\x1F\x00\x00\x01f\x00\x00\x01f"
end
