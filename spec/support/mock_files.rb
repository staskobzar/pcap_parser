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
  header = vector_le_usec
  new_savefile header
end

def vector_le_nsec
  "\x4D\x3C\xB2\xA1\x02\x00\x04\x00" +
  "\x00\x00\x00\x00\x00\x00\x00\x00" +
  "\xFF\xFF\x00\x00\x01\x00\x00\x00"
end

def sample_little_endian_nsec
  header = vector_le_nsec
  new_savefile header
end

def vector_be_usec
  "\xA1\xB2\xC3\xD4\x00\x02\x00\x04" +
  "\x00\x00\x00\x00\x00\x00\x00\x00" +
  "\x00\x00\xFF\xFF\x00\x00\x00\x01"
end

def sample_big_endian_usec
  header = vector_be_usec
  new_savefile header
end

def vector_be_nsec
  "\xA1\xB2<M\x00\x02\x00\x04" +
  "\x00\x00\x00\x00\x00\x00\x00\x00" +
  "\x00\x00\xFF\xFF\x00\x00\x00\x01"
end

def sample_big_endian_nsec
  header = vector_be_nsec
  new_savefile header
end

def sample_none_pcap_file
  header = "\x1A\xB2\x3C\xD4\x00\x00\x00\x00" +
          "\x00\x00\x00\x00\x00\x00\x00\x00" +
          "\x00\x00\xFF\xFF\x00\x00\x00\x01"
  new_savefile header
end

def sample_packhdr_le_usec
  "\xD4\xC3\xB2\xA1" +
  "\x8Ab\xD2S\x1Fh\x0E\x00f\x01\x00\x00f\x01\x00\x00" +
  "\x00\x00\xFF\xFF\x00\x00\x00\x01" # padding
end

def sample_packhdr_be_usec
  "\xA1\xB2\xC3\xD4" +
  "S\xD2b\x8A\x00\x0Eh\x1F\x00\x00\x01f\x00\x00\x01f" +
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

def sample_tcp_packet_1
  "\xD9?\x00P\xD3\x19i\x93\x11\xAD\x9D-\x80\x18 X\x97\xBC\x00\x00\x01\x01\b" +
  "\n6\xA6w\xC8\vu\xE1\x18GET /wiki/Transmission_Control_Protocol HTTP/1.1"  +
  "\r\nHost: en.wikipedia.org\r\nConnection: keep-alive\r\nCache-Control: "  +
  "max-age=0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0" +
  ".9,image/webp,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac " +
  "OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 " +
  "Safari/537.36\r\nReferer: http://en.wikipedia.org/wiki/Internet_Control_" +
  "Message_Protocol\r\nAccept-Encoding: gzip,deflate,sdch\r\nAccept-Language " +
  ": en-US,en;q=0.8,fr;q=0.6,ru;q=0.4,uk;q=0.2,pl;q=0.2\r\nCookie: centralno" +
  "tice_bannercount_fr12=55; centralnotice_bannercount_fr12-wait=34; central" +
  "notice_bannercount_wikimania14=1; centralnotice_bannercount_wikimania14-w" +
  "ait=4%7C1406979878894%7C0; centralnotice_only2times_tou=2; centralnotice_" +
  "only2times_tou-wait=19%7C1405617496119%7C0; GeoIP=CA:Montr_al:45.5000:-73" +
  ".5833:v4; uls-previous-languages=%5B%22en%22%5D; mediaWiki.user.sessionId" +
  "=UqdAIM4TSXOFMevKNqOszyCSwigFYpsc; centralnotice_bucket=1-4.2\r\nIf-Modif" +
  "ied-Since: Sun, 31 Aug 2014 16:41:06 GMT\r\n\r\n"
end

def sample_tcp_packet_2
  "\xD9?\x00P\xD3\x19i\x93\x11\xAD\x9D-QJ X\x97\xBC\x00\x00\x01\x01\b" +
  "\n6\xA6w\xC8\vu\xE1\x18GET /wiki/Transmission_Control_Protocol HTTP/1.1"  +
  "\r\nHost: en.wikipedia.org\r\nConnection: keep-alive\r\nCache-Control: "  +
  "max-age=0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0" +
  ".9,image/webp,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac " +
  "OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 " +
  "Safari/537.36\r\nReferer: http://en.wikipedia.org/wiki/Internet_Control_" +
  "Message_Protocol\r\nAccept-Encoding: gzip,deflate,sdch\r\nAccept-Language " +
  ": en-US,en;q=0.8,fr;q=0.6,ru;q=0.4,uk;q=0.2,pl;q=0.2\r\nCookie: centralno" +
  "tice_bannercount_fr12=55; centralnotice_bannercount_fr12-wait=34; central" +
  "notice_bannercount_wikimania14=1; centralnotice_bannercount_wikimania14-w" +
  "ait=4%7C1406979878894%7C0; centralnotice_only2times_tou=2; centralnotice_" +
  "only2times_tou-wait=19%7C1405617496119%7C0; GeoIP=CA:Montr_al:45.5000:-73" +
  ".5833:v4; uls-previous-languages=%5B%22en%22%5D; mediaWiki.user.sessionId" +
  "=UqdAIM4TSXOFMevKNqOszyCSwigFYpsc; centralnotice_bucket=1-4.2\r\nIf-Modif" +
  "ied-Since: Sun, 31 Aug 2014 16:41:06 GMT\r\n\r\n"
end

def sample_icmp_ttle
  "\v\x00\xC7u\x00\x00\x00\x00E\x00\x004\xE6\x8A\x00\x00\x01\x11\x00\xEB\xC0" +
  "\xA8\x01\x8C\b\b\b\b\xE6\x88\x82\x9C\x00 \xC4D\x00\x00\x00\x00\x00\x00"    +
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
end

def sample_icmp_echo
  "\b\x00\x15H\xA5h\x00\x00T\v!H\x00\x04\xDC\xF4\b\t\n\v\f\r\x0E\x0F\x10\x11" +
  "\x12\x13\x14\x15\x16\x17\x18\x19\x1A\e\x1C\x1D\x1E\x1F !\"\#$%&'()*+,-./01234567"
end
