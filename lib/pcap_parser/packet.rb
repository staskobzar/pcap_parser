module PcapParser
  class Packet
    attr_reader :sec, :usec, :cap_len, :orig_len
    def initialize(stream)
      @sec,
      @usec,
      @cap_len,
      @orig_len = stream.read_int32(4)
    end
  end
end
