module PcapParser
  class Packet
    attr_reader :sec, :cap_len, :orig_len
    def initialize(stream)
      @sec,
      @sec_frac,
      @cap_len,
      @orig_len = stream.read_int32(4)
      @sec_subt = stream.sec_subt
    end

    def usec
      (@sec_frac.to_f * @sec_subt / 10**-6).round
    end

    def nsec
      (@sec_frac.to_f * @sec_subt / 10**-9).round
    end
  end
end
