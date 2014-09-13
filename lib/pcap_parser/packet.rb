module PcapParser
  # Per-packet header of pcap file
  # See: http://www.tcpdump.org/manpages/pcap-savefile.5.txt
  class Packet
    attr_reader :sec, :cap_len, :orig_len
    def initialize(stream)
      @sec,
      @sec_frac,
      @cap_len,
      @orig_len = stream.read_int32(4)
      @sec_subt = stream.sec_subt
    end

    # Convert timestamp fraction to microseconds
    # @return [Integer] microseconds
    def usec
      (@sec_frac.to_f * @sec_subt / 10**-6).round
    end

    # Convert timestamp fraction to nanoseconds
    # @return [Integer] nanoseconds
    def nsec
      (@sec_frac.to_f * @sec_subt / 10**-9).round
    end
  end
end
