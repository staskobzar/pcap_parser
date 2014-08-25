module PcapParser
  class SaveFile
    LittleEndian  = :little_endian
    BigEndian     = :big_endian

    PCAP_MAGIC_BE       = 0xa1b2c3d4
    PCAP_MAGIC_LE       = 0xd4c3b2a1
    PCAP_MAGIC_BE_NSEC  = 0xa1b23c4d
    PCAP_MAGIC_LE_NSEC  = 0x4d3cb2a1

    attr_reader :magic
    attr_reader :version
    attr_reader :tz_offset
    attr_reader :tz_accur
    attr_reader :snaplen
    attr_reader :network

    # Open and read pcap file
    def initialize(filename)
      @file = File.open filename, "rb"
      self.magic= @file.read 4
      set_file_attr
    end

    # File byte order
    def byte_order
      if [PCAP_MAGIC_LE, PCAP_MAGIC_LE_NSEC].include? magic
        LittleEndian
      elsif [PCAP_MAGIC_BE, PCAP_MAGIC_BE_NSEC].include? magic
        BigEndian
      else
        raise InvalidPcapFile
      end
    end

    # Is file byte order little-endian?
    def little_endian?; byte_order.equal? LittleEndian;end

    # Is file byte order big-endian?
    def big_endian?; byte_order.equal? BigEndian; end

    # Seconds subtract fraction
    def sec_subt
      if [PCAP_MAGIC_BE_NSEC,PCAP_MAGIC_LE_NSEC].include? magic
        10**-9
      else
        10**-6
      end
    end

    def int16(len=1); ntoh_int(16,len); end
    def int32(len=1); ntoh_int(32,len); end

    private
      # Set magic number of file.
      # @param String 4 bytes magic header. For ex.: \xD4\xC3\xB2\xA1
      def magic=(magic_number)
        mchars = magic_number.unpack("C*")
        mchars.reverse! if is_sys_le?
        @magic = mchars.map.with_index{|x,i| x<<(i<<3)}.inject :+
        byte_order
      end

      # System byte order
      def sys_byte_order
        if [0x1a2b3c4d].pack("I").eql? [0x1a2b3c4d].pack("V")
          LittleEndian
        end
      end

      # Is system byte order is little-endian
      def is_sys_le?; sys_byte_order.equal? LittleEndian; end

      # Int 16/32 big/little endian compliance
      def ntoh_int(bit,len)
        if little_endian?
          bit.eql?(16) ? "v" : "V"
        else
          bit.eql?(16) ? "n" : "N"
        end * len
      end

      # Set up pcap file header attributes:
      # version, timezone offset, timezone accuracy,
      # snapshot length and link layer header type
      def set_file_attr
        @header = @file.read 20 # the rest of pcap header after subtracting magic
        raise PcapFileTooShort if @header.length < 20
        set_version
        set_timezone
        set_len_and_net
      end

      # Setup file version
      def set_version
        min,maj = @header[0..4].unpack int16(2)
        @version = "#{min}.#{maj}"
      end

      # Setup pcap file timezone
      def set_timezone
        @tz_offset, @tz_accur = @header[4..12].unpack int32(2)
      end

      # max length of captured packets, in octets
      # and network data link type
      def set_len_and_net
        @snaplen, @network = @header[12..20].unpack int32(2)
      end
  end
end
