module PcapParser
  # Current IO stream referencing pcap file.
  # Provides interface to read bin data from stream.
  class Stream
    LittleEndian  = :little_endian
    BigEndian     = :big_endian

    PCAP_MAGIC_BE       = 0xa1b2c3d4
    PCAP_MAGIC_LE       = 0xd4c3b2a1
    PCAP_MAGIC_BE_NSEC  = 0xa1b23c4d
    PCAP_MAGIC_LE_NSEC  = 0x4d3cb2a1

    attr_reader :magic

    def initialize(file)
      @file = file
      set_magic
      raise PcapFileTooShort if @file.read(20).length < 20
      @file.pos = 4
    end

    # File byte order: little-endian or big-indian
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
    def little_endian?
      byte_order.equal? LittleEndian
    end

    # Is file byte order big-endian?
    def big_endian?
      byte_order.equal? BigEndian
    end

    # Seconds subtract fraction
    def sec_subt
      if [PCAP_MAGIC_BE_NSEC, PCAP_MAGIC_LE_NSEC].include? magic
        10**-9
      else
        10**-6
      end
    end

    # Read 16bit Integer template string ("v" or "n") 
    # respecting file endianess.
    # @param len [Integer]
    # @return [String] template string len long
    def int16(len = 1)
      ntoh_int(16, len)
    end

    # Read 32bit Integer template string ("V" or "N") 
    # respecting file endianess.
    # @param len [Integer]
    # @return [String] template string len long
    def int32(len = 1)
      ntoh_int(32, len)
    end

    # Read 16bit Integer array from binary stream
    # respecting file endianess.
    # @param len [Integer]
    # @return [Array] 16bit integers
    def read_int16(len = 1)
      @file.read(len * 2).unpack int16(len)
    end

    # Read 32bit Integer array from binary stream
    # respecting file endianess.
    # @param len [Integer]
    # @return [Array] 32bit integers
    def read_int32(len = 1)
      @file.read(len * 4).unpack int32(len)
    end

    # Read unsigned char array from binary stream.
    # @param len [Integer]
    # @return [Array] 8bit characters array
    def read_char(len = 1)
      @file.read(len).unpack("C*")
    end

    # Read raw binary string from stream.
    # @param len [Integer]
    # @return [String]
    def read_raw(len)
      @file.read len
    end

    # Check if end of stream.
    # @return [true, false]
    def eof?
      @file.eof?
    end

    # Check if bit is set (equals 1) in 8bit char.
    # @param byte [Char]
    # @param bit  [Integer] 0 to 8 bit position in char
    def self.bit_set?(byte, bit)
      byte.unpack("C").pop >> (8 - bit) & 0b1 == 1
    end

    private
      # Set magic number of file.
      def set_magic
        mchars = @file.read(4).unpack("C*")
        mchars.reverse! if is_sys_le?
        @magic = mchars.map.with_index { |x, i| x<<(i<<3) }.inject :+
        byte_order
      end

      # System byte order
      def sys_byte_order
        LittleEndian if [0x1a2b3c4d].pack("I").eql? [0x1a2b3c4d].pack("V")
      end

      # Is system byte order is little-endian
      def is_sys_le?; sys_byte_order.equal? LittleEndian; end

      # Int 16/32 big/little endian compliance
      def ntoh_int(bit, len)
        if little_endian?
          bit.eql?(16) ? "v" : "V"
        else
          bit.eql?(16) ? "n" : "N"
        end * len
      end
  end
end
