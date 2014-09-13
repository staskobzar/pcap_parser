module PcapParser
  module Proto
    # Internet Control Message Protocol
    # See: http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
    class ICMP
      def initialize(bin_header)
        @binhdr = bin_header
      end

      # ICMP type.
      # See: http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
      # @return [Integer] 8bit unsigned int
      def type
        @binhdr[0].unpack("C").pop
      end

      # ICMP subtype
      # @return [Integer] 8bit unsigned int
      def code
        @binhdr[1].unpack("C").pop
      end

      # Checksum (16 bits)
      # @return [Integer] Big-Endian 16bit int
      def chsum
        @binhdr[2, 2].unpack("n").pop
      end

      # Error checking calculated from the ICMP header and data.
      # @return [true,false] true if packet is valid and has no errors
      def valid?
        0xffff == Proto::sum_pack_16int(@binhdr.unpack("n*"))
      end
    end
  end
end
