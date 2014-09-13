module PcapParser
  module Proto
    # TCP protocol read.
    # Segment structure: http://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure
    # Read values are big-endian (network byte order)
    class TCP
      def initialize(bin_header)
        @binhdr = bin_header
      end

      # Source port.
      # @return [Integer] Big-Endian 16bit int
      def port_src
        @binhdr[0, 2].unpack("n").pop
      end

      # Destination port.
      # @return [Integer] Big-Endian 16bit int
      def port_dst
        @binhdr[2, 2].unpack("n").pop
      end

      # Sequence number
      # @return [Integer] Big-Endian 32bit int
      def seq
        @binhdr[4, 4].unpack("N").pop
      end

      # Acknowledgment number (if ACK set)
      # @return [Integer] Big-Endian 32bit int
      def acknum
        @binhdr[8, 4].unpack("N").pop
      end

      # Data offset (4 bits)
      # @return [Integer] from 5 to 15
      def header_len
        (@binhdr[12, 1].unpack("C").pop >> 4) << 2
      end

      # Flags (9 bits) (aka Control bits)
      # @return [true,false] true if flag set
      def [](flag)
        bit = { NS: 8, CWR: 1, ECE: 2, URG: 3, ACK: 4, PSH: 5, RST: 6, SYN: 7, FIN: 8 }
        Stream::bit_set?(@binhdr[flag.eql?(:NS) ? 12 : 13], bit[flag])
      end

      # Window size (16 bits)
      # @return [Integer] Big-Endian 16bit int
      def win_size
        @binhdr[14, 2].unpack("n").pop
      end

      # Checksum (16 bits)
      # @return [Integer] Big-Endian 16bit int
      def chsum
        @binhdr[16, 2].unpack("n").pop
      end

      # Check if options set in TCP segment.
      # @return [true,false] true if options segement is set
      def has_opts?
        header_len > 20
      end

      # TCP segment data.
      # @return [String]
      def data
        @binhdr[header_len..-1].unpack("a*").pop
      end
    end
  end
end
