module PcapParser
  module Proto
    class TCP

      def initialize(bin_header)
        @binhdr=bin_header
      end

      def port_src
        @binhdr[0,2].unpack("n").pop
      end

      def port_dst
        @binhdr[2,2].unpack("n").pop
      end

      def seq
        @binhdr[4,4].unpack("N").pop
      end

      def acknum
        @binhdr[8,4].unpack("N").pop
      end

      def header_len
        (@binhdr[12,1].unpack("C").pop >> 4) << 2
      end

      def [](flag)
        case flag
        when :NS
          # ECN-nonce concealment protection
          (@binhdr[12,1].unpack("C").pop & 7) == 1
        when :CWR
          # Congestion Window Reduced
          (@binhdr[13,1].unpack("C").pop >> 7) == 1
        when :ECE
          # ECN-Echo
          ((@binhdr[13,1].unpack("C").pop >> 6) & 0b1 ) == 1
        when :URG
          # Urgent pointer
          ((@binhdr[13,1].unpack("C").pop >> 5) & 0b1 ) == 1
        when :ACK
          # Acknowledgment
          ((@binhdr[13,1].unpack("C").pop >> 4) & 0b1 ) == 1
        when :PSH
          # Push function
          ((@binhdr[13,1].unpack("C").pop >> 3) & 0b1 ) == 1
        when :RST
          # Reset the connection
          ((@binhdr[13,1].unpack("C").pop >> 2) & 0b1 ) == 1
        when :SYN
          # Synchronize sequence numbers
          ((@binhdr[13,1].unpack("C").pop >> 1) & 0b1 ) == 1
        when :FIN
          # No more data from sender
          (@binhdr[13,1].unpack("C").pop & 0b1 ) == 1
        else
          raise InvalidTCPFlag
        end
      end

      def win_size
        @binhdr[14,2].unpack("n").pop
      end

      def chsum
        @binhdr[16,2].unpack("n").pop
      end

      def has_opts?
        header_len > 20
      end

      def data
        @binhdr[header_len..-1].unpack("a*").pop
      end
    end
  end
end
