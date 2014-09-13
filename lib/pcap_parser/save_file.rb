module PcapParser
  # Top pcap_parser class.
  # Reads libpcap per-file header.
  # Header details: http://www.tcpdump.org/manpages/pcap-savefile.5.txt
  class SaveFile
    attr_reader :version
    attr_reader :tz_offset
    attr_reader :tz_accur
    attr_reader :snaplen
    attr_reader :network
    attr_reader :packet
    attr_reader :linktype
    attr_reader :ethertype
    attr_reader :proto

    # Open and read pcap file
    def initialize(filename)
      @stream = Stream.new(File.open filename, "rb")
      set_file_attr
    end

    # Loop through all packets in the file.
    # Expects block as an argument. 
    # Example:
    # ```
    # SaveFile.each_packet |packet| do
    #   pp packet
    # end
    # ```
    def each_packet
      yield read_packet until @stream.eof?
    end

    # Read whole packet 
    # @return [SaveFile]
    def read_packet
      @packet = Packet.new @stream
      linktype.read
      read_ethertype
      read_proto
      read_padding
      self
    end

    private
      # Set up pcap file header attributes:
      # version, timezone offset, timezone accuracy,
      # snapshot length and link layer header type
      def set_file_attr
        set_version
        set_timezone
        set_len_and_net
      end

      # Setup file version
      def set_version
        min, maj = @stream.read_int16(2)
        @version = "#{min}.#{maj}"
      end

      # Setup pcap file timezone
      def set_timezone
        @tz_offset, @tz_accur = @stream.read_int32(2)
      end

      # max length of captured packets, in octets
      # and network data link type
      def set_len_and_net
        @snaplen, @network = @stream.read_int32(2)
        raise LinkTypeNotSupported if LINK_TYPE[@network].nil?
        @linktype = LINK_TYPE[@network].new @stream
      end

      def read_ethertype
        etype = ETHER_TYPE[linktype.ether_type]
        hexstr = @stream.read_raw etype::LENGTH
        @ethertype = etype.new hexstr
        if etype.kind_of?(Ethertype::IPv4) && ethertype.has_opts?
          ethertype.options = @stream.read_raw(ethertype.header_len - etype::LENGTH)
        end
      end

      def read_proto
        etype = ETHER_TYPE[linktype.ether_type]
        if ethertype.proto_supported?
          @proto = PROTO[ethertype.proto].new @stream.read_raw(ethertype.length - etype::LENGTH)
        else
          raise ProtoNotSupported
        end
      end

      def linktype_len
        LINK_TYPE[network]::LENGTH
      end

      def ethertype_len
        ETHER_TYPE[linktype.ether_type]::LENGTH
      end

      # packet padding if length is <=60
      def read_padding
        if packet.cap_len <= 60
          @stream.read_raw(packet.cap_len - linktype_len - ethertype_len - proto.length)
        end
      end
  end
end
