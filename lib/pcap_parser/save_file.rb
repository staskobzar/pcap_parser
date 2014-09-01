module PcapParser
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

    def read_packet
      @packet = Packet.new @stream
      linktype.read
      read_ethertype
      read_proto
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
        min,maj = @stream.read_int16(2)
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
        hexstr = @stream.read_raw etype.len
        @ethertype = etype.new hexstr
        if etype.kind_of?(Ethertype::IPv4) && @ethertype.has_opts?
          @ethertype.options = @stream.read_raw(@ethertype.header_len - @ethertype.len)
        end
      end

      def read_proto
        etype = ETHER_TYPE[linktype.ether_type]
        if ethertype.proto_supported?
          @proto=PROTO[ethertype.proto].new @stream.read_raw(ethertype.length - etype.len)
        end
      end
  end
end
