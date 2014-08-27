module PcapParser
  class SaveFile

    attr_reader :version
    attr_reader :tz_offset
    attr_reader :tz_accur
    attr_reader :snaplen
    attr_reader :network

    # Open and read pcap file
    def initialize(filename)
      @stream = Stream.new(File.open filename, "rb")
      set_file_attr
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
      end
  end
end
