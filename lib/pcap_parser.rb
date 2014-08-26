require "pcap_parser/version"
require "pcap_parser/save_file"


module PcapParser
  # Exceptions

  # Raise when pcap file is invalid
  class InvalidPcapFile < StandardError;end

  # Raise when pcap file is too short
  class PcapFileTooShort < StandardError; end
end
