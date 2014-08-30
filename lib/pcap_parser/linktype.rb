require_relative 'linktype/ethernet'
module PcapParser
  module Linktype;end

  LINK_TYPE = {
    1 => Linktype::Ethernet
  }
end
