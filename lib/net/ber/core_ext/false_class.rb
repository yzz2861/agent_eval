# -*- ruby encoding: utf-8 -*-
##
# BER extensions to +false+.
module Net::BER::Extensions::FalseClass
  ##
  # Converts +false+ to the BER wireline representation of +false+.
  def to_ber
    "\001\001\000"
  end

  def to_ber_contextspecific(code)
    to_ber[0] + to_ber[1] + (0x80 + code).chr
  end
end
