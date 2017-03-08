require 'base64'
require 'digest'

module Rbpwn::String
  def base64_encode(str)
    Base64.strict_encode64(str)
  end

  def base64_decode(str)
    Base64.decode64(str)
  end

  def hex(str)
    str.unpack('H*')[0]
  end

  def unhex(str)
    [str].pack('H*')
  end

  def md5(str)
    Digest::MD5.hexdigest(str)
  end

  def sha1(str)
    Digest::SHA1.hexdigest(str)
  end

  def sha256(str)
    Digest::SHA256.hexdigest(str)
  end

  def sha512(str)
    Digest::SHA512.hexdigest(str)
  end
end
