module Rbpwn::Crypto
  # Xor a string using the given repeated key
  def xor(str, key)
    str.bytes.zip(key.bytes.cycle).map { |x| x.reduce(:^).chr }.join
  end

  # Pads a string using PKCS#7
  def pkcs7_pad(str, block_size=16)
    n = block_size - (str.size % block_size)
    pad(str, block_size, char=n.chr)
  end

  # Removes PKCS#7 padding from a string
  # Raises an exception when the padding is invalid
  def pkcs7_unpad(str)
    n = str[-1].ord
    if str[-n..-1] != str[-1] * n
      raise 'Pad padding'
    end

    str[0...-n]
  end

  # Pads a string using the given char
  def pad(str, block_size=16, char="\x00")
    n = block_size - (str.size % block_size)
    str + (char * n)
  end

  # Returns an enumerator where elements are the original string but with one bit flipped
  def bitflip(str)
    str = str.bytes

    Enumerator.new do |out|
      str.each.with_index do |_, i|
        7.downto(0).each do |c|
          tmp = str.dup
          tmp[i] ^= (1 << c)

          out << tmp.map(&:chr).join
        end
      end
    end
  end

  # Splits a strings in blocks of at most block_size
  def blocks(str, block_size)
    str.chars.each_slice(block_size).map(&:join).to_a
  end

  class PaddingOracle
    attr_accessor :oracle, :block_size

    def initialize(block_size=16, &block)
      @oracle = block
      @block_size = block_size
    end

    def decrypt(cipher_text)
      parts = blocks(cipher_text, @block_size)
      parts = parts.zip(parts.drop(1))
      parts.pop

      output = parts.map { |(iv, block)|
        decrypt_block(iv, block)
      }.join

      pkcs7_unpad(output)
    end

    def decrypt_block(iv, block)
      plain = "\x00" * @block_size
      padding_value = 1
      new_iv = iv.dup

      (@block_size - 1).downto(0).each do |i|
        found = false

        (0..255).each do |byte|
          new_iv[i] = byte.chr

          if @oracle.(new_iv + block)
            found = true
            plain[i] = (byte ^ iv[i].ord ^ padding_value).chr

            break
          end
        end

        unless found
          raise 'Could not find char at position ' + i.to_s
        end

        padding_value += 1

        (i...@block_size).each do |x|
          new_iv[x] = (new_iv[x].ord ^ padding_value ^ (padding_value - 1)).chr
        end
      end

      plain
    end

    def size(cipher_text)
      unless @oracle.(cipher_text)
        raise 'Cipher text is not valid'
      end

      i = -@block_size * 2

      @block_size.times do
        tmp = cipher_text.dup
        tmp[i] = (tmp[i].ord ^ 0xff).chr

        unless @oracle.(tmp)
          return cipher_text.size + i
        end

        i += 1
      end

      raise 'Unable to find size'
    end

  end
end
