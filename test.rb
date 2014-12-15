#!/usr/bin/env ruby

require 'openssl'
require 'zk'
require 'base64'

module ZK
module Client
  class Base

    def add_auth(*args)
      opts = args.extract_options!
      call_and_check_rc(:add_auth, opts )
    end
  end
end
end

z = ZK.new("localhost:2181")

secret = z.session_id.to_s
#secret = '92968746517135398'
passwd = 'ro6nie9oobeih3ye0ahc2oopeepool7eijie8fah5raGh3th'

puts "session id: #{secret}"
puts "passwd: #{passwd}"

signed = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('sha1'), secret.encode("UTF-8"), passwd.encode("UTF-8"))

z.add_auth({ :scheme => "hmac", :cert => "testuser:"+signed })

puts signed
