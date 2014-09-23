# encoding: UTF-8
require "openssl"
require "time"
require "uri"
require "pathname"

module AWS4
  class Signer
    RFC8601BASIC = "%Y%m%dT%H%M%SZ"
    attr_reader :access_key, :secret_key, :region
    attr_reader :date, :method, :uri, :headers, :body, :service

    def initialize(config)
      @access_key = config[:access_key] || config["access_key"]
      @secret_key = config[:secret_key] || config["secret_key"]
      @region = config[:region] || config["region"]
    end

    ## Sign the headers of a request
    # @param [String] Method Method used for the request (GET, POST, etc)
    # @param [String] Service AWS Service to call
    # @param [Uri] URI URI containing the URL for the request
    # @param [String] Date Datetime with a specific format ("%Y%m%dT%H%M%SZ")
    # @param [Hash] Headers Default headers to sign
    # @param [String] Body Body to send inside the request
    # @param [Boolean] Debug True if debug mode is activated
    # @return the signed headers
    def sign(method, uri, headers, body, debug = false, service_name=nil)
      @method = method.upcase
      @uri = uri
      @headers = headers
      @body = body
      @service = service_name || @uri.host.split(".", 2)[0]
      date_header = headers["Date"] || headers["DATE"] || headers["date"]
      @date = (date_header ? Time.parse(date_header) : Time.now).utc.strftime(RFC8601BASIC)
      debug_logs if debug
      signed = headers.dup
      signed['Authorization'] = authorization(headers)
      signed
    end

    private

    def authorization(headers)
      [
        "AWS4-HMAC-SHA256 Credential=#{access_key}/#{credential_string}",
        "SignedHeaders=#{headers.keys.map(&:downcase).sort.join(";")}",
        "Signature=#{signature}"
      ].join(', ')
    end

    def signature
      k_date = hmac("AWS4" + secret_key, date[0,8])
      k_region = hmac(k_date, region)
      k_service = hmac(k_region, service)
      k_credentials = hmac(k_service, "aws4_request")
      hexhmac(k_credentials, string_to_sign)
    end

    def string_to_sign
      [
        'AWS4-HMAC-SHA256',
        date,
        credential_string,
        hexdigest(canonical_request)
      ].join("\n")
    end

    def credential_string
      [
        date[0,8],
        region,
        service,
        "aws4_request"
      ].join("/")
    end

    def canonical_request
      [
        method,
        Pathname.new(uri.path).cleanpath.to_s,
        uri.query,
        headers.sort.map {|k, v| [k.downcase,v.strip].join(':')}.join("\n") + "\n",
        headers.sort.map {|k, v| k.downcase}.join(";"),
        hexdigest(body || '')
      ].join("\n")
    end

    # Hexdigest simply produces an ascii safe way
    # to view the bytes produced from the hash algorithm.
    # It takes the hex representation of each byte
    # and concatenates them together to produce a string
    def hexdigest(value)
      Digest::SHA256.new.update(value).hexdigest
    end

    # Hash-based message authentication code (HMAC)
    # is a mechanism for calculating a message authentication code
    # involving a hash function in combination with a secret key
    def hmac(key, value)
      OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('sha256'), key, value)
    end

    def hexhmac(key, value)
      OpenSSL::HMAC.hexdigest(OpenSSL::Digest::Digest.new('sha256'), key, value)
    end

    def debug_logs
      puts "\n ######  String to sign: \n"
      puts string_to_sign
      puts "\n ######  Canonical_request: \n"
      puts canonical_request
      puts "\n ######  Body: \n"
      puts body
    end
  end
end
