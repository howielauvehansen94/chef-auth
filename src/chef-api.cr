require "http/client"
require "json"
require "uri"
require "base64"
require "openssl"
require "openssl_ext"

module Chef
  class Error < Exception
    getter status

    def initialize(@status : Int32, body)
      super("Chef API #{@status}: #{body}")
    end
  end

  # Signs HTTP request headers for the Chef Infra API using v1.3
  # signed-header authentication (the mixlib-authentication wire format).
  #
  # The canonical request string is RSA-SHA256 signed and the signature is
  # split into 60-character chunks across numbered `X-Ops-Authorization-N`
  # headers, because Chef limits individual header line length.
  class Auth
    API_VERSION    = "1"
    SIGN_VERSION   = "1.3"
    SIGN_ALGORITHM = "sha256"

    def initialize(@client_name : String, @key : OpenSSL::PKey::RSA)
    end

    # Loads an RSA private key from PEM-encoded content.
    def self.new(client_name : String, key : String)
      new(client_name, OpenSSL::PKey::RSA.new(key))
    end

    # Signs *headers* in place for a request of *method* to the canonical
    # *path* with *body* as the request body. Returns the same headers.
    def sign!(headers : HTTP::Headers, method, path, body) : HTTP::Headers
      timestamp = Time.utc.to_s("%Y-%m-%dT%H:%M:%SZ")
      content_hash = content_hash(body)

      canonical = canonical_request(method, path, content_hash, timestamp)
      signature = Base64.strict_encode(@key.sign(OpenSSL::Digest.new(SIGN_ALGORITHM), canonical))

      headers["X-Ops-Sign"] = "algorithm=#{SIGN_ALGORITHM};version=#{SIGN_VERSION}"
      headers["X-Ops-Userid"] = @client_name
      headers["X-Ops-Timestamp"] = timestamp
      headers["X-Ops-Content-Hash"] = content_hash
      headers["X-Ops-Server-API-Version"] = API_VERSION

      signature.scan(/.{1,60}/).each_with_index do |m, i|
        headers["X-Ops-Authorization-#{i + 1}"] = m[0]
      end

      headers
    end

    # The string that is covered by the RSA signature.
    def canonical_request(method, path, content_hash, timestamp) : String
      [
        "Method:#{method.upcase}",
        "Path:#{path}",
        "X-Ops-Content-Hash:#{content_hash}",
        "X-Ops-Sign:version=#{SIGN_VERSION}",
        "X-Ops-Timestamp:#{timestamp}",
        "X-Ops-UserId:#{@client_name}",
        "X-Ops-Server-API-Version:#{API_VERSION}",
      ].join("\n")
    end

    # The server normalizes the path before verifying the signature, so the
    # signed path must match: collapse repeated slashes and strip a trailing
    # slash (unless the path is just "/").
    def self.canonical_path(p)
      p = p.gsub(/\/+/, "/")
      p.size > 1 ? p.chomp("/") : p
    end

    private def content_hash(body)
      Base64.strict_encode(OpenSSL::Digest.new(SIGN_ALGORITHM).update(body).final)
    end
  end

  class Client
    API_VERSION = Auth::API_VERSION

    def initialize(@server_url : String, @client_name : String, key_path, @verify_ssl : Bool = true)
      @uri = URI.parse(@server_url)
      @auth = Auth.new(@client_name, File.read(key_path))
    end

    def get(path)
      request("GET", path)
    end

    def delete(path)
      request("DELETE", path)
    end

    def post(path, body : JSON::Any | Hash | NamedTuple)
      request("POST", path, body.to_json)
    end

    def put(path, body : JSON::Any | Hash | NamedTuple)
      request("PUT", path, body.to_json)
    end

    def get_raw(path)
      perform("GET", path, "")
    end

    def request(method, path, body = "")
      raw = perform(method, path, body)
      raw.empty? ? JSON::Any.new(nil) : JSON.parse(raw)
    end

    private def perform(method, path, body)
      # Query string is excluded from the signed path but sent on the request.
      full_path = Auth.canonical_path("#{@uri.path}/#{path}")
      query = nil
      if idx = path.index('?')
        full_path = Auth.canonical_path("#{@uri.path}/#{path[0...idx]}")
        query = path[(idx + 1)..]
      end

      headers = HTTP::Headers{
        "Accept"         => "application/json",
        "Content-Type"   => "application/json",
        "X-Chef-Version" => "18.0.0",
      }
      @auth.sign!(headers, method, full_path, body)

      tls = nil
      if @uri.scheme == "https"
        tls = OpenSSL::SSL::Context::Client.new
        tls.verify_mode = OpenSSL::SSL::VerifyMode::NONE unless @verify_ssl
      end

      client = HTTP::Client.new(@uri.host.not_nil!, @uri.port, tls: tls)
      target = query ? "#{full_path}?#{query}" : full_path
      resp = client.exec(method, target, headers: headers, body: body.empty? ? nil : body)
      raise Error.new(resp.status_code, resp.body) unless resp.success?
      resp.body
    ensure
      client.try &.close
    end
  end
end
