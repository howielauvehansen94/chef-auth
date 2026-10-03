require "./spec_helper"

describe Chef::Auth do
  key = OpenSSL::PKey::RSA.new(2048)
  auth = Chef::Auth.new("test-client", key)

  describe ".canonical_path" do
    it "collapses repeated slashes" do
      Chef::Auth.canonical_path("/organizations//org//nodes").should eq("/organizations/org/nodes")
    end

    it "strips a trailing slash" do
      Chef::Auth.canonical_path("/organizations/org/nodes/").should eq("/organizations/org/nodes")
    end

    it "keeps a bare root path" do
      Chef::Auth.canonical_path("/").should eq("/")
    end
  end

  describe "#sign!" do
    it "sets the standard X-Ops headers" do
      headers = auth.sign!(HTTP::Headers.new, "GET", "/organizations/org/nodes", "")
      headers["X-Ops-Sign"].should eq("algorithm=sha256;version=1.3")
      headers["X-Ops-Userid"].should eq("test-client")
      headers["X-Ops-Server-API-Version"].should eq("1")
      headers["X-Ops-Timestamp"].should match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)
      headers["X-Ops-Content-Hash"].should eq(
        Base64.strict_encode(OpenSSL::Digest.new("SHA256").update("").final)
      )
    end

    it "produces a signature verifiable against the canonical request" do
      headers = auth.sign!(HTTP::Headers.new, "POST", "/organizations/org/nodes", %({"name":"web"}))

      signature = x_ops_signature(headers)
      canonical = auth.canonical_request(
        "POST", "/organizations/org/nodes",
        headers["X-Ops-Content-Hash"], headers["X-Ops-Timestamp"]
      )

      key.verify(OpenSSL::Digest.new("SHA256"), Base64.decode(signature), canonical).should be_true
    end

    it "splits the signature into 60-char chunks" do
      headers = auth.sign!(HTTP::Headers.new, "GET", "/organizations/org/nodes", "")
      chunks = [] of Tuple(String, String)
      headers.each do |name, values|
        next unless name.starts_with?("X-Ops-Authorization-")
        values.each { |v| chunks << {name, v} }
      end
      chunks.size.should be > 1
      chunks.each { |_, value| value.size.should be <= 60 }
    end
  end

  it "loads a key from PEM content" do
    from_pem = Chef::Auth.new("test-client", key.to_pem)
    headers = from_pem.sign!(HTTP::Headers.new, "GET", "/nodes", "")
    headers["X-Ops-Userid"].should eq("test-client")
  end
end
