require "./spec_helper"

# Verifies incoming X-Ops headers like a Chef server would: reassemble the
# signature from the numbered headers and check it against the canonical
# request string.
def verify_request(headers, method, path, body, key) : Bool
  signature = x_ops_signature(headers)

  canonical = [
    "Method:#{method.upcase}",
    "Path:#{path}",
    "X-Ops-Content-Hash:#{headers["X-Ops-Content-Hash"]}",
    "X-Ops-Sign:version=1.3",
    "X-Ops-Timestamp:#{headers["X-Ops-Timestamp"]}",
    "X-Ops-UserId:#{headers["X-Ops-Userid"]}",
    "X-Ops-Server-API-Version:#{headers["X-Ops-Server-API-Version"]}",
  ].join("\n")

  key.verify(OpenSSL::Digest.new("SHA256"), Base64.decode(signature), canonical)
end

describe Chef::Client do
  key = OpenSSL::PKey::RSA.new(2048)

  it "sends valid signed requests" do
    received = Channel(NamedTuple(headers: HTTP::Headers, method: String, path: String, body: String)).new(1)

    server = HTTP::Server.new do |context|
      received.send({headers: context.request.headers, method: context.request.method,
                     path: context.request.path, body: context.request.body.try(&.gets_to_end) || ""})
      context.response.headers["Content-Type"] = "application/json"
      context.response.print %({"name":"web"})
    end

    address = server.bind_unused_port
    spawn { server.listen }

    key_file = File.tempfile("chef_key") { |f| f.print(key.to_pem) }
    client = Chef::Client.new("http://#{address}", "integration-client", key_file.path)

    begin
      result = client.get("/nodes/web")
      result["name"].should eq("web")

      req = received.receive
      verify_request(req[:headers], req[:method], req[:path], req[:body], key).should be_true
    ensure
      server.close
      key_file.delete
    end
  end

  it "excludes the query string from the signed path" do
    received = Channel(NamedTuple(headers: HTTP::Headers, path: String)).new(1)

    server = HTTP::Server.new do |context|
      received.send({headers: context.request.headers, path: context.request.path})
      context.response.print ""
    end

    address = server.bind_unused_port
    spawn { server.listen }

    key_file = File.tempfile("chef_key") { |f| f.print(key.to_pem) }
    client = Chef::Client.new("http://#{address}/organizations/myorg", "integration-client", key_file.path)

    begin
      client.get("/nodes?name=web")

      req = received.receive
      req[:path].should eq("/organizations/myorg/nodes")
      verify_request(req[:headers], "GET", req[:path], "", key).should be_true
    ensure
      server.close
      key_file.delete
    end
  end

  it "raises Chef::Error on non-2xx responses" do
    server = HTTP::Server.new do |context|
      context.response.status = :not_found
      context.response.print "not found"
    end

    address = server.bind_unused_port
    spawn { server.listen }

    key_file = File.tempfile("chef_key") { |f| f.print(key.to_pem) }
    client = Chef::Client.new("http://#{address}", "integration-client", key_file.path)

    begin
      expect_raises(Chef::Error, "404") do
        client.get("/nodes/missing")
      end
    ensure
      server.close
      key_file.delete
    end
  end
end
