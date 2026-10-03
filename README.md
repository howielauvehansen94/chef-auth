# chef-auth

Chef Infra API v1.3 signed-header authentication and API client for Crystal.

Signs requests with an RSA key using the same wire format as
[mixlib-authentication](https://github.com/chef/mixlib-authentication) (the
`X-Ops-*` headers), so it works against any Chef Infra server or compatible
API.

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  chef-auth:
    github: howielauvehansen94/chef-auth
```

## Usage

```crystal
require "chef-auth"

client = Chef::Client.new(
  "https://chef.example.com/organizations/myorg",
  "my-client-name",
  "~/.chef/my-client.pem"
)

# GET /organizations/myorg/nodes
nodes = client.get("/nodes")

# POST with JSON body (Hash / NamedTuple / JSON::Any)
node = client.post("/nodes", {name: "web", run_list: ["role[base]"]})

# PUT /organizations/myorg/nodes/web with the updated node
client.put("/nodes/web", node)

# DELETE
client.delete("/nodes/web")

# Raw (non-JSON) response body, e.g. cookbook file contents
client.get_raw("/organizations/myorg/cookbooks/apache2/recipes/default.rb")

# Query strings are sent but excluded from the signature, as Chef requires
client.get("/nodes?name=web")
```

Non-2xx responses raise `Chef::Error` with a `status` getter.

### Signing only

If you only need the request-signing logic (e.g. for your own HTTP layer),
use `Chef::Auth` directly:

```crystal
auth = Chef::Auth.new("my-client-name", File.read("~/.chef/my-client.pem"))
auth.sign!(headers, "GET", "/organizations/myorg/nodes", "")
# headers now carries X-Ops-Sign, X-Ops-Userid, X-Ops-Timestamp,
# X-Ops-Content-Hash and the split X-Ops-Authorization-N signature headers
```

## SSL

`Chef::Client` verifies TLS certificates by default; pass `verify_ssl: false`
as the fourth argument to disable verification.

## Development

```
shards install
crystal spec
```

## License

MIT — see [LICENSE](LICENSE).
