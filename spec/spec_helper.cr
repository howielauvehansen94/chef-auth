require "spec"
require "../src/chef-auth"

# Reassembles the full signature from the numbered X-Ops-Authorization-N
# headers, in order.
def x_ops_signature(headers : HTTP::Headers) : String
  chunks = [] of Tuple(String, String)
  headers.each do |name, values|
    next unless name.starts_with?("X-Ops-Authorization-")
    values.each { |v| chunks << {name, v} }
  end
  chunks.sort_by { |name, _| name.split('-').last.to_i }.map(&.[1]).join
end
