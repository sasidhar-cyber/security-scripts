local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[Sends one HTTP OPTIONS request to / and records the Allow header.
This is an observation, not a definitive test of every method.]]
author = "Sasidhar C"
license = "MIT"
categories = {"safe", "discovery"}
portrule = shortport.http

action = function(host, port)
  local response = http.generic_request(host, port, "OPTIONS", "/")
  if not response then return "INCONCLUSIVE: no response to OPTIONS /" end
  local headers = response.header or {}
  local allow = headers["allow"] or headers["Allow"]
  local output = {"Request: OPTIONS /", "HTTP status: " .. tostring(response.status or "unknown")}
  if allow then
    table.insert(output, "Allow header: " .. tostring(allow))
    table.insert(output, "Review whether advertised methods are required.")
  else
    table.insert(output, "No Allow header observed; this does not prove methods are disabled.")
  end
  return stdnse.format_output(true, output)
end
