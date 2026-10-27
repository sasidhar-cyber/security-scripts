local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[Checks an HTTP response for selected browser security headers.
Missing headers are observations, not proof of a vulnerability.]]
author = "Sasidhar C"
license = "MIT"
categories = {"safe", "discovery"}
portrule = shortport.http

action = function(host, port)
  local response = http.get(host, port, "/")
  if not response then return "INCONCLUSIVE: no HTTP response for /" end
  local headers = response.header or {}
  local required = {"x-content-type-options", "content-security-policy", "referrer-policy"}
  local present, missing = {}, {}
  for _, name in ipairs(required) do
    if headers[name] then table.insert(present, name) else table.insert(missing, name) end
  end
  local output = {
    "Checked path: /",
    "Present: " .. (#present > 0 and table.concat(present, ", ") or "none of the selected headers"),
    "Absent: " .. (#missing > 0 and table.concat(missing, ", ") or "none"),
    "Header absence alone does not establish exploitability."
  }
  return stdnse.format_output(true, output)
end
