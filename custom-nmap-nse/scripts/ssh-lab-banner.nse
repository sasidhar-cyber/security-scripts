local comm = require "comm"
local shortport = require "shortport"

description = [[Records the SSH identification banner. Does not attempt authentication.]]
author = "Sasidhar C"
license = "MIT"
categories = {"safe", "discovery"}
portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local banner = comm.get_banner(host, port, {timeout = 5000})
  if not banner then return "INCONCLUSIVE: no SSH banner received" end
  banner = banner:gsub("[%c]", " ")
  return "Observed SSH identification: " .. banner ..
    "\nVersion strings are inventory evidence, not proof of vulnerability."
end
