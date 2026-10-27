local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[Checks conventional anonymous FTP login on an authorized lab service.
Does not enumerate, list, upload, or download files.]]
author = "Sasidhar C"
license = "MIT"
categories = {"safe", "discovery"}
portrule = shortport.port_or_service(21, "ftp", "tcp")

action = function(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  local ok, err = sock:connect(host, port)
  if not ok then sock:close(); return "INCONCLUSIVE: connection failed: " .. tostring(err) end
  local function read_line()
    local status, line = sock:receive_buf("\r\n", false)
    if status then return line end
    return nil
  end
  local greeting = read_line()
  if not greeting then sock:close(); return "INCONCLUSIVE: no FTP greeting" end
  local sent = sock:send("USER anonymous\r\n")
  local user_reply = sent and read_line() or nil
  if not user_reply then sock:close(); return "INCONCLUSIVE: no USER response" end
  if user_reply:match("^230") then
    sock:send("QUIT\r\n"); sock:close()
    return "OBSERVED: server accepted anonymous login at USER stage; no files accessed."
  end
  if not user_reply:match("^331") then
    sock:send("QUIT\r\n"); sock:close()
    return "Anonymous login not accepted at USER stage. Reply: " .. user_reply
  end
  sock:send("PASS nmap-lab-check@example.invalid\r\n")
  local pass_reply = read_line()
  if pass_reply then sock:send("QUIT\r\n") end
  sock:close()
  if pass_reply and pass_reply:match("^230") then
    return "OBSERVED: anonymous FTP login accepted; no files listed or transferred."
  end
  return "Anonymous login not accepted with fixed test identity. Reply: " .. tostring(pass_reply or "no response")
end
