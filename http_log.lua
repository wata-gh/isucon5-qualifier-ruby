local route = require "normalize_path"
local mysql = require "resty.mysql"
local db, err = mysql:new()
if not db then
  ngx.say("failed to instantiate mysql: ", err)
  return
end
db:set_timeout(1000) -- 1 sec
local ok, err, errcode, sqlstate = db:connect{
  host = "127.0.0.1",
  port = 3306,
  database = "isucon5q",
  user = "isucon",
  password = "isucon",
  max_packet_size = 1024 * 1024 }
if not ok then
  ngx.say("failed to connect: ", err, ": ", errcode, " ", sqlstate)
  return
end

ngx.req.read_body()
local method = ngx.req.get_method() == "GET" and ngx.HTTP_GET or ngx.HTTP_POST

local request_time = ngx.now()
local cap_res = ngx.location.capture("/_app" .. ngx.var.request_uri, { method = method, share_all_vars = true, body = ngx.req.get_body_data() })
y_data() })
request_time = ngx.now() - request_time

local h = cap_res.header
local raw_header = ""
for k, v in pairs(h) do
  raw_header = raw_header .. "\n" .. k .. ": " .. v
end

local normalized_path = route.normalize(ngx.var.uri)

local req_body = ngx.req.get_body_data() == nil and "" or ngx.req.get_body_data()
local sql = "insert into raw_http_logs (request_id, method, normalized_path, path, http_version, req_header, req_body, status, res_header, res_body, res_time) values ("
  .. "  \'" .. ngx.var.request_id .. "\'"      -- request_id
  .. ", \'" .. ngx.req.get_method() .. "\'"    -- method
  .. ", \'" .. normalized_path .. "\'"         -- normalized_path
  .. ", \'" .. ngx.var.uri .. "\'"             -- path
  .. ", \'" .. ngx.req.http_version() .. "\'"  -- http_version
  .. ", \'" .. ngx.req.raw_header() .. "\'"    -- req_header
  .. ", \'" .. req_body .. "\'"                -- req_body
  .. ", \'" .. cap_res.status .. "\'"          -- status
  .. ", \'" .. raw_header .. "\'"              -- res_header
  .. ", \'" .. cap_res.body .. "\'"            -- res_body
  .. ", " .. request_time .. ""                -- res_time
  .. ")"
res, err, errcode, sqlstate = db:query(sql)
if not res then
  ngx.say("bad result: ", err, ": ", errcode, ": ", sqlstate, ".")
  ngx.say(sql)
  return
end

if cap_res then
  ngx.status = cap_res.status
  local h = cap_res.header
  for k, v in pairs(h) do
    ngx.header[k] = v
  end
  ngx.header["X-Lua-Proxy"] = "1"
  ngx.print(cap_res.body)
else
  ngx.say("no response found")
end
