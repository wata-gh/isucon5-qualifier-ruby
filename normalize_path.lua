local P = {}

function string.starts(String, Start)
  return string.sub(String, 1, string.len(Start)) == Start
end

local function normalize(method, path)
  local normalized_path = path
  if string.starts(path, "/profile/") then
    normalized_path = "/profile/:account_name"
  elseif string.starts(path, "/diary/entries/") then
    normalized_path = "/diary/entries/:account_name"
  elseif string.starts(path, "/diary/entry/") then
    normalized_path = "/diary/entry/:entry_id"
  elseif string.starts(path, "/diary/comment/") then
    normalized_path = "/diary/comment/:entry_id"
  elseif string.starts(path, "/friends/") then
    normalized_path = "/friends/:account_name"
  end
  return method .. " " .. normalized_path
end

P.normalize = normalize
return P
