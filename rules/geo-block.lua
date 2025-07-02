--[[
Rule name: Regional access restrictions
Filtering stage: Request phase
Threat level: Low
Rule description: Restrict access to designated countries
--]]


local country, province, city = waf.ip2loc(waf.ip)
if country ~= "United States" and country ~= "" then
      return true, "Restrict access to designated countries", true
end
return false
