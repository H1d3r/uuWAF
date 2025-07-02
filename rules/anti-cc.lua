--[[
Rule name: Anti CC
Filtering stage: Request phase
Threat level: Medium
Rule description: When the frequency of accessing /api/ path exceeds 360 times per minute, intercept the IP access within 5 minutes
--]]


if not waf.startWith(waf.toLower(waf.uri), "/api/") then
    return false
end

local sh = waf.ipCache
local ccIp = 'cc-' .. waf.ip
local c, f = sh:get(ccIp)
if not c then
    sh:set(ccIp, 1, 60, 1)            -- Set a 60 seconds access count time
else
    if f == 2 then
        return waf.block(true)       -- Reset TCP connection without logging
    end
    sh:incr(ccIp, 1)
    if c + 1 >= 360 then             -- Frequency exceeding 360 times
        sh:set(ccIp, c + 1, 300, 2)  -- Set a 300 second interception time
        return true, ccIp, true      -- Return parameter, the first 'true' is whether it has been detected; The second parameter 'ccIp' is the content of the log record; The third parameter 'true' indicates interception, while 'false' indicates only recording without interception
    end
end

return false