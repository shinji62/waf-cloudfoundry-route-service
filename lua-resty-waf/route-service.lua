local headers = ngx.req.get_headers()
local cf_header_sign = headers["X-CF-Proxy-Signature"] 
local cf_header_metadata = headers["X-CF-Proxy-Metadata"] 
local cf_header_x_forwarded = headers["X-CF-Forwarded-Url"] 

if not cf_header_metadata or not cf_header_x_forwarded or not cf_header_sign  then
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
end


-- WAF firewall rule
local lua_resty_waf = require "waf"
local waf = lua_resty_waf:new()

-- default options can be overridden
waf:set_option("debug", true)
-- run the firewall


ngx.var.forwarded_url = cf_header_x_forwarded

ngx.header["X-CF-Proxy-Signature"]  = cf_header_sign
ngx.header["X-CF-Proxy-Metadata"]   = cf_header_metadata


waf:exec()





