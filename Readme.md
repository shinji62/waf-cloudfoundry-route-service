
## Description

**POC** please do not use to production.
Still not working properly under development

This project use https://github.com/p0pr0ck5/lua-resty-waf which is based on Openresty


### Explanation
Request going to the final application, will first go the "route service" which in this case is the WAF and this one will 
proxy the request to the final application


Route Service documentation can be found here https://docs.cloudfoundry.org/services/route-services.html

![Route Service](https://docs.cloudfoundry.org/services/images/route-services-user-provided.png)

### Route service logic is inside `lua/route-service.lua`

```lua 
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


waf:exec()

```

### Nginx Conf
```nginx
worker_processes 1;
error_log stderr notice;

events { worker_connections 1024;}



http {
    map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
   }




   charset utf-8;
   log_format cloudfoundry '$http_x_forwarded_for - $http_referer - [$time_local] "$request" $status $body_bytes_sent';
   resolver 8.8.8.8;
   tcp_nopush on;
   #Lua resty waf package
   lua_package_path '$prefixlua-resty-waf/?.lua;;';
   lua_package_cpath '$prefixlua-resty-waf/?.lua;;';

   variables_hash_max_size 1024;
   include mime.types;
   port_in_redirect off;
   server_tokens off;


    init_by_lua '
        require "resty.core"
        -- require the base module
        local lua_resty_waf = require "waf"

         -- define options that will be inherited across all scopes
        lua_resty_waf.default_option("debug", true)
        lua_resty_waf.default_option("mode", "ACTIVE")

        -- perform some preloading and optimization
        lua_resty_waf.init()
    ';
    server {

       listen 8080;

       lua_code_cache on;


        location / {
          set $forwarded_url '';
          access_by_lua_file route-service.lua;


          header_filter_by_lua '
            local lua_resty_waf = require "waf"

            -- note that options set in previous handlers (in the same scope)
            -- do not need to be set again
            local waf = lua_resty_waf:new()

            waf:exec()
        ';

        body_filter_by_lua '
          local lua_resty_waf = require "waf"
          local waf = lua_resty_waf:new()
          waf:exec()
        ';


        log_by_lua '
          local lua_resty_waf = require "waf"
          local waf = lua_resty_waf:new()
          -- write out any event log entries to the
          -- configured target, if applicable
          waf:write_log_events()
         ';

            default_type text/html;

        proxy_redirect ~^(http://[^:]+):\d+(/.+)$ $2;
        proxy_redirect / /;

        # Upgrade headers
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;



        proxy_pass $forwarded_url;
    }
    }
}
```


## Docker Image 

### Building

```bash
docker build -t getourneau/alpine-openresty .
```

### Running
```bash
docker run -i -t -p 8080:8080 getourneau/alpine-openresty
```

### Running into Cloud Foundry
```bash
cf push waf -o getourneau/alpine-openresty
```

## Usage
### Create User provided service in CF
```bash
cf cups waf-service -r https://waf.cf-domain
```

### Bind to your application domain
```bash
cf bind-route-service cf.domain waf-service -n app-hostname
```

### Testing
Should get denied error
```
curl -vvv "https://app-hostname.cf-domain/" -k  -X GET -d "test=alert(1)" 
```

