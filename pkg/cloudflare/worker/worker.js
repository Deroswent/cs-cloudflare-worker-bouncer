const ipaddr = require('ipaddr.js');
import jwt from '@tsndr/cloudflare-worker-jwt'
import { parse } from "cookie";

// ============================================================================
// CACHE API CONFIGURATION - TTL settings for different KV operations (in seconds)
// ============================================================================
// You can adjust these values based on your requirements:
// - Lower TTL = more frequent KV reads, but more up-to-date data
// - Higher TTL = fewer KV reads, but potentially stale data
//
// CACHE API BEHAVIOR:
// - Cache is shared between requests (persistent across requests)
// - Stored in Cloudflare's edge cache (memory of data centers)
// - Automatic eviction based on TTL and cache size limits
// - No KV operation limits - completely free to use
//
// PERFORMANCE IMPACT:
// - Reduces KV reads from ~5-6 per request to ~0-1 per request
// - Significant latency reduction (cache hits in ~1-5ms)
// - Inter-request caching (data persists between different requests)
// - No memory usage limits in your worker code
//
// USAGE EXAMPLE:
// - First request for IP 192.168.1.1: Cache MISS → 1 KV operation
// - Second request for IP 192.168.1.1: Cache HIT → 0 KV operations
// - Request for different IP: Cache MISS → 1 KV operation
//
// TTL RECOMMENDATIONS FOR DDOS PROTECTION:
// - IP_ADDRESS: 3600s (1 hour) - IPs change frequently during attacks
// - IP_RANGES: 7200s (2 hours) - IP ranges are relatively stable
// - ASN: 7200s (2 hours) - ASN data changes occasionally
// - COUNTRY: 7200s (2 hours) - Country data is very stable
// - BAN_TEMPLATE: 86400s (24 hours) - Template rarely changes
// - TURNSTILE_CONFIG: 1800s (30 min) - Config changes occasionally
const CACHE_API_TTL = {
  IP_ADDRESS: 3600,        // 1 hour - IP addresses change frequently
  IP_RANGES: 7200,        // 2 hours - IP ranges change less frequently
  ASN: 7200,              // 2 hours - ASN data is relatively stable
  COUNTRY: 7200,          // 2 hours - Country data is very stable
  BAN_TEMPLATE: 86400,    // 24 hours - Ban template rarely changes
  TURNSTILE_CONFIG: 86400  // 24 hours - Turnstile config changes occasionally
};


const getZoneFromReqURL = (reqURL, actionsByDomain) => {
  // loop through
  for (const [domain] of Object.entries(actionsByDomain)) {
    // if the request URL contains the domain, return the actions
    if (reqURL.includes(domain)) {
      return domain
    }
  }
}

const getSupportedActionForZone = (action, actionsForDomain) => {
  if (actionsForDomain["supported_actions"].includes(action)) {
    return action
  }
  return actionsForDomain["default_action"]
}

const handleTurnstilePost = async (request, body, turnstile_secret, zoneForThisRequest) => {
  const token = body.get('cf-turnstile-response');
  const ip = request.headers.get('CF-Connecting-IP');

  let formData = new FormData();

  formData.append('secret', turnstile_secret);
  formData.append('response', token);
  formData.append('remoteip', ip);

  const url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
  const result = await fetch(url, {
    body: formData,
    method: 'POST',
  });

  const outcome = await result.json();

  if (!outcome.success) {
    console.log('Invalid captcha solution');
    return new Response('Invalid captcha solution', {
      status: 401
    });
  } else {
    console.log('Valid captcha solution;', "Issuing JWT token");
    const jwtToken = await jwt.sign({
      data: "captcha solved",
      exp: Math.floor(Date.now() / 1000) + (2 * (60 * 60))
    }, turnstile_secret + ip);
    const newResponse = new Response(null, {
      status: 302
    })
    newResponse.headers.set("Set-Cookie", `${zoneForThisRequest}_captcha=${jwtToken}; Path=/; HttpOnly; Secure; SameSite=Strict;`)
    newResponse.headers.set("Location", request.url)
    return newResponse

  }
}

const getFromKV = async (kv, key) => {
  try {
    const value = await kv.get(key);
    return value;
  } catch (e) {
    console.log(e)
    return null
  }
}

// ============================================================================
// CACHE API FUNCTIONS - Inter-request caching using Cloudflare Cache API
// ============================================================================
const getFromKVWithCacheAPI = async (kv, key, cacheType) => {
  const cache = caches.default;
  
  // Create unique cache key (not a real HTTP request!)
  const cacheKey = new Request(`https://cache.local/${cacheType}/${key}`);
  
  try {
    // Check cache first (free, no KV operations)
    let cachedResponse = await cache.match(cacheKey);
    if (cachedResponse) {
      const cachedData = await cachedResponse.json();
      console.log(`Cache API HIT for ${cacheType}: ${key}`);
      return cachedData.value;
    }
  } catch (error) {
    console.log(`Cache API error for ${cacheType}: ${key}:`, error);
  }
  
  console.log(`Cache API MISS for ${cacheType}: ${key}`);
  
  // Get from KV (only KV operation)
  const value = await getFromKV(kv, key);
  
  // Cache the result if we have a valid value
  if (value !== null && CACHE_API_TTL[cacheType]) {
    try {
      const response = new Response(JSON.stringify({ 
        value, 
        timestamp: Date.now() 
      }), {
        headers: { 
          'Content-Type': 'application/json',
          'Cache-Control': `public, max-age=${CACHE_API_TTL[cacheType]}`
        }
      });
      await cache.put(cacheKey, response);
      console.log(`Cached ${cacheType}: ${key} with TTL ${CACHE_API_TTL[cacheType]}s`);
    } catch (error) {
      console.log(`Cache API put error for ${cacheType}: ${key}:`, error);
    }
  }
  
  return value;
}

// Helper functions for different cache types
const getIPFromKVWithCacheAPI = async (kv, ip) => {
  return await getFromKVWithCacheAPI(kv, ip, 'IP_ADDRESS');
};

const getIPRangesFromKVWithCacheAPI = async (kv) => {
  return await getFromKVWithCacheAPI(kv, 'IP_RANGES', 'IP_RANGES');
};

const getASNFromKVWithCacheAPI = async (kv, asn) => {
  return await getFromKVWithCacheAPI(kv, asn, 'ASN');
};

const getCountryFromKVWithCacheAPI = async (kv, country) => {
  return await getFromKVWithCacheAPI(kv, country, 'COUNTRY');
};

const getBanTemplateFromKVWithCacheAPI = async (kv) => {
  return await getFromKVWithCacheAPI(kv, 'BAN_TEMPLATE', 'BAN_TEMPLATE');
};

const getTurnstileConfigFromKVWithCacheAPI = async (kv) => {
  return await getFromKVWithCacheAPI(kv, 'TURNSTILE_CONFIG', 'TURNSTILE_CONFIG');
};

const writeToKV = async (kv, key, value) => {
  try {
    await kv.put(key, value);
  } catch (e) {
    console.log(e)
  }
}

// request ->
// <-captcha
// solved_captcha ->
// <-server original request with cookie

export default {
  async fetch(request, env, ctx) {

    const doBan = async () => {
      return new Response(await getBanTemplateFromKVWithCacheAPI(env.CROWDSECCFBOUNCERNS), {
        status: 403,
        headers: { "Content-Type": "text/html" }
      });
    }

    const doCaptcha = async (env, zoneForThisRequest) => {
      // Check if the request has proof of solving captcha
      // If the request has proof of solving captcha, let it pass through
      // If the request does not have proof of solving captcha. Check if the request is submission of captcha.
      // If it's captcha submission, do the validation  and issue a JWT token as a cookie. 
      // Else return the captcha HTML
      const ip = request.headers.get('CF-Connecting-IP');
      let turnstileCfg = await getTurnstileConfigFromKVWithCacheAPI(env.CROWDSECCFBOUNCERNS)
      if (turnstileCfg == null) {
        console.log("No turnstile config found for zone")
        return fetch(request)
      }
      if (typeof turnstileCfg === "string") {
        console.log("Converting turnstile config to JSON")
        turnstileCfg = JSON.parse(turnstileCfg)
        writeToKV(env.CROWDSECCFBOUNCERNS, "TURNSTILE_CONFIG", turnstileCfg)
        // Invalidate cache after updating KV
        const cache = caches.default;
        const cacheKey = new Request(`https://cache.local/TURNSTILE_CONFIG/TURNSTILE_CONFIG`);
        await cache.delete(cacheKey);
      }

      if (!turnstileCfg[zoneForThisRequest]) {
        console.log("No turnstile config found for zone")
        return fetch(request)
      }
      turnstileCfg = turnstileCfg[zoneForThisRequest]

      const cookie = parse(request.headers.get("Cookie") || "");
      if (cookie[`${zoneForThisRequest}_captcha`] !== undefined) {
        console.log("captchaAuth cookie is present")
        // Check if the JWT token is valid
        try {
          const decoded = await jwt.verify(cookie[`${zoneForThisRequest}_captcha`], turnstileCfg["secret"] + ip, {throwError: true});
          return fetch(request)
        } catch (err) {
          console.log(err)
        }
        console.log("jwt is invalid")
      }
      if (request.method === "POST") {
        const formBody = await request.clone().formData();
        if (formBody.get('cf-turnstile-response')) {
          console.log("Handling turnstile post")
          return await handleTurnstilePost(request, formBody, turnstileCfg["secret"], zoneForThisRequest)
        }
      }

      const captchaHTML = `
  <!DOCTYPE html>
  <html>
  <head>
      <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"></script>
      <title>Captcha</title>
      <style>
          html,
          body {
              height: 100%;
              margin: 0;
          }
  
          .container {
              display: flex;
              align-items: center;
              justify-content: center;
              height: 100%;
          }
  
          .centered-form {
              max-width: 400px;
              padding: 20px;
              background-color: #f0f0f0;
              border-radius: 8px;
          }
      </style>
  </head>
  
  <body>
      <div class="container">
          <form action="?" method="POST" class="centered-form", id="captcha-form">
              <div class="cf-turnstile" data-sitekey="${turnstileCfg["site_key"]}" id="container"></div>
              <br />
          </form>
      </div>
  </body>
  
  <script>
    // if using synchronous loading, will be called once the DOM is ready
    turnstile.ready(function () {
        turnstile.render('#container', {
            sitekey: '${turnstileCfg["site_key"]}',
            callback: function(token) {
              const xhr = new XMLHttpRequest();
              xhr.onreadystatechange = () => {
                if (xhr.readyState === 4) {
                  window.location.reload()
                }
              };
              const form = document.getElementById("captcha-form");
              xhr.open(form.method, "./");
              xhr.send(new FormData(form));
            },
        });
    });
  </script>
  
  </html>
      `
      return new Response(captchaHTML, {
        headers: {
          "content-type": "text/html;charset=UTF-8",
        },
        status: 200
      });
    }

    const getRemediationForRequest = async (request, env) => {
      console.log("Checking for decision against the IP")
      const clientIP = request.headers.get("CF-Connecting-IP");
      let value = await getIPFromKVWithCacheAPI(env.CROWDSECCFBOUNCERNS, clientIP);
      if (value !== null) {
        return value
      }

      console.log("Checking for decision against the IP ranges")
      let actionByIPRange = await getIPRangesFromKVWithCacheAPI(env.CROWDSECCFBOUNCERNS);
      if (typeof actionByIPRange === "string") {
        actionByIPRange = JSON.parse(actionByIPRange)
      }
      if (actionByIPRange !== null) {
        const clientIPAddr = ipaddr.parse(clientIP);
        for (const [range, action] of Object.entries(actionByIPRange)) {
          try {
            if (clientIPAddr.match(ipaddr.parseCIDR(range))) {
              return action
            }
          } catch (error) {
            // This happens when trying to match IPv6 address with IPv4 CIDR (or vice versa)
            // Just ignore the error and continue
          }
        }
      }
      // Check for decision against the AS
      const clientASN = request.cf.asn.toString();
      value = await getASNFromKVWithCacheAPI(env.CROWDSECCFBOUNCERNS, clientASN);
      if (value !== null) {
        return value
      }

      // Check for decision against the country of the request
      const clientCountry = request.cf.country.toLowerCase();
      if (clientCountry !== null) {
        value = await getCountryFromKVWithCacheAPI(env.CROWDSECCFBOUNCERNS, clientCountry);
        if (value !== null) {
          return value
        }
      }
      return null
    }

    const incrementMetrics = async (metricName, ipType, origin, remediation_type) => {
      if (env.CROWDSECCFBOUNCERDB !== undefined) {
        let parameters = [metricName, origin || "", remediation_type || "", ipType]
        let query = `
          INSERT INTO metrics (val, metric_name, origin, remediation_type, ip_type)
          VALUES (1, ?, ?, ?, ?)
          ON CONFLICT(metric_name, origin, remediation_type, ip_type) DO UPDATE SET val=val+1
        `;

        await env.CROWDSECCFBOUNCERDB
          .prepare(query)
          .bind(...parameters)
          .run();

      };
    }

    const clientIP = request.headers.get("CF-Connecting-IP");
    const ipType = ipaddr.parse(clientIP).kind();

    await incrementMetrics("processed", ipType)


    let remediation = await getRemediationForRequest(request, env)
    if (remediation === null) {
      console.log("No remediation found for request")
      return fetch(request)
    }
    if (typeof env.ACTIONS_BY_DOMAIN === "string") {
      env.ACTIONS_BY_DOMAIN = JSON.parse(env.ACTIONS_BY_DOMAIN)
    }
    const zoneForThisRequest = getZoneFromReqURL(request.url, env.ACTIONS_BY_DOMAIN);
    console.log("Zone for this request is " + zoneForThisRequest)
    remediation = getSupportedActionForZone(remediation, env.ACTIONS_BY_DOMAIN[zoneForThisRequest])
    console.log("Remediation for request is " + remediation)
    switch (remediation) {
      case "ban":
        await incrementMetrics("dropped", ipType, "crowdsec", "ban")
        return env.LOG_ONLY === "true" ? fetch(request) : await doBan()
      case "captcha":
        await incrementMetrics("dropped", ipType, "crowdsec", "captcha")
        return env.LOG_ONLY === "true" ? fetch(request) : await doCaptcha(env, zoneForThisRequest)
      default:
        return fetch(request)
    }
  }
}