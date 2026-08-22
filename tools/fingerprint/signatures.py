"""Signature tables for the technology fingerprinting engine.

Data only, no logic. Every table maps a technology name to the list of markers
that identify it; a technology matches when *any* of its markers matches.

CDN_SIGNATURES is matched against response *header names* (presence only, the
value is ignored). The remaining tables are matched as plain substrings against
the lowercased response body.

Dict order is part of the tool's output contract: matches are reported in the
order the technologies appear here.
"""

# Matched against header names, lowercased. Presence only.
CDN_SIGNATURES = {
    "Cloudflare":     ["cf-ray", "cf-cache-status"],
    "Fastly":         ["x-fastly-request-id"],
    "Akamai":         ["x-akamai-transformed"],
    "AWS CloudFront": ["x-amz-cf-id"],
    "Vercel":         ["x-vercel-id"],
    "Netlify":        ["x-nf-request-id"],
}

# Matched as substrings of the lowercased response body.
CMS_SIGNATURES = {
    "WordPress":   ["wp-content", "wp-includes", "wordpress"],
    "Drupal":      ["drupal.js", "drupal.min.js", "/sites/default/files"],
    "Joomla":      ["/media/jui/", "joomla"],
    "Shopify":     ["cdn.shopify.com", "shopify.com/s/files"],
    "Wix":         ["wix.com", "wixstatic.com"],
    "Squarespace": ["squarespace.com", "static.squarespace.com"],
    "Ghost":       ["ghost.io", "content/themes/ghost"],
}

JS_SIGNATURES = {
    "React":     ["react.js", "react.min.js", "_react", "__react"],
    "Vue.js":    ["vue.js", "vue.min.js", "__vue__"],
    "Angular":   ["angular.js", "ng-version", "angular/core"],
    "Next.js":   ["_next/static", "__next"],
    "Nuxt.js":   ["_nuxt/", "__nuxt"],
    "jQuery":    ["jquery.js", "jquery.min.js"],
    "Bootstrap": ["bootstrap.css", "bootstrap.min.css", "bootstrap.js"],
    "Tailwind":  ["tailwindcss", "tailwind.css"],
}

# Some of these are bare substrings that also match unrelated text - "ga(",
# for instance, matches the word "saga(". Known, and tracked in issue #130
# ("Current Problems"); tightening them is a behaviour change and deliberately
# not part of the extraction that created this module.
ANALYTICS_SIGNATURES = {
    "Google Analytics":   ["google-analytics.com", "gtag(", "ga("],
    "Google Tag Manager": ["googletagmanager.com"],
    "Hotjar":             ["hotjar.com"],
    "Mixpanel":           ["mixpanel.com"],
    "Segment":            ["segment.com", "analytics.js"],
    "Facebook Pixel":     ["connect.facebook.net/en_us/fbevents"],
}
