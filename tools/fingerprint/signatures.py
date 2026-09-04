"""Signature tables for the technology fingerprinting engine.

Data only, no logic.  Each table maps a technology name to a list of
``(marker_type, marker_value, confidence)`` triples:

* ``marker_type`` — one of ``"header_name"``, ``"header_value"``,
  ``"cookie_name"``, ``"meta_generator"``, ``"html_substring"``
* ``marker_value`` — the string to look for (always matched
  case-insensitively against the appropriate input)
* ``confidence``   — integer 0-100 awarded when this particular marker fires

When multiple markers fire for the same technology the individual
confidence points are **not** summed; instead the engine raises the
technology's confidence to the maximum single-marker score and merges all
evidence strings.

Dict insertion order is part of the output contract: technologies appear in
the result in the order they are listed here.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Web servers — detected from HTTP response headers
# ---------------------------------------------------------------------------
WEB_SERVER_SIGNATURES: dict[str, list[tuple[str, str, int]]] = {
    "Apache":  [("header_name",  "server",         95),
                ("header_value", "apache",         95)],
    "nginx":   [("header_name",  "server",         95),
                ("header_value", "nginx",          95)],
    "IIS":     [("header_value", "iis",            95),
                ("header_value", "microsoft-iis",  95)],
    "Caddy":   [("header_value", "caddy",          90)],
    "LiteSpeed": [("header_value", "litespeed",    90)],
    "Gunicorn":  [("header_value", "gunicorn",     90)],
    "Tornado":   [("header_value", "tornadoserver",85)],
}

# ---------------------------------------------------------------------------
# Programming languages / runtimes — detected from headers and cookies
# ---------------------------------------------------------------------------
LANGUAGE_SIGNATURES: dict[str, list[tuple[str, str, int]]] = {
    "PHP":    [("header_value", "php",        90),
               ("cookie_name", "phpsessid",   85)],
    "Python": [("header_value", "python",     90),
               ("header_value", "werkzeug",   85)],
    "Ruby":   [("header_value", "ruby",       90),
               ("header_value", "passenger",  85)],
    "Java":   [("header_value", "java",       90),
               ("cookie_name", "jsessionid",  85)],
    "ASP.NET":[("header_value", "asp.net",    90),
               ("cookie_name", ".aspxauth",   85),
               ("cookie_name", "asp.net_sessionid", 85)],
}

# ---------------------------------------------------------------------------
# CMS platforms — detected from HTML, cookies and meta generator tag
# ---------------------------------------------------------------------------
CMS_SIGNATURES: dict[str, list[tuple[str, str, int]]] = {
    "WordPress":   [("meta_generator", "wordpress",         95),
                    ("html_substring", "wp-content",        85),
                    ("html_substring", "wp-includes",       85),
                    ("html_substring", "wp-json",           80),
                    ("cookie_name",    "wordpress_logged_in", 95),
                    ("cookie_name",    "wp-settings-",      85)],
    "Drupal":      [("meta_generator", "drupal",            95),
                    ("html_substring", "drupal.js",         85),
                    ("html_substring", "/sites/default/files", 85),
                    ("cookie_name",    "drupal_uid",        90)],
    "Joomla":      [("meta_generator", "joomla",            95),
                    ("html_substring", "/media/jui/",       85),
                    ("html_substring", "joomla",            75)],
    "Shopify":     [("html_substring", "cdn.shopify.com",   90),
                    ("html_substring", "shopify.com/s/files", 90),
                    ("cookie_name",    "_shopify_s",        95)],
    "Wix":         [("html_substring", "wixstatic.com",     90),
                    ("html_substring", "wix.com/",          80)],
    "Squarespace": [("html_substring", "static.squarespace.com", 90),
                    ("html_substring", "squarespace.com",   85)],
    "Ghost":       [("meta_generator", "ghost",             95),
                    ("html_substring", "ghost.io",          90),
                    ("html_substring", "content/themes/ghost", 85)],
    "Webflow":     [("html_substring", "webflow.com",       90),
                    ("cookie_name",    "wf_cart",           90)],
    "Magento":     [("html_substring", "mage/",            85),
                    ("cookie_name",    "frontend",         75)],
}

# ---------------------------------------------------------------------------
# JavaScript frameworks — detected from HTML / asset URLs
# ---------------------------------------------------------------------------
JS_FRAMEWORK_SIGNATURES: dict[str, list[tuple[str, str, int]]] = {
    "React":     [("html_substring", "react.min.js",    90),
                  ("html_substring", "__react",         85),
                  ("html_substring", "react-dom",       85)],
    "Vue.js":    [("html_substring", "vue.min.js",      90),
                  ("html_substring", "__vue__",         85),
                  ("html_substring", "vue.js",          80)],
    "Angular":   [("html_substring", "ng-version",      90),
                  ("html_substring", "angular/core",    85),
                  ("html_substring", "angular.min.js",  80)],
    "Next.js":   [("html_substring", "_next/static",    90),
                  ("html_substring", "__next",          85),
                  ("meta_generator", "next.js",         90)],
    "Nuxt.js":   [("html_substring", "_nuxt/",          90),
                  ("html_substring", "__nuxt",          85),
                  ("meta_generator", "nuxt",            90)],
    "Svelte":    [("html_substring", "svelte",          80),
                  ("meta_generator", "svelte",          90)],
    "jQuery":    [("html_substring", "jquery.min.js",   85),
                  ("html_substring", "jquery.js",       80)],
    "Bootstrap": [("html_substring", "bootstrap.min.css", 85),
                  ("html_substring", "bootstrap.min.js",  80)],
    "Tailwind":  [("html_substring", "tailwindcss",     85),
                  ("html_substring", "tailwind.css",    80)],
    "Ember.js":  [("html_substring", "ember.min.js",    90),
                  ("html_substring", "emberjs",         80)],
}

# ---------------------------------------------------------------------------
# CDN / Hosting providers — detected from HTTP header names/values
# ---------------------------------------------------------------------------
CDN_SIGNATURES: dict[str, list[tuple[str, str, int]]] = {
    "Cloudflare":    [("header_name",  "cf-ray",               95),
                      ("header_name",  "cf-cache-status",      90),
                      ("header_value", "cloudflare",           90)],
    "Fastly":        [("header_name",  "x-fastly-request-id",  95),
                      ("header_value", "fastly",               90)],
    "Akamai":        [("header_name",  "x-akamai-transformed", 95)],
    "AWS CloudFront":[("header_name",  "x-amz-cf-id",          95)],
    "Vercel":        [("header_name",  "x-vercel-id",          95),
                      ("header_value", "vercel",               90)],
    "Netlify":       [("header_name",  "x-nf-request-id",      95)],
    "AWS S3":        [("header_value", "amazons3",             90),
                      ("header_name",  "x-amz-request-id",    85)],
    "Azure":         [("header_name",  "x-ms-request-id",      90),
                      ("header_value", "azure",                80)],
    "Google Cloud":  [("header_name",  "x-goog-generation",    95),
                      ("header_value", "google frontend",      90)],
}

# ---------------------------------------------------------------------------
# Analytics & marketing — detected from HTML body
# ---------------------------------------------------------------------------
ANALYTICS_SIGNATURES: dict[str, list[tuple[str, str, int]]] = {
    "Google Analytics":   [("html_substring", "google-analytics.com/analytics.js", 95),
                           ("html_substring", "googletagmanager.com/gtag",         95),
                           ("html_substring", "gtag('config'",                     90),
                           ("html_substring", "ga('create'",                       80)],
    "Google Tag Manager": [("html_substring", "googletagmanager.com/gtm.js",       95),
                           ("html_substring", "gtm.js",                            85)],
    "Hotjar":             [("html_substring", "hotjar.com",                        95)],
    "Mixpanel":           [("html_substring", "mixpanel.com",                      95)],
    "Segment":            [("html_substring", "segment.com/analytics.js",          95),
                           ("html_substring", "cdn.segment.com",                   90)],
    "Facebook Pixel":     [("html_substring", "connect.facebook.net/en_us/fbevents", 95)],
    "Plausible":          [("html_substring", "plausible.io/js",                   95)],
    "Matomo":             [("html_substring", "matomo.js",                         90),
                           ("html_substring", "piwik.js",                          90)],
}
