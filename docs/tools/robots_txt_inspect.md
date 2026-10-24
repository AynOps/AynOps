# `robots_txt_inspect`

## Overview

`robots_txt_inspect` fetches `robots.txt` from a domain, parses it into rule
groups, and reports the paths each group allows and disallows together with any
declared sitemaps and `Host` directive. It tries HTTPS first and falls back to
plain HTTP. No API key is required.

## Purpose and common use cases

`robots.txt` is often the cheapest hint about what an application does not want
crawled, which makes it a good early step in web reconnaissance:

- Collect disallowed paths that name admin consoles, staging trees, or internal
  API routes.
- Find the paths a permissive `Allow:` advertises to specific crawlers.
- Harvest sitemap URLs to widen the URL list for later checks.
- Read `Crawl-delay` when planning the request rate of a follow-up scan.

## Parameters

The MCP tool exposes one required input:

| Name | Type | Required | Description |
|---|---|---|---|
| `domain` | string | Yes | A fully qualified domain name. IP addresses, `localhost`, bare labels and malformed names are rejected. |

The value is normalized before validation — surrounding whitespace stripped,
lowercased, and trailing dots removed — then checked against the shared domain
validator: at most 253 characters, labels of at most 63 characters, and a final
label of at least two ASCII letters.

## Optional parameters

None. The fetch URL, the timeout and the user agent are fixed by the tool.

## Example MCP request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "robots_txt_inspect",
    "arguments": {
      "domain": "python.org"
    }
  }
}
```

## Example successful response

Captured from a live call, trimmed to two of the four parsed groups:

```json
{
  "success": true,
  "domain": "python.org",
  "robots_url": "https://www.python.org/robots.txt",
  "allowed_paths": ["/"],
  "disallowed_paths": ["/", "/~guido/orlijn/", "/webstats/"],
  "sitemaps": [],
  "host": null,
  "rules": [
    {
      "user_agents": ["HTTrack", "puf", "MSIECrawler"],
      "allow": [],
      "disallow": ["/"],
      "crawl_delay": null
    },
    {
      "user_agents": ["*"],
      "allow": [],
      "disallow": ["/~guido/orlijn/", "/webstats/"],
      "crawl_delay": null
    }
  ]
}
```

Note that `domain` echoes the normalized input while `robots_url` is the URL
that actually answered, after redirects (`python.org` → `www.python.org` here).

## Response field descriptions

| Field | Type | Description |
|---|---|---|
| `success` | boolean | `true` when a `robots.txt` response was retrieved and parsed. |
| `domain` | string | The normalized domain that was requested. |
| `robots_url` | string | The final URL of the retrieved file, which may differ from the request after a redirect. |
| `allowed_paths` | list of strings | Every `Allow:` path from every group, de-duplicated in first-seen order. |
| `disallowed_paths` | list of strings | Every `Disallow:` path from every group, de-duplicated in first-seen order. |
| `sitemaps` | list of strings | Every `Sitemap:` URL found anywhere in the file, de-duplicated. `Sitemap:` is global rather than per-group. |
| `host` | string or null | The `Host:` directive (a non-standard, Yandex-originated hint for the primary mirror), or `null` when absent. |
| `rules` | list of objects | One entry per user-agent group that carries at least one directive. |
| `rules[].user_agents` | list of strings | The agents in the group, in file order and de-duplicated. Consecutive `User-agent:` lines before the first directive form one group. |
| `rules[].allow` | list of strings | `Allow:` paths of this group, de-duplicated. |
| `rules[].disallow` | list of strings | `Disallow:` paths of this group, de-duplicated. |
| `rules[].crawl_delay` | string or null | `Crawl-delay:` value of this group as written (e.g. `"10"`), or `null`. Kept as a string because the directive is not always numeric. |

## Parsing behavior

- `#` starts an inline comment; everything from it to the end of the line is
  dropped before parsing.
- Blank lines are ignored. A new group starts only when a `User-agent:` line
  appears *after* the current group has already produced a directive, so a
  block of consecutive `User-agent:` lines shares one set of rules.
- Directives that appear before the first `User-agent:` line are ignored; there
  is no implicit `*` group.
- A group with no `Allow:`, `Disallow:` or `Crawl-delay:` is dropped. A file
  containing only `Sitemap:` lines therefore returns `rules: []` and a populated
  `sitemaps` list.
- Empty directive values (`Disallow:` with nothing after it, which is the
  conventional way of writing "allow everything") are not recorded, so they do
  not create a group.
- When a group repeats `Crawl-delay:`, the last value seen wins.
- `Host:` is global: the last valid value in the file is reported, independent
  of grouping.
- The parser reports what the file says. It does not apply group precedence, so
  callers that need the rules for one specific crawler must pick the matching
  group themselves.

## Errors and timeouts

Failures return `success: false` plus an `error` string:

| Situation | Response |
|---|---|
| The domain fails normalization or validation | `{"success": false, "error": "Invalid domain format"}` |
| Both the HTTPS attempt and the HTTP fallback fail | `{"success": false, "error": "Failed to fetch robots.txt: <detail>"}` |
| Anything else | `{"success": false, "error": "<exception message>"}` |

Each request uses a 10-second timeout, so a domain that refuses HTTPS and then
hangs on HTTP can occupy the tool for roughly twenty seconds. A non-2xx status
on the HTTPS attempt raises `requests.HTTPError`, which is caught as a request
failure and triggers the HTTP fallback; a 404 therefore produces the error above
for a site that publishes no `robots.txt` at all (verified against
`example.com`, which answers 404 over both schemes).

## Notes and limitations

- Plain HTTP fallback means a discovery that only exists over HTTP is still
  reported, but it also means the request can be observed in clear text.
- The request sends a desktop browser `User-Agent`, not a crawler identity.
- Redirects are followed, and `robots_url` reflects the final URL. A site that
  redirects to a different host is reported under that host's URL while `domain`
  keeps the input.
- `Crawl-delay` is returned verbatim. The tool does not validate it, convert it
  to a number, or wait for it.
- Sitemap contents are not fetched; only the URLs written in the file are
  returned.
- The tool reports the file's contents without judging them: a `Disallow:` entry
  is not evidence that the path exists.

## API key requirements

None required.

## Related tools

`headers_analyzer` inspects the response headers of a host, `trace_redirects`
follows an HTTP redirect chain, and `subdomain_takeover` checks discovered
hostnames for takeover indicators; all three pair naturally with the paths this
tool returns. `whois_lookup` and `dns_enumeration` cover the registration and DNS
sides of the same host. See the [tools index](README.md) for the current
registration inventory and documentation status.
