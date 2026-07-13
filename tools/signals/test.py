{
  "success": true,
  "domain": "google.com",
  "scanned_at": "2026-07-13T13:42:57.706714Z",
  "mode": "threat_analysis",
  "tool_coverage": {
    "whois": "success",
    "dns": "success",
    "ssl": "success",
    "email_security": "success",
    "asn": "success",
    "ports": "success",
    "techstack": "success",
    "ct_logs": "success",
    "ip_reputation": "success"
  },
  "tools_summary": {
    "total": 9,
    "succeeded": 9,
    "skipped": 0,
    "failed": 0
  },
  "raw_results": {
    "ssl": {
      "success": true,
      "domain": "google.com",
      "port": 443,
      "tls_version": "TLSv1.3",
      "cipher": {
        "name": "TLS_AES_256_GCM_SHA384",
        "protocol": "TLSv1.3",
        "bits": 256
      },
      "certificate": {
        "subject": {
          "commonName": "*.google.com"
        },
        "issuer": {
          "countryName": "US",
          "organizationName": "Google Trust Services",
          "commonName": "WR2"
        },
        "serial_number": "AE068DC8BDF3E7570A0C6AFB39C2E9C5",
        "not_before": "2026-06-22T08:35:23+00:00",
        "not_after": "2026-09-14T08:35:22+00:00",
        "days_until_expiry": 62,
        "expired": false,
        "expiring_soon": false,
        "subject_alt_names": [
          "*.google.com",
          "*.appengine.google.com",
          "*.bdn.dev",
          "*.origin-test.bdn.dev",
          "*.cloud.google.com",
          "*.crowdsource.google.com",
          "*.datacompute.google.com",
          "*.google.ca",
          "*.google.cl",
          "*.google.co.in",
          "*.google.co.jp",
          "*.google.co.uk",
          "*.google.com.ar",
          "*.google.com.au",
          "*.google.com.br",
          "*.google.com.co",
          "*.google.com.mx",
          "*.google.com.tr",
          "*.google.com.vn",
          "*.google.de",
          "*.google.es",
          "*.google.fr",
          "*.google.hu",
          "*.google.it",
          "*.google.nl",
          "*.google.pl",
          "*.google.pt",
          "*.gemini.cloud.google.com",
          "*.gstatic.com",
          "*.metric.gstatic.com",
          "*.gvt1.com",
          "*.gcpcdn.gvt1.com",
          "*.gvt2.com",
          "*.gcp.gvt2.com",
          "*.url.google.com",
          "*.youtube-nocookie.com",
          "*.ytimg.com",
          "ai.android",
          "android.com",
          "*.android.com",
          "*.flash.android.com",
          "g.co",
          "*.g.co",
          "goo.gl",
          "www.goo.gl",
          "google-analytics.com",
          "*.google-analytics.com",
          "google.com",
          "googlecommerce.com",
          "*.googlecommerce.com",
          "urchin.com",
          "*.urchin.com",
          "youtu.be",
          "youtube.com",
          "*.youtube.com",
          "music.youtube.com",
          "*.music.youtube.com",
          "youtubeeducation.com",
          "*.youtubeeducation.com",
          "youtubekids.com",
          "*.youtubekids.com",
          "yt.be",
          "*.yt.be",
          "android.clients.google.com",
          "*.aistudio.google.com"
        ],
        "version": 3
      }
    },
    "email_security": {
      "success": true,
      "domain": "google.com",
      "spf": {
        "found": true,
        "record": "v=spf1 include:_spf.google.com ~all",
        "policy": "softfail"
      },
      "dmarc": {
        "found": true,
        "record": "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com",
        "policy": "reject"
      },
      "dkim": {
        "found": true,
        "selectors_checked": [
          "202403",
          "20230901",
          "smtp",
          "202306",
          "google",
          "20240601",
          "202512",
          "s1",
          "20250901",
          "google2024",
          "20250601",
          "20260301",
          "202601",
          "202603",
          "k1",
          "scph0615",
          "20241201",
          "202309",
          "202401",
          "20240101",
          "202606",
          "20161025",
          "20230101",
          "google2026",
          "google2025",
          "dkim",
          "202501",
          "20260101",
          "20261201",
          "selector2",
          "202612",
          "k2",
          "amazonses",
          "s2",
          "mxvault",
          "selector1",
          "202301",
          "20230601",
          "202503",
          "20250101",
          "202303",
          "20240301",
          "20250301",
          "202409",
          "202406",
          "202506",
          "202509",
          "2025",
          "20231201",
          "202412",
          "20260601",
          "202312",
          "mail",
          "google2023",
          "20260901",
          "20230301",
          "2023",
          "20240901",
          "20251201",
          "2024",
          "202609",
          "2026",
          "default",
          "zoho",
          "mandrill"
        ],
        "found_selectors": [
          "20161025",
          "20230601"
        ]
      },
      "security_score": "90%",
      "rating": "Excellent",
      "recommendations": [
        "SPF uses softfail (~all) — consider a hard fail (-all) for stronger protection"
      ]
    },
    "asn": {
      "success": true,
      "ip": "2404:6800:4002:81b::200e",
      "asn": "AS15169",
      "org": null,
      "isp": "Google",
      "country": "Australia",
      "region": null,
      "city": "Commonwealth of Australia"
    },
    "dns": {
      "success": true,
      "domain": "google.com",
      "records": {
        "A": [
          "142.250.118.113",
          "142.250.118.139",
          "142.250.118.101",
          "142.250.118.138",
          "142.250.118.100",
          "142.250.118.102"
        ],
        "AAAA": [
          "2404:6800:4013:811::65",
          "2404:6800:4013:811::8b",
          "2404:6800:4013:811::66",
          "2404:6800:4013:811::64"
        ],
        "MX": [
          {
            "preference": 10,
            "exchange": "smtp.google.com"
          }
        ],
        "NS": [
          "ns3.google.com",
          "ns2.google.com",
          "ns4.google.com",
          "ns1.google.com"
        ],
        "TXT": [
          "v=spf1 include:_spf.google.com ~all",
          "onetrust-domain-verification=6d685f1d41a94696ad7ef771f68993e0",
          "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8=",
          "Z29vZ2xl",
          "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95",
          "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB",
          "apple-domain-verification=30afIBcvSuDV2PLX",
          "google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o",
          "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ",
          "google-site-verification=4ibFUgB-wXLQ_S7vsXVomSTVamuOXBiVAzpR5IZ87D0",
          "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e",
          "docusign=1b0a6754-49b1-4db5-8540-d2c12664b289",
          "cisco-ci-domain-verification=47c38bc8c4b74b7233e9053220c1bbe76bcc1cd33c7acf7acd36cd6a5332004b",
          "onetrust-domain-verification=0d477fe608074e6f9c12bca7826035cc"
        ],
        "CNAME": [],
        "SOA": {
          "mname": "ns1.google.com",
          "rname": "dns-admin.google.com",
          "serial": 946510390,
          "refresh": 900,
          "retry": 900,
          "expire": 1800,
          "minimum": 60
        }
      },
      "subdomains_found": [
        "www.google.com",
        "mail.google.com",
        "admin.google.com",
        "api.google.com",
        "vpn.google.com"
      ]
    },
    "whois": {
      "success": true,
      "domain": "google.com",
      "registrar": "MarkMonitor, Inc.",
      "whois_server": "whois.markmonitor.com",
      "creation_date": "1997-09-15 04:00:00+00:00",
      "expiration_date": "2028-09-14 04:00:00+00:00",
      "updated_date": "2019-09-09 15:39:04+00:00",
      "name_servers": [
        "NS1.GOOGLE.COM",
        "NS2.GOOGLE.COM",
        "NS3.GOOGLE.COM",
        "NS4.GOOGLE.COM"
      ],
      "status": [
        "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
        "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
        "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
        "serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
        "serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
        "serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited",
        "clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)",
        "clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)",
        "clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)",
        "serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)",
        "serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)",
        "serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)"
      ],
      "emails": [
        "abusecomplaints@markmonitor.com",
        "whoisrequest@markmonitor.com"
      ],
      "dnssec": "unsigned",
      "country": "US",
      "org": "Google LLC"
    },
    "techstack": {
      "success": true,
      "domain": "google.com",
      "url": "https://www.google.com/",
      "status_code": 200,
      "technologies": {
        "web_server": "gws"
      },
      "security_headers": {
        "present": [
          "x-frame-options",
          "x-xss-protection"
        ],
        "missing": [
          "strict-transport-security",
          "content-security-policy",
          "x-content-type-options",
          "referrer-policy",
          "permissions-policy"
        ],
        "score": "28%",
        "rating": "Poor"
      }
    },
    "ct_logs": {
      "success": true,
      "source": "crt.sh",
      "domain": "google.com",
      "total_certificates": 1332,
      "total_unique_subdomains": 100,
      "unique_subdomains": [
        "aarjav-b480g7k2ab9@checkout.google.com",
        "accounts.flexpack.google.com",
        "accounts.freezone.google.com",
        "accounts.google.com",
        "admin@google.com",
        "ads-compare.eem.corp.google.com",
        "adwords.google.com",
        "alt1.aspmx.l.google.com",
        "alt1.gmail-smtp-in.l.google.com",
        "alt1.gmr-smtp-in.l.google.com",
        "alt2.aspmx.l.google.com",
        "alt2.gmail-smtp-in.l.google.com",
        "alt2.gmr-smtp-in.l.google.com",
        "alt3.aspmx.l.google.com",
        "alt3.gmail-smtp-in.l.google.com",
        "alt3.gmr-smtp-in.l.google.com",
        "alt4.aspmx.l.google.com",
        "alt4.gmail-smtp-in.l.google.com",
        "alt4.gmr-smtp-in.l.google.com",
        "answers.google.com",
        "apps-secure-data-connector.google.com",
        "aspmx.l.google.com",
        "audioads.google.com",
        "bmcquade@google.com",
        "cag.ext.google.com",
        "cert-test.sandbox.google.com",
        "checkout.google.com",
        "cod.ext.google.com",
        "da.ext.corp.google.com",
        "da.ext.google.com",
        "dg.video.google.com",
        "ecc-test.sandbox.google.com",
        "eggroll.ext.google.com",
        "ext.google.com",
        "flexpack.google.com",
        "fra-da.ext.google.com",
        "freezone.accounts.google.com",
        "freezone.google.com",
        "freezone.m.google.com",
        "freezone.mail.google.com",
        "gaiastaging.flexpack.google.com",
        "gaiastaging.freezone.google.com",
        "glass-eur.ext.google.com",
        "glass-mtv.ext.google.com",
        "glass-twd.ext.google.com",
        "glass.ext.google.com",
        "gmail-smtp-in.l.google.com",
        "gmail.google.com",
        "gmr-smtp-in.l.google.com",
        "hosted-id.google.com",
        "hot-da.ext.google.com",
        "hyd-da.ext.google.com",
        "ice.ext.google.com",
        "ics.prod.google.com",
        "jmt0.google.com",
        "login.corp.google.com",
        "m.google.com",
        "m.guts.corp.google.com",
        "m.gutsdev.corp.google.com",
        "mail.flexpack.google.com",
        "mail.freezone.google.com",
        "mail.google.com",
        "meeting.ext.google.com",
        "misc-sni.google.com",
        "misc.google.com",
        "mtalk.google.com",
        "mtv-da-1.ad.corp.google.com",
        "mtv-da.corp.google.com",
        "mtv-da.ext.google.com",
        "mx.google.com",
        "mygeist.corp.google.com",
        "mygeist2010.corp.google.com",
        "news.freezone.google.com",
        "onex.wifi.google.com",
        "plus.flexpack.google.com",
        "plus.freezone.google.com",
        "proxyconfig.corp.google.com",
        "qa.adz.google.com",
        "reseed.corp.google.com",
        "sandbox.google.com",
        "search.flexpack.google.com",
        "search.freezone.google.com",
        "services.google.com",
        "soaproxyprod01.ext.google.com",
        "soaproxytest01.ext.google.com",
        "spdy-proxy-debug.ext.google.com",
        "spdy-proxy.ext.google.com",
        "talk.google.com",
        "twd-da.ext.google.com",
        "twdsalesgsa.twd.corp.google.com",
        "uberproxy-nocert.corp.google.com",
        "uberproxy-san.corp.google.com",
        "uberproxy.corp.google.com",
        "upload.google.com",
        "upload.video.google.com",
        "vp.video.l.google.com",
        "wifi.google.com",
        "www.flexpack.google.com",
        "www.freezone.google.com",
        "www.google.com"
      ],
      "wildcards_found": [
        ".apis.corp.google.com",
        ".appengine.google.com",
        ".auth.corp.google.com",
        ".bigstore-test.corp.google.com",
        ".bigstore.corp.google.com",
        ".blogger.corp.google.com",
        ".blogspot.corp.google.com",
        ".c.docs.google.com",
        ".c.pack.google.com",
        ".c.play.google.com",
        ".c.video.google.com",
        ".cache1.c.docs.google.com",
        ".cache1.c.play.google.com",
        ".cache1.c.video.google.com",
        ".cache2.c.docs.google.com",
        ".cache2.c.play.google.com",
        ".cache2.c.video.google.com",
        ".cache3.c.docs.google.com",
        ".cache3.c.play.google.com",
        ".cache3.c.video.google.com",
        ".cache4.c.docs.google.com",
        ".cache4.c.play.google.com",
        ".cache4.c.video.google.com",
        ".cache5.c.docs.google.com",
        ".cache5.c.play.google.com",
        ".cache5.c.video.google.com",
        ".cache6.c.docs.google.com",
        ".cache6.c.play.google.com",
        ".cache6.c.video.google.com",
        ".cache7.c.docs.google.com",
        ".cache7.c.play.google.com",
        ".cache7.c.video.google.com",
        ".cache8.c.docs.google.com",
        ".cache8.c.play.google.com",
        ".cache8.c.video.google.com",
        ".cag.ext.google.com",
        ".chrome.google.com",
        ".client-channel.google.com",
        ".clients.google.com",
        ".cloud.google.com",
        ".code.google.com",
        ".corp-backups.corp.google.com",
        ".corp.google.com",
        ".dasher-qa.corp.google.com",
        ".dasher.corp.google.com",
        ".demetrius-codespot.corp.google.com",
        ".demetrius-googlecode.corp.google.com",
        ".demetrius.corp.google.com",
        ".devconsole-testers.sandbox.google.com",
        ".developer.google.com",
        ".developers.google.com",
        ".dfa7.corp.google.com",
        ".docs-dev.corp.google.com",
        ".docs-nightly.corp.google.com",
        ".docs-platinum.corp.google.com",
        ".docs-qa.corp.google.com",
        ".docs.google.com",
        ".docs.sandbox.google.com",
        ".drive-test.corp.google.com",
        ".drive.google.com",
        ".drive.sandbox.google.com",
        ".dthree.corp.google.com",
        ".ext.google.com",
        ".focus.corp.google.com",
        ".friendconnect.google.com",
        ".games.corp.google.com",
        ".git.corp.google.com",
        ".glass.ext.google.com",
        ".google.com",
        ".googlesource.corp.google.com",
        ".ice.ext.google.com",
        ".jotspot-qa08.corp.google.com",
        ".loop.corp.google.com",
        ".mail.google.com",
        ".meeting.ext.google.com",
        ".orkut-fixprod.corp.google.com",
        ".orkut-impersonation.corp.google.com",
        ".orkut-ocdemo.corp.google.com",
        ".orkut-qa.corp.google.com",
        ".orkut-staging.corp.google.com",
        ".orkut-uberproxy.corp.google.com",
        ".orkut-vctask0.corp.google.com",
        ".orkut-vcvrfy.corp.google.com",
        ".orkut-yhtask0.corp.google.com",
        ".orkut-yhvrfy.corp.google.com",
        ".orkut-yqtask0.corp.google.com",
        ".orkut-yqvrfy.corp.google.com",
        ".oz-gmail.corp.google.com",
        ".oz-s2.corp.google.com",
        ".oz-www.corp.google.com",
        ".photos.google.com",
        ".plus.corp.google.com",
        ".plus.google.com",
        ".plusone.corp.google.com",
        ".postini.corp.google.com",
        ".profiles.corp.google.com",
        ".prom-qa.corp.google.com",
        ".prom-qa.sandbox.google.com",
        ".prom-test.corp.google.com",
        ".prom-test.sandbox.google.com",
        ".prom.corp.google.com",
        ".qa.adz.google.com",
        ".sandbox.google.com",
        ".script.sandbox.google.com",
        ".search.corp.google.com",
        ".sites-googlegroups-nightly.corp.google.com",
        ".sites-googlegroups-qa01.corp.google.com",
        ".sites-googlegroups-qa02.corp.google.com",
        ".sites-googlegroups-qa03.corp.google.com",
        ".sites-googlegroups-qa04.corp.google.com",
        ".sites-googlegroups-qa05.corp.google.com",
        ".sites-googlegroups-qa06.corp.google.com",
        ".sites-googlegroups-qa07.corp.google.com",
        ".sites-googlegroups-qa08.corp.google.com",
        ".sites-googlegroups-tctest.corp.google.com",
        ".sites.google.com",
        ".sites.sandbox.google.com",
        ".spdy-proxy.ext.google.com",
        ".staging-a.blogger.corp.google.com",
        ".staging-b.blogger.corp.google.com",
        ".staging-c.blogger.corp.google.com",
        ".staging-d.blogger.corp.google.com",
        ".staging-daily.blogger.corp.google.com",
        ".staging-daily.blogspot.corp.google.com",
        ".staging-gaia.blogger.corp.google.com",
        ".staging-git.corp.google.com",
        ".staging-googlesource.corp.google.com",
        ".staging-prod.blogger.corp.google.com",
        ".staging-weekly.blogger.corp.google.com",
        ".staging-weekly.blogspot.corp.google.com",
        ".talkgadget.google.com",
        ".test.postini.corp.google.com",
        ".upload.google.com",
        ".urchin.corp.google.com",
        ".url.google.com",
        ".vp.video.l.google.com",
        ".webdrive-test-canary.corp.google.com",
        ".webdrive-test-prod.corp.google.com"
      ],
      "returned_certificates": 50,
      "truncated": true,
      "certificates": [
        {
          "subdomain": "admin@google.com",
          "issuer": "C=NL, O=DigiNotar, CN=DigiNotar Public CA 2025, emailAddress=info@diginotar.nl",
          "not_before": "2011-07-10",
          "not_after": "2013-07-09"
        },
        {
          "subdomain": "onex.wifi.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2012-02-29",
          "not_after": "2013-02-28"
        },
        {
          "subdomain": "accounts.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-07-13",
          "not_after": "2012-07-13"
        },
        {
          "subdomain": "hosted-id.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority G2",
          "not_before": "2013-11-22",
          "not_after": "2013-11-24"
        },
        {
          "subdomain": "accounts.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-05-11",
          "not_after": "2012-05-11"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-05-11",
          "not_after": "2012-05-11"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-04-13",
          "not_after": "2012-04-13"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-02-16",
          "not_after": "2012-02-16"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-09-05",
          "not_after": "2012-09-05"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-08-12",
          "not_after": "2012-08-12"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-07-27",
          "not_after": "2012-07-27"
        },
        {
          "subdomain": "accounts.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-06-07",
          "not_after": "2012-06-07"
        },
        {
          "subdomain": "wifi.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-06-07",
          "not_after": "2012-06-07"
        },
        {
          "subdomain": "jmt0.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-05-27",
          "not_after": "2012-05-27"
        },
        {
          "subdomain": "wifi.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-05-11",
          "not_after": "2012-05-11"
        },
        {
          "subdomain": "jmt0.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-05-11",
          "not_after": "2012-05-11"
        },
        {
          "subdomain": "upload.video.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-06-07",
          "not_after": "2012-06-07"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-05-27",
          "not_after": "2012-05-27"
        },
        {
          "subdomain": "upload.video.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-05-27",
          "not_after": "2012-05-27"
        },
        {
          "subdomain": "eggroll.ext.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-08-18",
          "not_after": "2011-08-18"
        },
        {
          "subdomain": "sandbox.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-05-11",
          "not_after": "2012-05-11"
        },
        {
          "subdomain": "cod.ext.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-08-05",
          "not_after": "2011-08-05"
        },
        {
          "subdomain": "accounts.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-01-05",
          "not_after": "2012-01-05"
        },
        {
          "subdomain": "sandbox.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-01-05",
          "not_after": "2012-01-05"
        },
        {
          "subdomain": "jmt0.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-06-07",
          "not_after": "2012-06-07"
        },
        {
          "subdomain": "sandbox.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-06-07",
          "not_after": "2012-06-07"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-06-07",
          "not_after": "2012-06-07"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2011-01-05",
          "not_after": "2012-01-05"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-09-02",
          "not_after": "2011-09-02"
        },
        {
          "subdomain": "upload.video.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-05-24",
          "not_after": "2011-05-24"
        },
        {
          "subdomain": "wifi.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-05-24",
          "not_after": "2011-05-24"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-05-24",
          "not_after": "2011-05-24"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-03-05",
          "not_after": "2011-03-05"
        },
        {
          "subdomain": "jmt0.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-05-24",
          "not_after": "2011-05-24"
        },
        {
          "subdomain": "jmt0.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-03-05",
          "not_after": "2011-03-05"
        },
        {
          "subdomain": "sandbox.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-03-05",
          "not_after": "2011-03-05"
        },
        {
          "subdomain": "wifi.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-03-05",
          "not_after": "2011-03-05"
        },
        {
          "subdomain": "accounts.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-03-05",
          "not_after": "2011-03-05"
        },
        {
          "subdomain": "upload.video.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-03-05",
          "not_after": "2011-03-05"
        },
        {
          "subdomain": "sandbox.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2010-05-24",
          "not_after": "2011-05-24"
        },
        {
          "subdomain": "upload.video.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2009-12-22",
          "not_after": "2010-12-22"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2009-12-22",
          "not_after": "2010-12-22"
        },
        {
          "subdomain": "sandbox.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2009-12-22",
          "not_after": "2010-12-22"
        },
        {
          "subdomain": "accounts.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2009-12-22",
          "not_after": "2010-12-22"
        },
        {
          "subdomain": "glass.ext.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2009-10-21",
          "not_after": "2010-10-21"
        },
        {
          "subdomain": "ice.ext.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2009-10-21",
          "not_after": "2010-10-21"
        },
        {
          "subdomain": "www.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2009-11-12",
          "not_after": "2010-11-12"
        },
        {
          "subdomain": "wifi.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2009-11-12",
          "not_after": "2010-11-12"
        },
        {
          "subdomain": "sandbox.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2009-11-12",
          "not_after": "2010-11-12"
        },
        {
          "subdomain": "adwords.google.com",
          "issuer": "C=US, O=Google Inc, CN=Google Internet Authority",
          "not_before": "2009-11-12",
          "not_after": "2010-11-12"
        }
      ]
    },
    "ports": {
      "success": true,
      "target": "google.com",
      "scan_type": "service",
      "hosts_found": 1,
      "results": [
        {
          "host": "142.250.182.206",
          "hostname": "google.com",
          "state": "up",
          "protocols": {
            "tcp": [
              {
                "port": 80,
                "state": "open",
                "service": "http",
                "product": "gws"
              },
              {
                "port": 443,
                "state": "open",
                "service": "https",
                "product": "gws"
              }
            ]
          }
        }
      ]
    },
    "ip_reputation": {
      "success": true,
      "ip": "2404:6800:4002:81b::200e",
      "is_malicious": false,
      "abuse_confidence_score": 0,
      "total_reports": 0,
      "country": "IN",
      "isp": "Asia Pacific Network Information Centre",
      "domain": "apnic.net",
      "usage_type": "Content Delivery Network",
      "last_reported_at": null
    }
  },
  "pre_extracted_signals": {
    "domain_expiry_days": 793,
    "dns_missing_records": [],
    "open_ports": [
      "80/tcp (http)",
      "443/tcp (https)"
    ],
    "ssl_days_remaining": 62,
    "software_detected": [
      "gws"
    ],
    "ip_abuse_score": 0,
    "subdomain_count": 100,
    "missing_security_headers": [
      "strict-transport-security",
      "content-security-policy",
      "x-content-type-options",
      "referrer-policy",
      "permissions-policy"
    ],
    "email_security": {
      "security_score": "90%",
      "rating": "Excellent",
      "spf_found": true,
      "spf_policy": "softfail",
      "dkim_found": true,
      "dmarc_found": true,
      "dmarc_policy": "reject",
      "recommendations": [
        "SPF uses softfail (~all) — consider a hard fail (-all) for stronger protection"
      ]
    },
    "ip_reputation_flagged": false,
    "auto_warnings": [
      "5 security headers missing (strict-transport-security, content-security-policy, x-content-type-options, referrer-policy, permissions-policy) — significant hardening gap",
      "Very large attack surface: 100 subdomains in CT logs"
    ]
  },
  "instructions": "You are a senior penetration tester reviewing raw reconnaissance data collected\nfrom 10 automated tools about the target domain below.\n\nYOUR JOB IS CORRELATION, NOT ENUMERATION.\nDo NOT summarise each tool individually.\nInstead, weave findings across tools into a single coherent threat picture.\nLook especially for combinations that amplify risk — examples:\n  • Outdated CMS (techstack) + missing X-Frame-Options (headers) = clickjacking on a CMS\n    with known exploits\n  • Open port 443 (ports) + SSL cert expiring in < 30 days (ssl) = imminent HTTPS outage\n  • Missing DMARC/SPF/DKIM (email_security) + public-facing mail server = trivial spoofing\n  • High ASN abuse score (asn) + IP flagged by reputation (ip_reputation) = hosting provider\n    actively used for attacks; consider moving infra\n  • Many CT-log subdomains (ct_logs) + weak headers on root domain (headers) = broad surface\n    with inadequate baseline hardening\n\nFollow this exact output structure — no prose outside it:\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n🛡️  AynOps Threat Intelligence Report\nTarget : google.com\nScanned: 2026-07-13T13:42:57.706714Z\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n## Executive Summary\n[Exactly 3 sentences:\n  1. Overall security posture (one word rating + brief reason)\n  2. The single most dangerous finding and what an attacker gains from it\n  3. The one action the domain owner must take TODAY]\n\n## 🔴 Critical Findings\n[Only issues that are directly exploitable RIGHT NOW or expose sensitive data.\n Use this format for every item:\n\n   **[SHORT TITLE]**\n   Risk   : <what an attacker can do — be specific, no vague language>\n   Source : <which tool(s) surfaced this>\n   Correlated with: <other signal(s) that make this worse, or \"None\">\n\n Write \"None identified.\" if nothing qualifies.]\n\n## 🟡 Notable Findings\n[Medium/high risk that are not immediately exploitable but increase attack surface.\n Same format as Critical Findings above.\n Include: outdated software, missing security headers, weak TLS, large subdomain\n surface, email spoofing gaps, permissive ASN neighbourhood, and similar.]\n\n## 🟢 What Is Configured Correctly\n[3 bullet points MAX. Only include things that are genuinely well configured.\n Skip the section entirely if nothing stands out — do not pad.]\n\n## Risk Score\n| Category                        | Score  | Reason (one line)            |\n|---------------------------------|--------|------------------------------|\n| Open ports exposure             |  X/20  | (0 = No Risk, 20 = Max Risk) |\n| SSL / TLS posture               |  X/20  | (0 = No Risk, 20 = Max Risk) |\n| Security headers                |  X/20  | (0 = No Risk, 20 = Max Risk) |\n| Email security (SPF/DKIM/DMARC) |  X/20  | (0 = No Risk, 20 = Max Risk) |\n| IP / ASN reputation             |  X/10  | (0 = No Risk, 10 = Max Risk)  |\n| DNS / subdomain surface         |  X/10   | (0 = No Risk, 10 = Max Risk)  |\n| **TOTAL**                       | **X/100** |                         |\n\nRisk Level: CRITICAL (80–100) / HIGH (60–79) / MEDIUM (40–59) / LOW (0–39)\n(higher score = more risk)\n\n## Remediation Roadmap\n**Immediate — do today (before close of business):**\n  1. ...\n\n**This week:**\n  1. ...\n\n**This month:**\n  1. ...\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\nPRE-EXTRACTED SIGNALS (use these; do not re-derive from raw JSON):\n⚠️  AUTO-WARNINGS (highest priority):\n  • 5 security headers missing (strict-transport-security, content-security-policy, x-content-type-options, referrer-policy, permissions-policy) — significant hardening gap\n  • Very large attack surface: 100 subdomains in CT logs\n\nDomain expiry      : 793 days\nSSL days remaining : 62 days\nOpen ports         : 80/tcp (http), 443/tcp (https)\nSoftware detected  : gws\nSubdomains (CT)    : 100\nIP abuse score     : 0/100\nIP flagged malicious: False\nMissing sec headers: 5 — strict-transport-security, content-security-policy, x-content-type-options, referrer-policy, permissions-policy\nHeaders tool state : unknown\nMissing DNS records : none\nEmail security score: 90% (Excellent)\n  SPF  : ✓ found — policy: softfail\n  DKIM : ✓ found\n  DMARC: ✓ found — policy: reject\nCVEs found         : none\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\nEVIDENCE QUALITY RULES — follow these strictly:\n• Never report a vulnerability solely because data is missing from a tool.\n• IF the Headers tool returned an HTTP status of 4xx or 5xx, or if the scan returned an empty payload, you MUST classify security headers as \"Insufficient data\" rather than \"Missing\". Do not penalize the domain for a blocked or failed request.\n• Use this language:\n    - \"Confirmed\" — tool returned explicit evidence\n    - \"Likely\" — strong indirect evidence from correlated tools\n    - \"Insufficient data\" — tool failed, was blocked, or returned no result\n• CVSS ≥ 9.0 → always Critical regardless of other context\n• CVSS 7.0–8.9 → Notable unless correlated with open port or CMS → then Critical\n• ASN or IP reputation abuse score > 50 → always at least Notable\n• SSL or domain expiry < 14 days → always Critical\n• Missing SPF + missing DMARC → always Critical (trivial spoofing)\n• If a tool was skipped or failed, say so in the relevant finding instead of omitting it\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
}