# ipgeo Community Edition — field reference

Read the MMDB with any maxminddb reader's generic `.get(ip)`. This is
`DatabaseType: "ipgeo"` with a FLAT record schema — it is NOT a typed geoip2
City database, so use `.get()`, not `.city()`. A field is ABSENT from a record
when unknown.

| Field           | Type    | Notes                                                    |
| --------------- | ------- | -------------------------------------------------------- |
| `country_code`  | string  | ISO 3166-1 alpha-2 (e.g. "US")                           |
| `country_name`  | string  | English country name, derived from `country_code`        |
| `region`        | string  | Region / state name                                      |
| `city`          | string  | City name                                                |
| `postal_code`   | string  | Postal / ZIP code; present on a small minority of records |
| `latitude`      | float64 | WGS84                                                    |
| `longitude`     | float64 | WGS84                                                    |
| `timezone`      | string  | IANA tz name (e.g. "America/New_York") OR a fixed UTC offset (e.g. "-07:00") — both forms occur, so parse for either |
| `asn`           | uint32  | Autonomous System Number                                 |
| `as_org`        | string  | AS organization / operator                               |
| `is_vpn`        | bool    | true when the ASN is a known VPN network (native ASN)    |
| `is_proxy`      | bool    | RESERVED — in the schema, not populated in this release   |
| `is_datacenter` | bool    | true when the ASN is datacenter / hosting                |
| `ip_type`       | string  | datacenter / cdn / mobile_carrier / satellite / education / government |

## Field coverage
Absent means unknown, and coverage differs a lot between fields: `country_code`
and `timezone` are near-universal, `city`/`region`/`latitude`/`longitude` are
high but not complete, the ASN-derived fields cover most of the space, and
`postal_code` and `ip_type` are sparse — `postal_code` especially, so do not
build on it. `is_proxy` is RESERVED — it is part of the schema so the shape
stays stable, but no record carries a value for it in this release. Do not
treat its absence as a negative signal. Coverage is restated per release in the release
notes; check it there rather than assuming last week's numbers still hold.

## community-vpn-list.csv
Columns `network,provider,basis` — `basis` is `asn`, `x4bnet`, or `cluster`;
`provider` is the VPN brand where known. Rows with `basis=x4bnet` are used under
the MIT license (see VPN-ATTRIBUTION.txt).

Provider names live in this file ONLY — the MMDB carries the `is_vpn` flag but
never a provider name, and the two are built from different inputs, so a range
listed here will not always have `is_vpn` set on its MMDB record. Match against
this list when you need to name the operator or want its full coverage.

## Not included (commercial WhoisXML API IP Geolocation products only)
Per-IP (/32) precision, confidence scores, `observed_*` fields, suspect classes,
and daily cadence.
