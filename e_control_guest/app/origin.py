"""Request origin evidence. No DNS, geolocation service or network requests."""
import ipaddress


COUNTRIES = frozenset("""AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF
BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO
CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB
GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN
IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT
LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC
NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO
RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG
TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE
YT ZA ZM ZW""".split())


def address(value):
    if not isinstance(value, str) or len(value) > 64 or "%" in value:
        return None
    try:
        parsed = ipaddress.ip_address(value.strip())
        return getattr(parsed, "ipv4_mapped", None) or parsed
    except ValueError:
        return None


def trusted(peer, cidrs):
    if peer is None:
        return False
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.prefixlen > 0 and peer.version == network.version and peer in network:
                return True
        except (TypeError, ValueError):
            continue
    return False


def single_header(request, name):
    values = request.headers.getlist(name)
    return values[0].strip() if len(values) == 1 else ""


def request_origin(request, settings):
    peer = address(request.client.host if request.client else "")
    client, source, country = peer, "peer", ""
    cloudflare = trusted(peer, settings.cloudflare_proxy_cidrs)
    cidrs = settings.trusted_proxy_cidrs + settings.cloudflare_proxy_cidrs
    if trusted(peer, cidrs):
        source = "proxy_unresolved"
        if cloudflare:
            # Only an explicitly authorized Cloudflare connector may supply
            # these headers. Generic reverse proxies are not sufficient.
            visitor = address(single_header(request, "cf-connecting-ip"))
            ipv6 = address(single_header(request, "cf-connecting-ipv6"))
            if (visitor is not None and visitor.version == 4 and int(visitor) >> 28 == 15
                    and ipv6 is not None and ipv6.version == 6 and ipv6.is_global):
                visitor = ipv6
            if visitor is not None and visitor.is_global:
                client, source = visitor, "cloudflare"
                code = single_header(request, "cf-ipcountry").upper()
                # Worker subrequests can alter origin evidence; do not assign
                # a geographic country in this unsupported path.
                if not request.headers.get("cf-worker") and (code in COUNTRIES or code == "T1"):
                    country = code
        if source == "proxy_unresolved":
            forwarded = single_header(request, "x-forwarded-for")
            parts = forwarded.split(",") if forwarded and len(forwarded) <= 2048 else []
            hops = [address(part) for part in parts] if len(parts) <= 16 else []
            if hops and all(hop is not None for hop in hops):
                candidate = peer
                for hop in reversed(hops):
                    if not trusted(candidate, cidrs):
                        break
                    candidate = hop
                # A chain made exclusively of trusted hops does not identify
                # a visitor. Never label a connector as the original client.
                if not trusted(candidate, cidrs):
                    client, source = candidate, "forwarded"
    kind = "unknown" if client is None else "public" if client.is_global else "local"
    return {"client_ip": str(client) if client is not None else "",
            "ip_source": source, "country_code": country,
            "country_source": "cloudflare" if country else "", "network_kind": kind}
