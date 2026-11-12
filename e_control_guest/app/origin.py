"""Request origin evidence. No DNS, geolocation service or network requests."""
import ipaddress
import hmac
import unicodedata


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


def location_header(request, name):
    """Bounded text from verified Cloudflare location headers, never raw data."""
    raw = single_header(request, name)
    try:
        raw = raw.encode('latin1').decode('utf8')
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    value = unicodedata.normalize('NFC', raw).strip()
    if (not value or len(value) > 100 or any(unicodedata.category(c).startswith('C') for c in value)
            or any(c in '<>"\\' for c in value)):
        return ''
    return value


def request_origin(request, settings):
    peer = address(request.client.host if request.client else "")
    client, source, country, city = peer, "peer", "", ""
    cloudflare_peer = trusted(peer, settings.cloudflare_proxy_cidrs)
    secret = settings.cloudflare_proxy_secret
    supplied = single_header(request, 'x-econtrol-proxy-secret')
    secret_valid = (32 <= len(secret) <= 256 and secret.isascii()
                    and hmac.compare_digest(secret, supplied) if supplied.isascii() else False)
    # This standard HA host gateway is shared by traffic sources. A CIDR alone
    # does not establish which process forwarded a request through it.
    shared_gateway = str(peer) == '172.30.32.1'
    proof_required = bool(secret) or shared_gateway
    cloudflare = cloudflare_peer and (not proof_required or secret_valid)
    proof_failed = cloudflare_peer and proof_required and not secret_valid
    cidrs = settings.trusted_proxy_cidrs + (settings.cloudflare_proxy_cidrs if cloudflare else ())
    if proof_failed:
        source = 'proxy_unresolved'
    if not proof_failed and trusted(peer, cidrs):
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
                if not request.headers.get("cf-worker") and code in COUNTRIES:
                    city = location_header(request, 'cf-ipcity')
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
    observation = {}
    if proof_failed and not request.headers.get("cf-worker"):
        # These values are useful operational evidence, but a shared HA
        # gateway cannot authenticate them. Never feed them into client_ip:
        # Runtime.network_id and rate limiting must keep using the socket peer.
        observed = address(single_header(request, "cf-connecting-ip"))
        if observed is not None and observed.is_global:
            observation = {
                "observed_client_ip": str(observed),
                "observation_source": "cloudflare_headers_unverified",
            }
            code = single_header(request, "cf-ipcountry").upper()
            if code in COUNTRIES or code == "T1":
                observation["observed_country_code"] = code
            if code in COUNTRIES:
                observed_city = location_header(request, "cf-ipcity")
                if observed_city:
                    observation["observed_city"] = observed_city
    kind = "unknown" if client is None else "public" if client.is_global else "local"
    return {"client_ip": str(client) if client is not None else "",
            "ip_source": source, "country_code": country,
            "country_source": "cloudflare" if country else "", "network_kind": kind,
            "city": city, "city_source": "cloudflare" if city else "", **observation}
