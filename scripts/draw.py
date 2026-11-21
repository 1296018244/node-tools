#!/usr/bin/env python3
"""URnetwork auto redraw for GitHub Actions.

- Checks the existing proxy's health; only redraws when it is dead or dirty.
- Draws a clean US residential exit (ip-api proxy=false AND hosting=false,
  real broadband ISP, stable exit IP), verifies google/x, measures speed.
- Publishes a Clash proxy-provider fragment to docs/<SECRET>/node.yaml
  (serve via GitHub Pages; keep the URL secret).
- Stdlib only. Direct connections (GitHub runners have open egress).

Env: URNETWORK_API_KEY (required, from GitHub Secrets).
"""
import json, os, re, socket, ssl, struct, sys, time, urllib.error, urllib.parse, urllib.request

API_BASE = 'https://api.bringyour.com'
API_KEY = os.environ.get('URNETWORK_API_KEY', '')
US_LOCATION = '018bab1d-60e8-27a7-3757-6b11fd7e747c'
SECRET_PATH = 'b408183724197289'  # unguessable Pages path segment; change if leaked
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'docs', SECRET_PATH)
DIALER = '自动选择'  # group name in the user's main Clash config
NODE_NAME = '🇺🇸美国住宅-URnetwork'
MAX_TRIES = 5

DC_KEYWORDS = ('amazon', 'google', 'microsoft', 'digitalocean', 'linode', 'vultr', 'ovh',
               'hetzner', 'cloudflare', 'akamai', 'hosting', 'datacenter', 'data center',
               'server', 'cloud', 'vps', 'dedicated', 'colocation', 'colo')


def log(*a):
    print(*a, flush=True)


def api(method, path, body=None, retries=4):
    url = API_BASE + path
    data = json.dumps(body).encode() if body is not None else None
    last_err = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header('Authorization', f'Bearer {API_KEY}')
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'curl/8.5.0')
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode() or '{}')
            except Exception:
                return e.code, {}
        except Exception as e:
            last_err = e
            time.sleep(3 * (attempt + 1))
    log(f'API {method} {path} unreachable: {type(last_err).__name__}: {last_err}')
    return None, {}


def remove_client(cid):
    if not cid:
        return
    st, _ = api('POST', '/network/remove-client', {'client_id': cid})
    log(f'  remove-client {cid} -> HTTP {st}')


def find_key(obj, key):
    """Recursively find first value for key in nested dicts/lists."""
    if isinstance(obj, dict):
        if key in obj and obj[key]:
            return obj[key]
        for v in obj.values():
            r = find_key(v, key)
            if r:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, key)
            if r:
                return r
    return None


def socks5_connect(gw_host, gw_port, username, password, dst_host, dst_port, timeout=25):
    s = socket.create_connection((gw_host, gw_port), timeout=timeout)
    try:
        s.sendall(b'\x05\x01\x02')  # ver, 1 method, user/pass
        resp = s.recv(2)
        if len(resp) < 2 or resp[1] != 0x02:
            raise ConnectionError('socks auth method rejected')
        u, p = username.encode(), password.encode()
        s.sendall(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
        resp = s.recv(2)
        if len(resp) < 2 or resp[1] != 0x00:
            raise ConnectionError('socks auth failed')
        h = dst_host.encode()
        s.sendall(b'\x05\x01\x00\x03' + bytes([len(h)]) + h + struct.pack('>H', dst_port))
        resp = s.recv(4)
        if len(resp) < 4 or resp[1] != 0x00:
            raise ConnectionError(f'socks connect failed: {resp.hex()}')
        atyp = resp[3]
        if atyp == 1:
            s.recv(4)
        elif atyp == 3:
            n = s.recv(1)[0]
            s.recv(n)
        elif atyp == 4:
            s.recv(16)
        s.recv(2)
        return s
    except Exception:
        s.close()
        raise


def fetch(gw_host, gw_port, token, dst_host, dst_port, use_tls, path, timeout=30, deadline=None):
    t0 = time.time()
    s = socks5_connect(gw_host, gw_port, token, 'x', dst_host, dst_port, timeout=timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=dst_host)
        s.settimeout(timeout)
        s.sendall(f'GET {path} HTTP/1.1\r\nHost: {dst_host}\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n'.encode())
        data = b''
        while True:
            if deadline and time.time() - t0 > deadline:
                break
            try:
                chunk = s.recv(65536)
            except Exception:
                break
            if not chunk:
                break
            data += chunk
        elapsed = time.time() - t0
        code = 0
        head, _, body = data.partition(b'\r\n\r\n')
        parts = head.split(b'\r\n')[0].decode('latin1', 'replace').split()
        if len(parts) >= 2 and parts[1].isdigit():
            code = int(parts[1])
        return code, body, elapsed
    finally:
        try:
            s.close()
        except Exception:
            pass


def ipapi(gw_host, gw_port, token, attempts=3):
    last = None
    for i in range(attempts):
        try:
            code, body, _ = fetch(gw_host, gw_port, token, 'ip-api.com', 80, False,
                                  '/json/?fields=status,country,regionName,city,isp,org,as,proxy,hosting,query',
                                  timeout=25)
            if code == 200 and body:
                return json.loads(body.decode()), None
            last = f'http {code}'
        except Exception as e:
            last = f'{type(e).__name__}: {e}'
        time.sleep(3)
    return None, last


def isp_ok(info):
    blob = ' '.join(str(info.get(k) or '') for k in ('isp', 'org', 'as')).lower()
    for kw in DC_KEYWORDS:
        if kw in blob:
            return False, f'datacenter keyword: {kw}'
    return True, ''


def clean_check(info):
    if not info:
        return False, ['no info']
    reasons = []
    if info.get('status') != 'success':
        reasons.append('status')
    if info.get('country') != 'United States':
        reasons.append('country')
    if info.get('proxy') is not False:
        reasons.append('proxy')
    if info.get('hosting') is not False:
        reasons.append('hosting')
    ok, why = isp_ok(info)
    if not ok:
        reasons.append(why)
    return (not reasons), reasons


def verify_node(gw_host, gw_port, token, full=True):
    """Returns (info, speed_bps, g_latency) or (None, 0, 999) if unusable."""
    info, err = ipapi(gw_host, gw_port, token)
    if info is None:
        log(f'  ip-api failed: {err}')
        return None, 0, 999
    log(f'  exit ip={info.get("query")} city={info.get("city")} country={info.get("country")} '
        f'isp={info.get("isp")} proxy={info.get("proxy")} hosting={info.get("hosting")}')
    ok, reasons = clean_check(info)
    if not ok:
        log(f'  FAIL clean check: {reasons}')
        return None, 0, 999
    time.sleep(5)
    info2, _ = ipapi(gw_host, gw_port, token, attempts=2)
    if info2 is None or info2.get('query') != info.get('query'):
        log('  FAIL ip unstable')
        return None, 0, 999
    try:
        gcode, _, g_elapsed = fetch(gw_host, gw_port, token, 'www.google.com', 443, True,
                                    '/generate_204', timeout=30)
    except Exception as e:
        gcode, g_elapsed = f'ERR {e}', 999
    log(f'  google 204 -> {gcode} in {g_elapsed:.1f}s')
    if gcode != 204:
        return None, 0, 999
    speed_bps = 0.0
    if full:
        try:
            scode, sbody, s_elapsed = fetch(gw_host, gw_port, token, 'speed.cloudflare.com', 443, True,
                                            '/__down?bytes=200000', timeout=15, deadline=40)
            if s_elapsed > 0:
                speed_bps = len(sbody) / s_elapsed
            log(f'  speed: http {scode} {len(sbody)}B in {s_elapsed:.1f}s = {speed_bps/1e6:.3f} MB/s')
        except Exception as e:
            log(f'  speed ERR: {type(e).__name__}: {e}')
    return info, speed_bps, g_elapsed


def write_fragment(gw_host, gw_port, token, info):
    os.makedirs(OUT_DIR, exist_ok=True)
    try:
        server_ip = socket.gethostbyname(gw_host)
    except Exception:
        server_ip = gw_host
    yaml_text = (
        'proxies:\n'
        f'  - name: {NODE_NAME}\n'
        '    type: socks5\n'
        f'    server: {server_ip}\n'
        f'    port: {gw_port}\n'
        f'    username: "{token}"\n'
        '    password: x\n'
        f'    dialer-proxy: {DIALER}\n'
    )
    with open(os.path.join(OUT_DIR, 'node.yaml'), 'w') as f:
        f.write(yaml_text)
    city = (info.get('city') or 'US').replace(' ', '-')
    isp = (info.get('isp') or 'ISP').replace(' ', '-')
    link = f'socks://{token}:@{gw_host}:{gw_port}#URnetwork-US-{city}-{isp}-Clean'
    with open(os.path.join(OUT_DIR, 'node.txt'), 'w') as f:
        f.write(link + '\n')
    log(f'wrote fragment for {info.get("query")} ({info.get("city")}, {info.get("isp")})')


def main():
    if not API_KEY:
        log('URNETWORK_API_KEY env missing')
        return 1

    # 1) existing proxies: keep a healthy one
    st, res = api('GET', '/network/proxies')
    existing = res.get('clients', []) if st == 200 else []
    log(f'existing proxies: {len(existing)}')
    kept = None  # (client_id, gw_host, gw_port, token, info)
    for c in existing:
        cid = c.get('client_id')
        token = find_key(c, 'auth_token') or ''
        socks_url = find_key(c, 'socks_proxy_url') or ''
        if not token or not socks_url:
            log(f'  {cid}: no usable credentials, will remove')
            remove_client(cid)
            continue
        sp = urllib.parse.urlparse(socks_url)
        log(f'checking existing {cid} via {sp.hostname}:{sp.port} ...')
        info, _, _ = verify_node(sp.hostname, sp.port, token, full=False)
        if info and kept is None:
            kept = (cid, sp.hostname, sp.port, token, info)
            log('  existing node healthy, keeping')
        else:
            remove_client(cid)
    if kept:
        _, gw_host, gw_port, token, info = kept
        write_fragment(gw_host, gw_port, token, info)
        log('done (kept existing)')
        return 0

    # 2) redraw: merge samples, prefer specific-city locations
    pool = {}
    for i in range(3):
        st, res = api('POST', '/network/find-providers2', {'specs': [{'location_id': US_LOCATION}]})
        if st != 200:
            log(f'sample {i} failed: HTTP {st}')
            continue
        for p in res.get('providers', []):
            pool[p.get('client_id')] = p
        time.sleep(2)
    provs = list(pool.values())

    def city_key(p):
        city = ((p.get('location') or {}).get('city') or '').strip().lower()
        generic = 1 if city in ('united states', 'us', '') else 0
        return (generic, -(p.get('estimated_bytes_per_second') or 0))

    provs.sort(key=city_key)
    log(f'unique providers: {len(provs)}')

    passing = []
    tries = 0
    for prov in provs:
        if tries >= MAX_TRIES:
            break
        tries += 1
        pid = prov.get('client_id')
        loc = prov.get('location') or {}
        log(f'\n=== try {tries}/{MAX_TRIES}: {pid} ({loc.get("city")}, {loc.get("region")})')
        body = {'proxy_config': {'initial_device_state': {'location': {'connect_location_id': {'client_id': pid}}}}}
        st, res = api('POST', '/network/auth-client', body)
        if st != 200:
            log(f'  auth-client failed: HTTP {st}')
            continue
        pcr = res.get('proxy_config_result') or {}
        token = pcr.get('auth_token') or ''
        cid = res.get('client_id')
        socks_url = pcr.get('socks_proxy_url') or ''
        if socks_url:
            sp = urllib.parse.urlparse(socks_url)
            gw_host, gw_port = sp.hostname, sp.port
        else:
            gw_host, gw_port = 'crisp.bringyour.com', 7117
        log(f'  socks {gw_host}:{gw_port} client {cid}')
        if not token:
            remove_client(cid)
            continue
        time.sleep(5)
        info, speed_bps, g_latency = verify_node(gw_host, gw_port, token, full=True)
        if info and speed_bps > 0:
            passing.append({'client_id': cid, 'token': token, 'host': gw_host, 'port': gw_port,
                            'info': info, 'speed_bps': speed_bps, 'g_latency': g_latency})
            log(f'  PASS candidate speed {speed_bps/1e6:.3f} MB/s')
        else:
            log('  FAIL, removing')
            remove_client(cid)

    if not passing:
        log('NO PASSING CANDIDATE')
        return 2

    passing.sort(key=lambda p: (p['g_latency'], -p['speed_bps']))
    best = passing[0]
    for p in passing[1:]:
        remove_client(p['client_id'])
    log(f'\nBEST: {best["info"].get("query")} g204={best["g_latency"]:.1f}s speed={best["speed_bps"]/1e6:.3f} MB/s')
    write_fragment(best['host'], best['port'], best['token'], best['info'])
    log('done (redrawn)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
