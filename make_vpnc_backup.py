#!/usr/bin/env python3
"""Build a VPN Client Pro (.bak, 'vpncbackup') file from a plain server list.

Format (reverse-engineered from the app's own backup/restore code):
  header : 'vpncbackup' | u32be version=1 | u32be flags=1 (password) | salt[8] | check[32]
  check  : SHA256(salt+pw) then 5x SHA256
  body   : <vpncbackup><Profiles><profile id=UUID>base64(blob)</profile>...</Profiles></vpncbackup>
  blob   : AES-128-CTR(profile xml); key||iv = SHA256(n(salt,id) + salt + pw) then 5x SHA256
"""
import argparse, base64, hashlib, os, re, struct, sys, uuid
from xml.sax.saxutils import escape
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b'vpncbackup'


def chain(*parts, rounds=5):
    h = hashlib.sha256(b''.join(parts)).digest()
    for _ in range(rounds):
        h = hashlib.sha256(h).digest()
    return h


def ctr(k1, k2, k3, data):
    key = chain(k1, k2, k3)
    c = Cipher(algorithms.AES(key[:16]), modes.CTR(key[16:32])).encryptor()
    return c.update(data) + c.finalize()


def xml_text(s):
    # escape, and write astral chars (emoji) as numeric refs, like the app does
    s = escape(s)
    return ''.join('&#%d;' % ord(ch) if ord(ch) > 0xFFFF else ch for ch in s)


def sstp_profile(pid, name, host, port=443, sni=None, user='vpn', password='vpn', mtu=1300):
    conn_opts = '<option id="10030">%d</option>' % port
    if sni:
        conn_opts += '<option id="10370">%s</option>' % xml_text(sni)
    conn_opts += '<option id="10160">%d</option><option id="10010">%s</option>' % (mtu, xml_text(host))
    return (
        "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>"
        '<sstp version="6"><uuid>%s</uuid><name>%s</name><owner></owner><ownerTag></ownerTag>'
        '<usageTimestamp>0</usageTimestamp><preferred>true</preferred>'
        '<Options><option id="30060">false</option><option id="30220">true</option>'
        '<option id="30030">%s</option><option id="30210">true</option>'
        '<option id="30230">false</option><option id="30180">true</option>'
        '<option id="60010">true</option><option id="30040">%s</option>'
        '<option id="30200">true</option></Options>'
        '<Connections><connection id="%s"><Options>%s</Options><HttpCustomHeaders /></connection></Connections>'
        '<IPv4Routes /><IPv6Routes /><AppFilterList /><OnDemandRoutes /><WifiSSIDList />'
        '<CaList /><ExtraCertList /><GroupList /></sstp>'
    ) % (pid, xml_text(name), xml_text(user), xml_text(password), uuid.uuid4(), conn_opts)


def read_backup(path, password):
    d = open(path, 'rb').read()
    assert d[:10] == MAGIC, 'not a vpncbackup file'
    salt, chk = d[18:26], d[26:58]
    pw = password.encode()
    if chain(salt, pw) != chk:
        raise SystemExit('wrong password for existing backup')
    body = d[58:].decode()
    profs = {}
    for pid, b in re.findall(r'<profile id="([^"]+)">([^<]*)</profile>', body):
        profs[pid] = ctr(chain(salt, pid.encode()), salt, pw, base64.b64decode(b))
    prefs = re.findall(r'<Preferences id="[^"]+">[^<]*</Preferences>', body)
    return salt, pw, profs, prefs


def write_backup(path, password, profiles, keep_prefs=None):
    """profiles: dict {uuid: xml_bytes}. keep_prefs: raw <Preferences> xml strings to copy (same salt only)."""
    salt = os.urandom(8)
    pw = password.encode()
    out = [MAGIC, struct.pack('>II', 1, 1), salt, chain(salt, pw)]
    xml = ["<?xml version='1.0' encoding='utf-8' standalone='yes' ?><vpncbackup><Profiles>"]
    for pid, data in profiles.items():
        blob = ctr(chain(salt, pid.encode()), salt, pw, data)
        xml.append('<profile id="%s">%s</profile>' % (pid, base64.b64encode(blob).decode()))
    xml.append('</Profiles>')
    xml.append('</vpncbackup>')
    out.append(''.join(xml).encode())
    open(path, 'wb').write(b''.join(out))


def parse_list(text):
    """Lines: 'name | host | port | sni | user | pass' (also accepts ',' ';' or tab; only host is required).
    A bare 'host' or 'host:port' works too."""
    servers = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = [p.strip() for p in re.split(r'\s*[|;\t,]\s*', line)]
        if len(parts) == 1:
            host = parts[0]; name = host; rest = []
        else:
            # if first field looks like a host and 2nd like a number -> no name given
            if re.fullmatch(r'[\w.-]+\.[A-Za-z]{2,}(:\d+)?', parts[0]) and len(parts) > 1 and parts[1].isdigit():
                name = parts[0]; host = parts[0]; rest = parts[1:]
            else:
                name, host, rest = parts[0], parts[1], parts[2:]
        port = 443
        if ':' in host and host.rsplit(':', 1)[1].isdigit():
            host, p = host.rsplit(':', 1); port = int(p)
        # positional fields after host: port (may be empty), sni, user, pass
        if rest and (rest[0] == '' or rest[0].isdigit()):
            if rest[0].isdigit():
                port = int(rest[0])
            rest = rest[1:]
        sni = rest[0] if len(rest) > 0 and rest[0] else None
        user = rest[1] if len(rest) > 1 and rest[1] else 'vpn'
        pw = rest[2] if len(rest) > 2 and rest[2] else 'vpn'
        servers.append(dict(name=name, host=host, port=port, sni=sni, user=user, password=pw))
    return servers


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('list', help='text file with the server list')
    ap.add_argument('-o', '--out', default='VPNClientPro_custom.bak')
    ap.add_argument('-p', '--password', default='1234')
    ap.add_argument('--merge', help='existing .bak to keep its profiles and add the new ones')
    ap.add_argument('--merge-password', default='1234')
    a = ap.parse_args()
    profiles = {}
    if a.merge:
        _, _, old, _ = read_backup(a.merge, a.merge_password)
        profiles.update(old)
    for s in parse_list(open(a.list, encoding='utf-8').read()):
        pid = str(uuid.uuid4())
        profiles[pid] = sstp_profile(pid, **s).encode('utf-8')
    write_backup(a.out, a.password, profiles)
    print('wrote', a.out, 'with', len(profiles), 'profiles')


if __name__ == '__main__':
    main()
