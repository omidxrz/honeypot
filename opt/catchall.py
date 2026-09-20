#!/usr/bin/env python3
"""All-port TCP catch-all. Logs peer, intended port, and opening bytes. Never executes anything."""
import base64, json, os, re, socket, ssl, struct, sys, threading, time

LOG = "/opt/honeypot/logs/hp.jsonl"
CERT = "/opt/honeypot/hp.pem"
BIND = ("0.0.0.0", 8000)
SO_ORIGINAL_DST = 80
MAXBYTES = 4096
IDLE = 1.5          # wait for a client that speaks first
AFTER_BANNER = 2.0  # wait after we prompt a server-speaks-first protocol
MAXLOG = 512 << 20  # rotate one generation at 512 MiB; ~34 MiB/day observed
CHECK_EVERY = 1000  # records between size checks, so it is not a stat per connection
SEM = threading.Semaphore(300)
LOCK = threading.Lock()
SINCE_CHECK = 0
HOSTCHARS = re.compile(rb"^[a-z0-9.\-]{1,253}$")

# Only enough to make server-speaks-first protocols talk. Not emulation.
BANNERS = {
    21:   b"220 ProFTPD 1.3.5e Server ready\r\n",
    22:   b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
    23:   b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27\r\nlogin: ",
    25:   b"220 mail.internal ESMTP Postfix (Ubuntu)\r\n",
    110:  b"+OK POP3 server ready\r\n",
    143:  b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR] Dovecot ready.\r\n",
    465:  b"220 mail.internal ESMTP Postfix (Ubuntu)\r\n",
    587:  b"220 mail.internal ESMTP Postfix (Ubuntu)\r\n",
    1723: b"",
    3306: b"J\x00\x00\x00\n5.7.42-0ubuntu0.18.04.1\x00\x08\x00\x00\x00"
          b"\x51\x6d\x33\x7a\x2f\x53\x69\x00\xff\xf7\x08\x02\x00\xff\x81\x15"
          b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2c\x54\x5a\x37\x71\x66"
          b"\x62\x76\x5f\x39\x4b\x00mysql_native_password\x00",
    5900: b"RFB 003.008\n",
    6379: b"",
    11211: b"",
}


def original_dst(sock):
    """The port the client actually aimed at, before nftables redirected it here.

    SO_ORIGINAL_DST is a Linux netfilter option and only answers when a NAT
    redirect put this connection here. Without one -- a container on a bridge
    network with a few published ports, or anything not Linux -- it raises, and
    the socket's own local address IS the intended destination. Falling back to
    it keeps `dport` a real port instead of null in those setups; on the sensor
    the getsockopt always succeeds, so the fallback never runs there."""
    try:
        raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port, a, b, c, d = struct.unpack("!2xH4B8x", raw)
        return "%d.%d.%d.%d" % (a, b, c, d), port
    except (OSError, AttributeError, struct.error):
        try:
            ip, port = sock.getsockname()[:2]
            return ip, port
        except OSError:
            return None, None


def sni(hello):
    """The Name from a TLS ClientHello, or "". Never raises: this is attacker input.

    Best effort by design. The hello is whatever one peek returned, so a Name
    sitting behind a very long extension list can be missed; a missed Name costs
    one Contact, a raised exception would cost the connection.
    """
    try:
        if len(hello) < 44 or hello[0] != 0x16 or hello[5] != 0x01:
            return ""
        i = 43
        i += 1 + hello[i]                                        # session id
        i += 2 + int.from_bytes(hello[i:i + 2], "big")           # cipher suites
        i += 1 + hello[i]                                        # compression methods
        end = min(i + 2 + int.from_bytes(hello[i:i + 2], "big"), len(hello))
        i += 2
        while i + 4 <= end:
            etype = int.from_bytes(hello[i:i + 2], "big")
            elen = int.from_bytes(hello[i + 2:i + 4], "big")
            if etype == 0:                                       # server_name
                b = hello[i + 4:i + 4 + elen]
                if len(b) >= 5 and b[2] == 0:                    # name_type host_name
                    nlen = int.from_bytes(b[3:5], "big")
                    n = b[5:5 + nlen].lower()
                    if len(n) != nlen:                           # truncated: slicing
                        return ""                                # silently shortens, so check
                    return n.decode("ascii") if HOSTCHARS.match(n) else ""
                return ""
            i += 4 + elen
        return ""
    except (IndexError, ValueError, UnicodeDecodeError):
        return ""


def write(rec):
    """Append one record. Rotates one generation so the disk is not the end state.

    Rotation changes the inode, so rollup.py restarts at zero on the fresh file
    (resume_at handles that); whatever it had not yet read of the old one goes
    with it -- at most one timer interval.
    """
    global SINCE_CHECK
    line = json.dumps(rec, separators=(",", ":")) + "\n"
    with LOCK:
        SINCE_CHECK += 1
        if SINCE_CHECK >= CHECK_EVERY:
            SINCE_CHECK = 0
            try:
                if os.path.getsize(LOG) >= MAXLOG:
                    os.replace(LOG, LOG + ".1")
            except OSError:
                pass
        with open(LOG, "a") as f:
            f.write(line)


def preview(data):
    try:
        return data[:200].decode("utf-8", "replace").replace("\x00", ".")
    except Exception:
        return ""


def handle(conn, peer):
    dst_ip, dport = original_dst(conn)
    rec = {
        "t": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "src": "hp",
        "ip": peer[0],
        "sport": peer[1],
        "dport": dport,
        "dst": dst_ip,
        "tls": False,
        "banner": False,
        "n": 0,
    }
    data = b""
    hello = b""
    try:
        conn.settimeout(IDLE)
        try:
            head = conn.recv(1, socket.MSG_PEEK)
        except (socket.timeout, TimeoutError):
            head = b""

        if not head and dport in BANNERS and BANNERS[dport]:
            conn.sendall(BANNERS[dport])
            rec["banner"] = True
            conn.settimeout(AFTER_BANNER)
            try:
                data = conn.recv(MAXBYTES)
            except (socket.timeout, TimeoutError):
                data = b""
        elif head[:1] == b"\x16":
            # TLS: keep the ClientHello so JA3/JA4 can be computed offline, then read plaintext
            rec["tls"] = True
            try:
                hello = conn.recv(MAXBYTES, socket.MSG_PEEK)
            except Exception:
                hello = b""
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            ctx.load_cert_chain(CERT)
            try:
                tconn = ctx.wrap_socket(conn, server_side=True)
                tconn.settimeout(AFTER_BANNER)
                data = tconn.recv(MAXBYTES)
                conn = tconn
            except (ssl.SSLError, OSError):
                data = b""
        else:
            try:
                data = conn.recv(MAXBYTES)
            except (socket.timeout, TimeoutError):
                data = b""
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass
        SEM.release()

    if hello:
        name = sni(hello)
        if name:
            rec["sni"] = name
    rec["n"] = len(data)
    if data:
        rec["b64"] = base64.b64encode(data).decode()
        rec["preview"] = preview(data)
    if hello:
        rec["hello_b64"] = base64.b64encode(hello[:512]).decode()
    write(rec)


def bind_ports(raw=None):
    """Ports to listen on, from $HP_BIND_PORTS. Default: just 8000.

    On the sensor that default is the whole story -- nftables redirects all
    65,535 ports to 8000 and SO_ORIGINAL_DST recovers which one was meant, so
    one listener sees everything. Somewhere without that redirect (a container
    on a bridge network) nothing arrives on 8000 at all, and the only way to
    see a given port is to actually listen on it. Junk is dropped rather than
    raising: this reads an environment variable, and refusing to start the
    capture over a stray comma is the worse failure."""
    if raw is None:
        raw = os.environ.get("HP_BIND_PORTS", "")
    out = []
    for part in raw.replace(" ", "").split(","):
        if part.isdigit() and 1 <= int(part) <= 65535 and int(part) not in out:
            out.append(int(part))
    return out or [BIND[1]]


def serve(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND[0], port))
    srv.listen(512)
    while True:
        try:
            conn, peer = srv.accept()
        except OSError:
            continue
        if not SEM.acquire(blocking=False):
            conn.close()   # ponytail: shed load rather than queue; raise the semaphore if drops matter
            continue
        threading.Thread(target=handle, args=(conn, peer), daemon=True).start()


def main():
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    ports = bind_ports()
    # One shared semaphore across every listener, so the 300-connection budget
    # is the process's, not each port's.
    for p in ports[1:]:
        threading.Thread(target=serve, args=(p,), daemon=True).start()
    serve(ports[0])


def _hello(name=b"a.example", extra_exts=b""):
    """Build a ClientHello carrying an SNI, for the self-check."""
    sni_ext = b"\x00\x00" + struct.pack("!H", len(name) + 5) + \
        struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
    exts = extra_exts + sni_ext if name else extra_exts
    body = (b"\x03\x03" + b"R" * 32 + b"\x00" +          # version, random, no session id
            b"\x00\x02\x13\x01" + b"\x01\x00" +        # one cipher suite, null compression
            struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def demo():
    """Self-check: original_dst parsing, SNI extraction, record shape. No network."""
    raw = struct.pack("!HH4B8x", socket.AF_INET, 8080, 10, 0, 0, 7)
    port, a, b, c, d = struct.unpack("!2xH4B8x", raw)
    assert (port, a, b, c, d) == (8080, 10, 0, 0, 7), (port, a, b, c, d)

    # On the sensor the redirect answers, and its answer must be used as-is.
    # This fake fails loudly if the fallback below ever masks a working
    # redirect -- that would report every connection as arriving on 8000 and
    # quietly destroy the port column the whole panel is built on.
    class _Redirected:
        def getsockopt(self, *a):
            return struct.pack("!HH4B8x", socket.AF_INET, 5900, 203, 0, 113, 9)

        def getsockname(self):
            raise AssertionError("fell back although SO_ORIGINAL_DST answered")

    assert original_dst(_Redirected()) == ("203.0.113.9", 5900), original_dst(_Redirected())

    # No redirect: a bridged container, or any host that is not Linux. The
    # socket's own address is then the port the client actually aimed at.
    # Without the fallback every record here logs dport null.
    class _NoRedirect:
        def getsockopt(self, *a):
            raise OSError(92, "Protocol not available")

        def getsockname(self):
            return ("192.0.2.7", 2323)

    assert original_dst(_NoRedirect()) == ("192.0.2.7", 2323), original_dst(_NoRedirect())

    # A socket that died mid-handshake answers neither. Still must not raise:
    # this runs per connection, on attacker-controlled timing.
    class _Dead:
        def getsockopt(self, *a):
            raise OSError(9, "Bad file descriptor")

        def getsockname(self):
            raise OSError(9, "Bad file descriptor")

    assert original_dst(_Dead()) == (None, None), "a dead socket must not raise"

    # Unset must stay exactly the sensor's behaviour: one listener on 8000.
    # Anything else changes what the live capture binds.
    assert bind_ports("") == [8000], bind_ports("")
    assert bind_ports("23,22,3306") == [23, 22, 3306]
    assert bind_ports(" 23 , 23 ,8000") == [23, 8000], "duplicates collapse, order kept"
    assert bind_ports("0,65536,-1,http,") == [8000], "out-of-range and junk fall back"
    assert bind_ports("65535") == [65535], "the top of the range is valid"

    assert preview(b"GET / HTTP/1.1\r\n\x00") == "GET / HTTP/1.1\r\n."
    assert BANNERS[22].startswith(b"SSH-2.0-")

    # the Name, which is what makes a Contact on a port nginx never sees
    assert sni(_hello(b"ops.example.com")) == "ops.example.com"
    assert sni(_hello(b"A.EXAMPLE")) == "a.example", "Names are compared lowercased"
    assert sni(_hello(b"", b"\x00\x17\x00\x00")) == "", "no SNI extension"
    assert sni(_hello(b"a.example", b"\x00\x17\x00\x00")) == "a.example", "SNI after another ext"

    # attacker input: every one of these must return "", not raise
    h = _hello()
    for bad in (b"", b"\x16", b"\x15" + h[1:], h[:20], h[:44],
                h.replace(b"a.example", b"a.exa"), b"\x16\x03\x01\xff\xff\x01\xff\xff\xff",
                h[:5] + b"\x02" + h[6:], bytes(len(h))):
        assert sni(bad) == "", bad[:12]
    assert sni(_hello(b"bad name!")) == "", "a Name that is not a hostname is dropped"
    print("catchall self-check ok")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        main()
