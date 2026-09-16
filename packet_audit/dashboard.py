"""Loopback-only, authenticated, read-only viewer for existing JSONL evidence.

The capture process never imports or waits on this server. Reads, responses,
browser history and retained rows are bounded; the JSONL export remains the
complete record. No captured value is interpreted as HTML or executable code.
"""

from __future__ import annotations

import base64
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import math
import os
from pathlib import Path
import secrets
import stat
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .writer import prepare_private_directory


MAX_READ_BYTES = 1024 * 1024
MAX_RECORDS = 500
MAX_JSON_DEPTH = 128
FILES = {"findings": "findings-unredacted.jsonl", "operations": "operations.jsonl"}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'none'; object-src 'none'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)


def _endpoint(value: Any) -> str | None:
    if isinstance(value, dict):
        address, port = value.get("address", value.get("ip")), value.get("port")
        if isinstance(address, str) and isinstance(port, int):
            return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
    return value if isinstance(value, str) else None


def normalize_finding(record: dict[str, Any]) -> dict[str, Any]:
    """Add display endpoints without guessing direction or altering evidence."""
    result = dict(record)
    source, destination = _endpoint(record.get("source")), _endpoint(record.get("destination"))
    if source is None:
        source = _endpoint({"address": record.get("source_ip"), "port": record.get("source_port")})
    if destination is None:
        destination = _endpoint({"address": record.get("destination_ip"), "port": record.get("destination_port")})
    parts = str(record.get("flow_id", "")).split("|")
    direction = record.get("direction")
    if len(parts) >= 5 and type(direction) is int and direction in (0, 1):
        source = source or parts[3 + direction]
        destination = destination or parts[4 - direction]
    result["source_endpoint"] = source
    result["destination_endpoint"] = destination
    return result


def _cursor(identity: tuple[int, int], offset: int, discard: bool = False) -> str:
    raw = json.dumps([*identity, offset, discard], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str) -> tuple[tuple[int, int], int, bool]:
    try:
        if len(cursor) > 160:
            raise ValueError
        values = json.loads(base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True))
        if (not isinstance(values, list) or len(values) != 4
                or any(type(value) is not int or value < 0 for value in values[:3])
                or type(values[3]) is not bool):
            raise ValueError
        return (values[0], values[1]), values[2], values[3]
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("invalid cursor") from exc


def _reject_nonfinite(_value: str) -> None:
    raise ValueError("nonfinite number")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite number")
    return result


def _check_json_depth(line: bytes) -> None:
    """Bound parser/serializer nesting independently of Python's stack limit.

    JSON structure uses ASCII delimiters even in UTF-8 input. Delimiters in
    strings (including escaped quotes and backslashes) are not structure.
    Syntax validation remains the JSON decoder's responsibility.
    """
    depth = 0
    quoted = False
    escaped = False
    for byte in line:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:  # backslash
                escaped = True
            elif byte == 34:  # double quote
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):  # [ {
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("evidence JSON exceeds dashboard nesting limit")
        elif byte in (93, 125):  # ] }
            depth -= 1


def read_page(path: Path, cursor: str | None = None, limit: int = 200) -> dict[str, Any]:
    """Read at most 1 MiB; paginate complete lines and tolerate a partial tail.

    Initial requests show a recent bounded tail, never a full historical scan.
    Subsequent requests advance their cursor. Oversized records are skipped
    visibly, including across reads, rather than blocking the viewer forever.
    """
    limit = max(1, min(MAX_RECORDS, limit))
    decoded = _decode_cursor(cursor) if cursor else None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise PermissionError("evidence must be a regular, non-symlink file")
        if os.name == "nt":
            from .windows_security import private_acl_error
            error = private_acl_error(path)
            if error:
                raise PermissionError(error)
        fd = os.open(path, flags)
    except FileNotFoundError:
        return {"records": [], "cursor": None, "missing": True, "reset": bool(cursor),
                "more": False, "skipped": 0, "window_limited": False, "bytes_read": 0}
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino) != (before.st_dev, before.st_ino)):
            raise PermissionError("evidence changed while opening")
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise PermissionError("evidence file is not owner-private")
        if os.name == "nt":
            error = private_acl_error(path, fd=fd)
            if error:
                raise PermissionError(error)
        identity = metadata.st_dev, metadata.st_ino
        reset = bool(decoded and (decoded[0] != identity or decoded[1] > metadata.st_size))
        initial = decoded is None or reset
        start = max(0, metadata.st_size - MAX_READ_BYTES) if initial else decoded[1]
        discard = (initial and start > 0) or (not initial and decoded[2])
        os.lseek(fd, start, os.SEEK_SET)
        data = os.read(fd, MAX_READ_BYTES)
    finally:
        os.close(fd)
    records: deque[dict[str, Any]] = deque(maxlen=limit)
    record_count = 0
    offset = 0
    skipped = 0
    while offset < len(data):
        end = data.find(b"\n", offset)
        if end < 0:
            break
        line = data[offset:end]
        offset = end + 1
        if discard:
            discard = False
            continue
        try:
            _check_json_depth(line)
            record = json.loads(line, parse_constant=_reject_nonfinite, parse_float=_finite_float)
            if not isinstance(record, dict):
                raise ValueError("not an object")
        except (ValueError, UnicodeError, RecursionError):
            skipped += 1
            continue
        records.append(record)
        record_count += 1
        if not initial and record_count >= limit:
            break
    # A line larger than our entire window cannot be rendered. Advance safely
    # to its next newline over subsequent bounded requests, flagging the loss.
    if offset == 0 and len(data) == MAX_READ_BYTES:
        offset = len(data)
        if not discard:
            skipped += 1
        discard = True
    limited = bool(initial and (start > 0 or record_count > limit))
    return {"records": list(records), "cursor": _cursor(identity, start + offset, discard),
            "missing": False, "reset": reset, "more": start + offset < metadata.st_size and offset > 0,
            "skipped": skipped, "window_limited": limited, "bytes_read": len(data)}


def _write_token(path: Path, token: str) -> None:
    prepare_private_directory(path.parent)
    # Atomic replacement also avoids following a pre-existing token symlink.
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(token + "\n")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


class DashboardServer(HTTPServer):
    """Single bounded reader; accepted clients have a short socket timeout."""

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(3)
        return sock, address


def create_server(evidence_dir: str | Path, host: str = "127.0.0.1", port: int = 8765,
                  token_file: str | Path | None = None, *, require_token: bool = True) -> DashboardServer:
    """Create a loopback server, optionally requiring a private access token."""
    if not require_token and token_file is not None:
        raise ValueError("token_file cannot be used with token-free access")
    if host == "localhost":
        host = "127.0.0.1"
    address = ipaddress.ip_address(host)
    if address.version != 4 or not address.is_loopback:
        raise ValueError("dashboard must bind an IPv4 loopback address; use an SSH tunnel")
    if not 0 <= port <= 65535:
        raise ValueError("invalid dashboard port")
    evidence = Path(evidence_dir).absolute()
    metadata = evidence.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PermissionError("evidence directory must be a real directory")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise PermissionError("evidence directory must be owner-private")
    if os.name == "nt":
        from .windows_security import private_acl_error
        error = private_acl_error(evidence)
        if error:
            raise PermissionError(error)
    token = secrets.token_urlsafe(32) if require_token else None
    html = HTML if require_token else (HTML.replace(LOGIN_HTML, "")
                                      .replace('class="badge">Locked', 'class="badge">Connecting')
                                      .replace("Waiting for access token.", "Loading live findings."))
    javascript = JS.replace("const requireToken = true;", f"const requireToken = {str(require_token).lower()};")

    class Handler(BaseHTTPRequestHandler):
        server_version = "PacketAuditDashboard"
        sys_version = ""

        def log_message(self, _format, *_args):
            # URLs, captured values and Authorization are deliberately never logged.
            pass

        def _reply(self, status: int, body: bytes, content_type: str = "application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _error(self, status: int, message: str):
            self._reply(status, json.dumps({"error": message}).encode())

        def do_GET(self):
            authority = self.headers.get_all("Host", [])
            allowed = {f"{host}:{self.server.server_port}", f"localhost:{self.server.server_port}"}
            if len(authority) != 1 or authority[0] not in allowed:
                self._error(403, "untrusted Host")
                return
            origins = self.headers.get_all("Origin", [])
            if (len(origins) > 1 or (origins and origins[0] != "http://" + authority[0])
                    or self.headers.get("Sec-Fetch-Site") == "cross-site"):
                self._error(403, "untrusted Origin")
                return
            if len(self.path) > 2048:
                self._error(400, "request too long")
                return
            try:
                parts = urlsplit(self.path)
            except ValueError:
                self._error(400, "invalid request target")
                return
            if parts.scheme or parts.netloc or parts.fragment:
                self._error(400, "invalid request target")
                return
            assets = {"/": (html, "text/html; charset=utf-8"),
                      "/app.js": (javascript, "text/javascript; charset=utf-8"),
                      "/app.css": (CSS, "text/css; charset=utf-8")}
            if parts.path in assets and not parts.query:
                body, kind = assets[parts.path]
                self._reply(200, body.encode(), kind)
                return
            if parts.path not in ("/api/findings", "/api/operations"):
                self._error(404, "not found")
                return
            authorization = self.headers.get_all("Authorization", [])
            if require_token and (len(authorization) != 1 or len(authorization[0]) > 256
                    or not secrets.compare_digest(authorization[0].encode(), ("Bearer " + token).encode())):
                self._error(401, "authentication required")
                return
            try:
                query = parse_qs(parts.query, keep_blank_values=True, max_num_fields=3)
                if any(key not in ("cursor", "limit") or len(value) != 1 for key, value in query.items()):
                    raise ValueError("invalid query")
                limit = int(query.get("limit", ["200"])[0])
                page = read_page(evidence / FILES[parts.path.rsplit("/", 1)[-1]],
                                 query.get("cursor", [None])[0], limit)
                if parts.path == "/api/findings":
                    page["records"] = [normalize_finding(record) for record in page["records"]]
                self._reply(200, json.dumps(page, ensure_ascii=True, allow_nan=False).encode())
            except (ValueError, OverflowError):
                self._error(400, "invalid query or evidence record")
            except OSError:
                self._error(503, "evidence unavailable or permissions unsafe")

        def do_POST(self):
            self._error(405, "read-only dashboard")

        do_PUT = do_POST
        do_DELETE = do_POST
        do_PATCH = do_POST
        do_OPTIONS = do_POST

    server = DashboardServer((host, port), Handler)
    try:
        if require_token:
            _write_token(Path(token_file) if token_file else evidence / ".dashboard-token", token)
    except BaseException:
        server.server_close()
        raise
    return server


def serve_dashboard(evidence_dir: str | Path, host: str = "127.0.0.1", port: int = 8765,
                    token_file: str | Path | None = None, *, require_token: bool = True) -> None:
    with create_server(evidence_dir, host, port, token_file, require_token=require_token) as server:
        print(f"Packet Audit read-only dashboard: http://{server.server_address[0]}:{server.server_port}/", flush=True)
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass


LOGIN_HTML = '<section id="login"><label for="token">Dashboard access token</label><div class="controls"><input id="token" type="password" autocomplete="off" placeholder="Paste the private dashboard token"><button id="connect">Connect</button></div><p>Access through your SSH tunnel. The token stays in this page\'s memory only.</p></section>'

HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Packet Audit · Live evidence</title><link rel="stylesheet" href="/app.css"><script src="/app.js" defer></script></head>
<body><header><div><p class="eyebrow">PACKET AUDIT</p><h1>Live evidence</h1><p>Local, read-only view · sensitive material is unredacted</p></div><span id="connection" class="badge">Locked</span></header>
<main><section id="login"><label for="token">Dashboard access token</label><div class="controls"><input id="token" type="password" autocomplete="off" placeholder="Paste the private dashboard token"><button id="connect">Connect</button></div><p>Access through your SSH tunnel. The token stays in this page's memory only.</p></section>
<section class="metrics" aria-label="Capture health"><article><span>Capture heartbeat</span><strong id="heartbeat">Unknown</strong></article><article><span>Captured packets</span><strong id="packets">—</strong></article><article><span>Reported drops</span><strong id="drops">—</strong></article><article><span>Worker restarts</span><strong id="restarts">—</strong></article></section>
<section><div class="controls"><input id="search" type="search" aria-label="Filter findings" placeholder="Filter by IP, protocol, detector or material"><select id="detector" aria-label="Detector"><option value="">All detectors</option></select><button id="pause">Pause view</button></div><p id="summary" aria-live="polite">Waiting for access token.</p><p id="notice" class="notice">Recent bounded view: up to 500 findings and a 1 MiB read window. The JSONL files remain the full export; dashboard limits never suppress capture.</p>
<div class="table-wrap"><table><thead><tr><th>Observed time</th><th>Protocol / detector</th><th>Source IP:port</th><th>Destination IP:port</th><th>Sensitive material</th><th>Attempt / quality</th></tr></thead><tbody id="findings"></tbody></table></div></section>
<details><summary>Operational events &amp; health details</summary><pre id="operations">No operational events loaded.</pre></details>
</main><footer>Read-only • no external services • encrypted HTTPS payloads are not decrypted</footer></body></html>"""

CSS = """:root{color-scheme:dark;font:15px/1.5 system-ui,sans-serif;background:#0b1220;color:#e6edf6}*{box-sizing:border-box}body{margin:0}header{padding:30px 4vw;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #2b3b50;background:#101c2d}h1{font-size:32px;letter-spacing:-1px;margin:0}.eyebrow{color:#6edccc;font-size:12px;font-weight:800;letter-spacing:2px;margin:0}header p{margin:8px 0 0;color:#a8b8cc}main{padding:24px 4vw;max-width:1900px;margin:auto}section,details{margin-bottom:24px}.badge{padding:6px 13px;border:1px solid #486179;border-radius:30px;color:#b1c8da}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.metrics article{background:#121f31;padding:18px;border:1px solid #283e53;border-radius:10px}.metrics span{display:block;color:#9faec2;font-size:13px}.metrics strong{display:block;font-size:25px;margin-top:6px}.controls{display:flex;gap:10px;margin-top:10px}input,select,button{border:1px solid #3a526d;background:#13243a;color:#e6edf6;border-radius:6px;padding:10px 12px;font:inherit}input{flex:1;min-width:0}button{cursor:pointer;background:#185b60}input:focus,select:focus,button:focus{outline:2px solid #74e7d1;outline-offset:2px}#summary{color:#b8c8db}.notice,#login p,footer{font-size:12px;color:#9badc2}.table-wrap{overflow:auto;border:1px solid #2b3b50;border-radius:8px}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;color:#9cafc4;background:#152437;padding:13px;white-space:nowrap}td{padding:13px;border-top:1px solid #293b50;vertical-align:top;max-width:500px;overflow-wrap:anywhere}td pre{white-space:pre-wrap;margin:0;font:12px/1.6 ui-monospace,monospace;max-height:240px;overflow:auto}tbody tr:hover{background:#14243a}td small{display:block;color:#a4b7cc}#operations{font-size:12px;max-height:400px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;background:#111f31;padding:18px}footer{padding:0 4vw 24px}summary{cursor:pointer;color:#b5c6da}@media(max-width:850px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.controls{flex-wrap:wrap}header{align-items:flex-start;gap:15px}.metrics strong{font-size:21px}}"""

JS = """'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const requireToken = true;
  let token = requireToken ? new URLSearchParams(location.hash.slice(1)).get('token') || '' : '';
  if (location.hash) history.replaceState(null, '', location.pathname);
  let paused = false, rows = [], operations = [], lastHeartbeat = null, lastCaptureEvent = null;
  const cursors = {findings:null, operations:null};
  let busy = false, skipped = 0, bounded = false, more = false, missing = false;
  function text(tag, value) { const n=document.createElement(tag); n.textContent=value; return n; }
  function stamp(value) { const t=Number(value)/1e6; return t>0 ? new Date(t).toLocaleString() : 'Unknown'; }
  function material(value) { return typeof value==='string' ? value : JSON.stringify(value,null,2); }
  function retain(entries, count, maxChars) {
    let bytes=0, start=entries.length;
    while(start>0 && entries.length-start<count) {
      const size=JSON.stringify(entries[start-1]).length;
      if(bytes+size>maxChars) {bounded=true;break;}
      bytes+=size;start--;
    }
    if(start>0) bounded=true;
    return entries.slice(start);
  }
  function render() {
    const selected=$('detector').value;
    const detectors=[...new Set(rows.map(r=>String(r.detector || 'unknown')))].sort();
    $('detector').replaceChildren(new Option('All detectors',''),...detectors.map(d=>new Option(d,d)));
    if(detectors.includes(selected)) $('detector').value=selected;
    const q=$('search').value.toLowerCase();
    const visible=rows.filter(r=>(!selected || r.detector===selected) && JSON.stringify(r).toLowerCase().includes(q));
    const fragment=document.createDocumentFragment();
    for(const r of visible.slice().reverse()) {
      const tr=document.createElement('tr');
      tr.append(text('td',stamp(r.observed_timestamp_ns || r.timestamp_ns)));
      const kind=text('td',r.protocol || '—'); kind.append(text('small',r.detector || 'unknown')); tr.append(kind);
      tr.append(text('td',r.source_endpoint || 'Direction unknown'),text('td',r.destination_endpoint || 'Direction unknown'));
      const secret=document.createElement('td'); secret.append(text('pre',material(r.material)));
      const details=document.createElement('details'); details.append(text('summary','Full event'),text('pre',JSON.stringify(r,null,2))); secret.append(details); tr.append(secret);
      const quality=text('td',`#${r.attempt_ordinal ?? '—'} · ${r.completeness || 'unknown'}`);quality.append(text('small',r.confidence || '')); tr.append(quality);fragment.append(tr);
    }
    $('findings').replaceChildren(fragment);
    $('summary').textContent=`${visible.length} visible / ${rows.length} recent findings · ${paused?'view paused':'refreshing every 2 seconds'}${more?' · catching up':''}${missing?' · waiting for evidence file':''}${skipped?' · '+skipped+' malformed/oversized lines skipped':''}${bounded?' · bounded history window':''}`;
    $('operations').textContent=operations.slice(-30).reverse().map(r=>JSON.stringify(r,null,2)).join('\\n\\n') || 'No operational events loaded.';
    const age=lastHeartbeat ? Math.max(0,Date.now()-Number(lastHeartbeat.timestamp_ns)/1e6)/1000 : null;
    const ended=lastCaptureEvent && ['session_stopped','session_error','session_finished','capture_stopped'].includes(lastCaptureEvent.event);
    $('heartbeat').textContent=ended ? 'Stopped / ended' : age===null ? 'Unknown' : (age>35?'Stale · ':'')+Math.floor(age)+'s ago';
    $('packets').textContent=lastHeartbeat?.captured_packets?.toLocaleString() ?? '—';
    if(lastHeartbeat) {
      const names=['userspace_queue_drops','libpcap_dropped','interface_dropped'];
      const known=names.map(n=>lastHeartbeat[n]).filter(v=>typeof v==='number');
      $('drops').textContent=known.length ? known.reduce((a,b)=>a+b,0).toLocaleString()+(known.length<3?' (partial)':'') : 'Unknown';
      $('restarts').textContent=lastHeartbeat.worker_restarts ?? '—';
    }
  }
  async function page(kind) {
    const query=new URLSearchParams({limit:'200'}); if(cursors[kind]) query.set('cursor',cursors[kind]);
    const response=await fetch('/api/'+kind+'?'+query,{headers:requireToken?{Authorization:'Bearer '+token}:{},cache:'no-store',credentials:'omit',redirect:'error'});
    if(!response.ok) throw new Error(response.status===401?'Token missing or expired; reconnect with the current token.':'Dashboard request failed ('+response.status+').');
    const data=await response.json(); cursors[kind]=data.cursor; skipped+=data.skipped; bounded ||= data.window_limited; more ||= data.more; missing ||= data.missing;
    if(kind==='findings') rows=retain((data.reset?[]:rows).concat(data.records),500,4*1024*1024);
    else {
      if(data.reset) {operations=[]; lastHeartbeat=null; lastCaptureEvent=null;}
      operations=retain(operations.concat(data.records),100,1024*1024);
      for(const event of data.records) {
        if(event.event==='session_started') lastHeartbeat=null;
        if(event.event==='capture_heartbeat') lastHeartbeat=event;
        if(event.event==='capture_heartbeat' || String(event.event || '').startsWith('session_')) lastCaptureEvent=event;
      }
    }
  }
  async function poll() {
    if(busy || paused || (requireToken && !token)) return; busy=true; more=false; missing=false;
    try { await page('findings'); await page('operations'); $('connection').textContent='Connected · local'; if(requireToken) $('login').hidden=true; render(); }
    catch(error) {$('connection').textContent='Disconnected';$('summary').textContent=error.message;if(requireToken) $('login').hidden=false;}
    finally {busy=false;}
  }
  if(requireToken) {
    $('connect').addEventListener('click',()=>{token=$('token').value.trim();$('token').value='';poll();});
    $('token').addEventListener('keydown',event=>{if(event.key==='Enter') $('connect').click();});
  }
  $('pause').addEventListener('click',()=>{paused=!paused;$('pause').textContent=paused?'Resume view':'Pause view';render();if(!paused)poll();});
  $('search').addEventListener('input',render);$('detector').addEventListener('change',render);
  setInterval(poll,2000);poll();
})();"""
