import socket

from lib.file_store import write_json


_FORM_HTML = """<!doctype html>
<html>
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Printellect Setup</title></head>
<body style=\"font-family:sans-serif;max-width:420px;margin:24px auto;padding:0 12px\">
<h2>Printellect Wi-Fi Setup</h2>
<p><b>Device ID:</b> {device_id}</p>
<form method=\"POST\" action=\"/save\">
<label>Claim code</label><br><input name=\"claim_code\" style=\"width:100%\" /><br><br>
<label>Wi-Fi SSID</label><br><input name=\"ssid\" style=\"width:100%\" /><br><br>
<label>Wi-Fi password</label><br><input name=\"password\" type=\"password\" style=\"width:100%\" /><br><br>
<button type=\"submit\">Save and Reboot</button>
</form>
</body></html>"""


_SAVED_HTML = """<!doctype html><html><body style=\"font-family:sans-serif;padding:20px\">Saved. Rebooting...<br><br>Return to Printellect and claim your device.</body></html>"""


def _parse_form(body):
    out = {}
    for pair in body.split("&"):
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        out[_decode(key)] = _decode(value)
    return out


def _decode(value):
    value = value.replace("+", " ")
    out = ""
    i = 0
    while i < len(value):
        if value[i] == "%" and i + 2 < len(value):
            try:
                out += chr(int(value[i + 1 : i + 3], 16))
                i += 3
                continue
            except Exception:
                pass
        out += value[i]
        i += 1
    return out


def _resp(conn, code=200, content_type="text/html", body=""):
    payload = body.encode("utf-8")
    headers = [
        "HTTP/1.1 %d OK" % code,
        "Content-Type: %s" % content_type,
        "Content-Length: %d" % len(payload),
        "Connection: close",
        "",
        "",
    ]
    conn.send("\r\n".join(headers).encode("utf-8") + payload)


def run_setup_server(device_meta, wifi_path="/wifi.json"):
    device_id = device_meta.get("device_id", "unknown")
    claim_code = device_meta.get("claim_code", "")

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 80))
    sock.listen(1)

    while True:
        conn, _addr = sock.accept()
        try:
            req = conn.recv(2048).decode("utf-8")
            if "Content-Length:" in req and "\r\n\r\n" in req:
                headers, body = req.split("\r\n\r\n", 1)
                content_len = 0
                for line in headers.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        try:
                            content_len = int(line.split(":", 1)[1].strip())
                        except Exception:
                            content_len = 0
                while len(body.encode("utf-8")) < content_len:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    body += chunk.decode("utf-8")
                req = headers + "\r\n\r\n" + body
            first = req.split("\r\n", 1)[0]
            if first.startswith("GET / ") or first.startswith("GET /HTTP"):
                _resp(conn, body=_FORM_HTML.format(device_id=device_id))
                continue

            if first.startswith("POST /save"):
                body = req.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in req else ""
                form = _parse_form(body)
                if form.get("claim_code", "") != claim_code:
                    _resp(conn, code=401, body="Invalid claim code")
                    continue

                ssid = form.get("ssid", "")
                password = form.get("password", "")
                if not ssid:
                    _resp(conn, code=422, body="SSID is required")
                    continue

                write_json(wifi_path, {"ssid": ssid, "password": password})
                _resp(conn, body=_SAVED_HTML)
                return True

            _resp(conn, code=404, body="Not found")
        except Exception:
            try:
                _resp(conn, code=500, body="Setup error")
            except Exception:
                pass
        finally:
            conn.close()
