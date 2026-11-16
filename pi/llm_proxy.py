#!/usr/bin/env python3
"""
FoxHole LLM relay  ->  /usr/local/lib/foxhole/llm_proxy.py   (service: foxhole-llm-proxy)

Listens on 127.0.0.1:8001 and forwards to hailo-ollama on 127.0.0.1:8000.

Why it exists (found 2026-11-15):
  1. hailo-ollama 5.1.1 answers HTTP 500 when a chat request carries some standard
     Ollama fields in a shape it does not expect (keep_alive as text like "5m",
     a "tools" list, message content given as a list of parts, ...). Open WebUI
     sends those. The relay removes or converts them.
  2. The Hailo NPU generates ONE answer at a time. The relay makes chat requests
     wait their turn instead of colliding (Open WebUI and the triage daemon share it).

Everything else (model list, version, pull) is passed through untouched.
"""
import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN = ("127.0.0.1", 8001)
UPSTREAM = ("127.0.0.1", 8000)
UPSTREAM_TIMEOUT = 300          # seconds to wait for hailo-ollama
TURN_WAIT = 240                 # seconds a request may wait for the NPU to be free

LANGUAGE_RULE = ("Always reply in English, unless the user writes to you in a different "
                 "language, in which case reply in that language.")

_npu = threading.Lock()
PRIMITIVE = (str, int, float, bool)


def log(msg):
    print(msg, flush=True)


def sanitize(body):
    """Return (clean_body, list_of_changes) for an /api/chat or /api/generate request."""
    changes = []
    if not isinstance(body, dict):
        return body, changes

    if "keep_alive" in body and (isinstance(body["keep_alive"], bool)
                                 or not isinstance(body["keep_alive"], (int, float))):
        changes.append(f"dropped keep_alive={body['keep_alive']!r}")
        del body["keep_alive"]
    for key in ("tools", "tool_choice", "metadata"):
        if key in body:
            changes.append(f"dropped {key}")
            del body[key]
    if "format" in body and not isinstance(body["format"], str):
        changes.append("dropped non-text format")
        del body["format"]
    if "options" in body:
        opts = body["options"]
        if not isinstance(opts, dict):
            changes.append("dropped non-object options")
            del body["options"]
        else:
            for k in list(opts):
                v = opts[k]
                ok = isinstance(v, PRIMITIVE) or (k == "stop" and isinstance(v, list)
                                                  and all(isinstance(s, str) for s in v))
                if not ok:
                    changes.append(f"dropped options.{k}")
                    del opts[k]

    msgs = body.get("messages")
    if isinstance(msgs, list):
        clean = []
        for m in msgs:
            if not isinstance(m, dict):
                continue
            role = m.get("role")
            if role not in ("system", "user", "assistant"):
                changes.append(f"dropped message with role {role!r}")
                continue
            content = m.get("content")
            if isinstance(content, list):          # OpenAI-style parts -> plain text
                content = "\n".join(p.get("text", "") for p in content
                                    if isinstance(p, dict) and p.get("type") == "text")
                changes.append("flattened list content")
            elif content is None:
                content = ""
            elif not isinstance(content, str):
                content = str(content)
            extra = [k for k in m if k not in ("role", "content")]
            if extra:
                changes.append("dropped message fields " + ",".join(sorted(extra)))
            clean.append({"role": role, "content": content})
        # Qwen is a Chinese-English model and sometimes answers short English prompts in
        # Chinese. Pin the language with a system instruction on every chat.
        if clean and clean[0]["role"] == "system":
            if LANGUAGE_RULE not in clean[0]["content"]:
                clean[0]["content"] = (LANGUAGE_RULE + " " + clean[0]["content"]).strip()
        else:
            clean.insert(0, {"role": "system", "content": "You are a helpful assistant. " + LANGUAGE_RULE})
        body["messages"] = clean
    return body, changes


class Relay(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"                 # body ends when the connection closes

    def log_message(self, fmt, *args):            # quiet: no per-request access log
        pass

    def _forward(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        is_chat = self.command == "POST" and self.path.split("?")[0] in ("/api/chat", "/api/generate")

        if is_chat and raw:
            try:
                body, changes = sanitize(json.loads(raw))
                raw = json.dumps(body).encode()
                if changes:
                    log(f"[relay] {self.path}: " + "; ".join(sorted(set(changes))))
            except ValueError:
                pass                               # not JSON - let hailo-ollama answer

        got_turn = False
        if is_chat:
            got_turn = _npu.acquire(timeout=TURN_WAIT)
            if not got_turn:
                log("[relay] NPU busy for too long - request refused (503)")
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"The AI chip is busy with another request. Try again in a minute."}')
                return
        conn = None
        try:
            conn = http.client.HTTPConnection(*UPSTREAM, timeout=UPSTREAM_TIMEOUT)
            headers = {"Content-Type": self.headers.get("Content-Type", "application/json")}
            if raw:
                headers["Content-Length"] = str(len(raw))
            conn.request(self.command, self.path, body=raw or None, headers=headers)
            resp = conn.getresponse()
            if resp.status >= 500:
                log(f"[relay] hailo-ollama answered {resp.status} for {self.command} {self.path}")
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.getheader("Content-Type") or "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            while True:
                chunk = resp.read1(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass                                   # the client went away mid-answer
        except Exception as e:
            log(f"[relay] error talking to hailo-ollama: {e!r}")
            try:
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"LLM server unreachable: {e}"}).encode())
            except Exception:
                pass
        finally:
            if conn:
                conn.close()
            if got_turn:
                _npu.release()

    do_GET = do_POST = do_DELETE = do_HEAD = do_PUT = _forward


if __name__ == "__main__":
    log(f"[relay] listening on {LISTEN[0]}:{LISTEN[1]} -> hailo-ollama {UPSTREAM[0]}:{UPSTREAM[1]}")
    ThreadingHTTPServer(LISTEN, Relay).serve_forever()
