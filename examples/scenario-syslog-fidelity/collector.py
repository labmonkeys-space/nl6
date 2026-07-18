#!/usr/bin/env python3
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# collector.py — a minimal UDP syslog sink that counts received datagrams and
# exposes the count over HTTP, so the run script can diff nl6's reported
# `sent` against the wire-observed `received`. Stdlib only (runs on a stock
# python:3-alpine image, no pip install).
#
#   UDP  :514        every datagram increments a counter
#   GET  /count      -> {"received": <N>}
#   POST /reset      -> zeroes the counter (called after arm, before start,
#                       so only in-window scenario traffic is counted)

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

_count = 0
_lock = threading.Lock()


def _udp_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # A generous receive buffer so a burst of small syslog datagrams is not
    # dropped before the loop drains them.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind(("0.0.0.0", 514))
    global _count
    while True:
        sock.recvfrom(65535)
        with _lock:
            _count += 1


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/count":
            with _lock:
                self._send(200, {"received": _count})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        global _count
        if self.path == "/reset":
            with _lock:
                _count = 0
            self._send(200, {"received": 0})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *args):  # silence per-request logging
        pass


def main():
    threading.Thread(target=_udp_loop, daemon=True).start()
    print("collector: UDP :514 (syslog), HTTP :9000 (/count, /reset)", flush=True)
    HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()


if __name__ == "__main__":
    main()
