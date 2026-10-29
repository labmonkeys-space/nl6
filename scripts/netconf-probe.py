#!/usr/bin/env python3
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# netconf-probe.py drives one IOS XE NETCONF target through a fixed script of
# establish-subscription requests, session RPCs and interface state toggles.
# It prints one JSON line per reply and per notification:
#
#   {"phase": "...", "step": "...", "kind": "reply|notification|closed|timeout", "xml": "..."}
#
# "xml" is a canonical form: namespaces resolved, one xmlns per namespace
# change, attributes sorted, whitespace-only text dropped. Values are NOT
# normalised here. The differential test (netconf_interop_test.go) does that.
#
# Toggles: the probe prints {"kind": "toggle", "step": "<action>"} and waits
# for one line "ok" on stdin. The caller flips the state, then answers. The
# actions are link-down, link-up, admin-down and admin-up.
#
# The probe talks raw RFC 6242 end-of-message framing over paramiko so it can
# send requests ncclient would refuse to build (no message-id, an unknown
# namespace). Run it with:
#
#   uv run -q --with ncclient==0.7.1 python -I scripts/netconf-probe.py \
#       --host "$NL6_NETCONF_REF" --user "$NL6_NETCONF_REF_USER" --password "$NL6_NETCONF_REF_PASSWORD" \
#       --interface GigabitEthernet2 [--settle 30] run
#
# The "admin up|down" command sets or removes native-config shutdown on the
# interface instead (IOS XE only, used for the reference device).
import argparse
import json
import re
import socket
import sys
import time
import xml.etree.ElementTree as ET

import paramiko

EOM = b"]]>]]>"
BASE = "urn:ietf:params:xml:ns:netconf:base:1.0"
EN = "urn:ietf:params:xml:ns:yang:ietf-event-notifications"
SN = "urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"
YP = "urn:ietf:params:xml:ns:yang:ietf-yang-push"
XE = "/interfaces-ios-xe-oper:interfaces"


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def canon(text):
    root = ET.fromstring(text.encode())

    def ser(e, parent_ns):
        ns, local = ("", e.tag)
        if e.tag.startswith("{"):
            ns, local = e.tag[1:].split("}", 1)
        out = "<" + local
        if ns != parent_ns:
            out += ' xmlns="' + ns + '"'
        for k in sorted(e.attrib):
            out += " " + k + '="' + esc(e.attrib[k]) + '"'
        out += ">"
        if e.text and e.text.strip():
            out += esc(e.text.strip())
        for c in e:
            out += ser(c, ns)
        return out + "</" + local + ">"

    return ser(root, None)


class Session:
    def __init__(self, a):
        sock = socket.create_connection((a.host, a.port), timeout=30)
        self.t = paramiko.Transport(sock)
        self.t.connect(username=a.user, password=a.password)
        self.ch = self.t.open_session()
        self.ch.invoke_subsystem("netconf")
        self.buf = b""
        self.mid = 0
        hello = self.read(30)
        if hello is None:
            raise SystemExit("no server hello")
        self.session_id = re.search(r"<session-id>(\d+)<", hello).group(1)
        self.send('<?xml version="1.0" encoding="UTF-8"?><hello xmlns="' + BASE + '"><capabilities>'
                  "<capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>")

    def send(self, s):
        self.ch.sendall(s.encode() + EOM)

    def read(self, timeout):
        """One message, or None after timeout. EOFError when the peer closed."""
        deadline = time.time() + timeout
        while EOM not in self.buf:
            left = deadline - time.time()
            if left <= 0:
                return None
            self.ch.settimeout(left)
            try:
                d = self.ch.recv(65536)
            except socket.timeout:
                return None
            if not d:
                raise EOFError
            self.buf += d
        msg, self.buf = self.buf.split(EOM, 1)
        return msg.decode()

    def closed_within(self, timeout):
        try:
            while True:
                if self.read(timeout) is None:
                    return False
        except (EOFError, OSError):
            return True

    def close(self):
        """Ends the session with close-session before dropping the
        transport. The c8000v frees a subscription of a session that just
        disappears only after a long delay, and its subscription pool is
        device-wide."""
        try:
            self.mid += 1
            self.send('<rpc xmlns="' + BASE + '" message-id="%d"><close-session/></rpc>' % self.mid)
            self.closed_within(5)
        except Exception:
            pass
        try:
            self.t.close()
        except Exception:
            pass


class Probe:
    def __init__(self, a):
        self.a = a
        self.phase = ""

    def emit(self, step, kind, xml=""):
        print(json.dumps({"phase": self.phase, "step": step, "kind": kind,
                          "xml": canon(xml) if xml else ""}), flush=True)

    def rpc(self, s, step, body, with_id=True, quiet=None):
        """Send body, emit the reply, then emit the notifications that follow
        until the session is quiet. Notifications that arrive before the
        reply are emitted in arrival order too."""
        quiet = self.a.quiet if quiet is None else quiet
        s.mid += 1
        attr = ' message-id="%d"' % s.mid if with_id else ""
        s.send('<rpc xmlns="' + BASE + '"' + attr + ">" + body + "</rpc>")
        reply = None
        deadline = time.time() + 30
        try:
            while reply is None:
                m = s.read(max(0.1, deadline - time.time()))
                if m is None:
                    self.emit(step, "timeout")
                    return None
                if "<rpc-reply" in m[:200]:
                    reply = m
                    self.emit(step, "reply", m)
                else:
                    self.emit(step, "notification", m)
            self.collect(s, step, quiet)
        except (EOFError, OSError):
            self.emit(step, "closed")
        return reply

    def collect(self, s, step, quiet):
        while True:
            m = s.read(quiet)
            if m is None:
                return
            self.emit(step, "notification", m)

    def window(self, s, step, seconds):
        end = time.time() + seconds
        while time.time() < end:
            m = s.read(end - time.time())
            if m is not None:
                self.emit(step, "notification", m)

    def toggle(self, action):
        print(json.dumps({"phase": self.phase, "step": action, "kind": "toggle", "xml": ""}), flush=True)
        if sys.stdin.readline().strip() != "ok":
            raise SystemExit("toggle %s not confirmed" % action)

    # ---- request builders

    def xp(self, leaf="", name=None):
        name = self.a.interface if name is None else name
        x = XE + "/interface[name='" + name + "']"
        return x + "/" + leaf if leaf else x

    @staticmethod
    def sub(xpath, stream=True, damp="0", period=None, ns=EN):
        b = '<establish-subscription xmlns="' + ns + '" xmlns:yp="' + YP + '">'
        if stream:
            b += "<stream>yp:yang-push</stream>"
        b += "<yp:xpath-filter>" + esc(xpath) + "</yp:xpath-filter>"
        if damp is not None:
            b += "<yp:dampening-period>" + damp + "</yp:dampening-period>"
        if period is not None:
            b += "<yp:period>" + period + "</yp:period>"
        return b + "</establish-subscription>"

    @staticmethod
    def sub_id(reply):
        m = re.search(r"<subscription-id[^>]*>(\d+)<", reply or "")
        return m.group(1) if m else None

    @staticmethod
    def delete(sid):
        return '<delete-subscription xmlns="' + EN + '"><subscription-id>' + sid + "</subscription-id></delete-subscription>"

    # ---- phases

    def run(self):
        a = self.a
        self.phase = "establish"
        s = Session(a)
        oper = self.rpc(s, "sub-oper", self.sub(self.xp("oper-status")))
        self.rpc(s, "sub-admin", self.sub(self.xp("admin-status")))
        self.rpc(s, "sub-row", self.sub(self.xp()))
        self.rpc(s, "sub-nonexistent-interface", self.sub(self.xp("oper-status", "GigabitEthernet9/9/99")))
        sid = self.sub_id(oper) or "0"
        self.rpc(s, "delete-known", self.delete(sid))
        self.rpc(s, "delete-again", self.delete(sid))
        self.rpc(s, "delete-unknown", self.delete("12345"))
        self.rpc(s, "sub-container", self.sub(XE))
        name = a.interface
        for leaf in ("oper-status", "admin-status", ""):
            x = "/if:interfaces-state/interface[name='" + name + "']" + ("/" + leaf if leaf else "")
            self.rpc(s, "sub-ietf-interfaces-state-" + (leaf or "row"), self.sub(x))
        self.rpc(s, "sub-ietf-interfaces-nmda", self.sub("/if:interfaces/interface/oper-status"))
        self.rpc(s, "sub-unknown-module", self.sub("/no-such-module:foo/bar"))
        self.rpc(s, "sub-malformed-xpath", self.sub(XE + "/interface[name='Gi"))
        self.rpc(s, "sub-no-stream", self.sub(XE + "/interface/oper-status", stream=False))
        self.rpc(s, "sub-no-dampening", self.sub(XE + "/interface/oper-status", damp=None))
        self.rpc(s, "sub-dampening-nonzero", self.sub(self.xp("oper-status"), damp="5"))
        self.rpc(s, "sub-rfc8639-namespace", self.sub(self.xp("oper-status"), ns=SN))
        self.rpc(s, "close-session", "<close-session/>", quiet=0)
        self.emit("close-session", "closed" if s.closed_within(5) else "timeout")

        # Requests the device accepts and nl6 refuses run on their own
        # sessions so what follows the acceptance cannot leak into a row
        # that is compared.
        self.phase = "period"
        s = Session(a)
        self.rpc(s, "sub-period", self.sub(self.xp("oper-status"), damp=None, period="1000"))
        s.close()
        self.phase = "create-subscription"
        s = Session(a)
        self.rpc(s, "create-subscription", '<create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">'
                 "<stream>NETCONF</stream></create-subscription>")
        s.close()

        self.phase = "keyless"
        s = Session(a)
        self.rpc(s, "sub-keyless-oper", self.sub(XE + "/interface/oper-status"))
        self.rpc(s, "sub-keyless-admin", self.sub(XE + "/interface/admin-status"))
        self.rpc(s, "sub-keyless-row", self.sub(XE + "/interface"))
        s.close()

        self.phase = "kill"
        victim, killer = Session(a), Session(a)
        self.rpc(killer, "kill-other", '<kill-session><session-id>' + victim.session_id + "</session-id></kill-session>")
        self.emit("kill-other", "closed" if victim.closed_within(5) else "timeout")
        self.rpc(killer, "kill-own", '<kill-session><session-id>' + killer.session_id + "</session-id></kill-session>")
        victim.close()
        killer.close()

        self.phase = "missing-message-id"
        s = Session(a)
        self.rpc(s, "sub-without-message-id", self.sub(self.xp("oper-status")), with_id=False)
        s.close()

        # State changes. Creation order oper, admin, row: the device pushes
        # in reverse creation order, so row first.
        self.phase = "events"
        s = Session(a)
        self.rpc(s, "sub-oper", self.sub(self.xp("oper-status")))
        self.rpc(s, "sub-admin", self.sub(self.xp("admin-status")))
        self.rpc(s, "sub-row", self.sub(self.xp()))
        for action in ("link-down", "link-up", "admin-down", "admin-up"):
            self.toggle(action)
            self.window(s, action, a.settle)
        s.close()


def admin(a, down):
    kind, num = re.match(r"([A-Za-z]+)(.*)", a.interface).groups()
    op = "create" if down else "remove"
    cfg = ('<config><native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native"><interface><' + kind + "><name>" + num +
           '</name><shutdown xmlns:nc="' + BASE + '" nc:operation="' + op + '"/></' + kind + "></interface></native></config>")
    s = Session(a)
    s.send('<rpc xmlns="' + BASE + '" message-id="1"><edit-config><target><running/></target>' + cfg + "</edit-config></rpc>")
    while True:
        m = s.read(30)
        if m is None:
            raise SystemExit("edit-config: no reply")
        if "<rpc-reply" in m[:200]:
            break
    s.close()
    # "remove" of an absent shutdown is data-missing: the interface is
    # already up, which is the state asked for.
    if "<ok/>" not in m and not (not down and "data-missing" in m):
        raise SystemExit("edit-config failed: " + m)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=830)
    p.add_argument("--user", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--interface", required=True)
    p.add_argument("--quiet", type=float, default=2.0, help="seconds without a message that end a reply row")
    p.add_argument("--settle", type=float, default=30.0, help="seconds to collect after each toggle")
    p.add_argument("command", choices=["run", "admin"])
    p.add_argument("state", nargs="?", choices=["up", "down"])
    a = p.parse_args()
    if a.command == "admin":
        if a.state is None:
            p.error("admin needs up or down")
        admin(a, a.state == "down")
        return
    Probe(a).run()


if __name__ == "__main__":
    main()
