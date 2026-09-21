#!/bin/sh
# Runs inside the client container. Each request is its own TCP connection
# (Connection: close) so each becomes its own flow with one host and one URI.
# Also a few non-HTTP flows so the capture carries other application ids.
ROUNDS=${1:-20}
HOSTS="www.example.com api.example.com cdn.example.net login.example.org static.example.com"
URIS="/ /api/v1 /static/app.js /api/login"
i=0
while [ $i -lt $ROUNDS ]; do
  for h in $HOSTS; do
    for u in $URIS; do
      curl -s -o /dev/null -m 3 -H "Host: $h" -H "Connection: close" "http://10.10.2.10$u"
    done
  done
  # non-HTTP: DNS query (no server, still a flow), SSH connect attempt, ICMP
  dig +time=1 +tries=1 @10.10.2.10 example.com >/dev/null 2>&1
  nc -z -w1 10.10.2.10 22 >/dev/null 2>&1
  ping -c1 -W1 10.10.2.10 >/dev/null 2>&1
  i=$((i+1))
done
echo "traffic done: $ROUNDS rounds"
