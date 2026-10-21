#!/usr/bin/env bash
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: Apache-2.0
#
# Checks for the nl6 role. Run from the repo root:
#   bash deploy/ansible/tests/check-role.sh
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT" || exit 1
VENV="$ROOT/build/ansible-venv"
ROLE="$ROOT/deploy/ansible/roles/nl6"
TASKS="$ROLE/tasks/main.yml"
PKG="$ROLE/tasks/package.yml"
COLL="$ROOT/build/ansible-collections"

if [ ! -x "$VENV/bin/ansible-playbook" ]; then
  echo "FAIL setup: $VENV missing, run 'make check-ansible' first" >&2
  exit 1
fi
export PATH="$VENV/bin:$PATH"
export ANSIBLE_COLLECTIONS_PATH="$COLL"
export ANSIBLE_ROLES_PATH="$ROOT/deploy/ansible/roles"
export ANSIBLE_LOCALHOST_WARNING=False
export ANSIBLE_INVENTORY_UNPARSED_WARNING=False

ansible-galaxy collection install -p "$COLL" -r deploy/ansible/requirements.yml >/dev/null 2>&1 \
  || echo "WARN: could not install collection requirements" >&2

fail=0
check() { # name, command...
  local name=$1
  shift
  if out=$("$@" 2>&1); then
    echo "PASS $name"
  else
    echo "FAIL $name"
    echo "$out" | sed 's/^/     /'
    fail=1
  fi
}

t_syntax() {
  [ -d "$ROLE" ] || { echo "role not found: $ROLE"; return 1; }
  ansible-playbook --syntax-check -i localhost, deploy/ansible/tests/playbook.yml
}
t_api_wait() {
  grep -q '/api/v1/version' "$TASKS" && grep -q 'ansible.builtin.uri' "$TASKS" \
    && grep -q 'retries: 12' "$TASKS" && grep -q 'delay: 5' "$TASKS"
}
t_iface() {
  grep -q 'ansible.builtin.assert' "$TASKS" \
    && grep -q 'nl6_net_interface | length > 0' "$TASKS" \
    && grep -q 'nl6_net_interface in ansible_facts.interfaces' "$TASKS"
}
t_sysctl() {
  grep -q 'ansible.posix.sysctl' "$TASKS" \
    && grep -q 'net.ipv4.ip_forward' "$TASKS" \
    && grep -q 'net.ipv4.conf.all.rp_filter' "$TASKS" \
    && grep -q 'net.ipv4.conf.{{ nl6_net_interface }}.rp_filter' "$TASKS"
}
t_version_warn() {
  grep -q 'dpkg-query' "$TASKS" && grep -q 'ansible.builtin.debug' "$TASKS" \
    && grep -q 'WARNING' "$TASKS" && grep -q 'nl6_installed.stdout != nl6_version' "$TASKS" \
    && grep -q "nl6_unit.status.ActiveState | default('') == 'active'" "$TASKS"
}
t_forward_policy() {
  grep -q 'iptables -S FORWARD' "$TASKS" && grep -q -- "-P FORWARD ACCEPT" "$TASKS" \
    && grep -q 'changed_when: false' "$TASKS"
}
t_checksum() {
  grep -q 'ansible.builtin.get_url' "$TASKS" && grep -q 'checksum: "{{ nl6_pkg_checksum }}"' "$TASKS" \
    && grep -q "'sha256:https://" "$PKG" && grep -q 'sha256:\[0-9a-fA-F\]{64}' "$PKG"
}
t_el10() {
  grep -q "rpm -q --queryformat '%{VERSION}' nl6" "$TASKS" && grep -q 'ansible.builtin.dnf' "$TASKS" \
    && grep -q 'disable_gpg_check: true' "$TASKS" && grep -q "nl6_pkg_format == 'rpm'" "$TASKS"
}
t_firewalld() {
  grep -q 'name: firewalld.service' "$TASKS" && grep -q 'WARNING: firewalld is active' "$TASKS" \
    && grep -q "nl6_firewalld.status.ActiveState | default('') == 'active'" "$TASKS"
}
# Run the role's package selection with the facts of each supported platform.
t_package() {
  local dest="$ROOT/build/nl6.package.selected" ver base got case facts want
  ver=$(sed -nE 's/^nl6_version:[[:space:]]*"?([^"[:space:]]+)"?.*/\1/p' "$ROLE/defaults/main.yml")
  base="https://github.com/labmonkeys-space/nl6/releases/download/v$ver"
  mkdir -p "$ROOT/build"
  for case in \
    "Debian 24 x86_64|deb $base/nl6_${ver}_amd64.deb" \
    "Debian 24 aarch64|deb $base/nl6_${ver}_arm64.deb" \
    "RedHat 10 x86_64|rpm $base/nl6-${ver}-1.x86_64.rpm" \
    "RedHat 10 aarch64|rpm $base/nl6-${ver}-1.aarch64.rpm"; do
    read -r fam major arch <<<"${case%%|*}"
    want=${case#*|}
    facts=$(printf '{"ansible_facts":{"os_family":"%s","distribution":"%s","distribution_major_version":"%s","architecture":"%s"}}' "$fam" "$fam" "$major" "$arch")
    rm -f "$dest"
    ansible-playbook -e "render_dest=$dest" -e "$facts" deploy/ansible/tests/package.yml >/dev/null \
      || { echo "$fam $major $arch: play failed"; return 1; }
    got=$(cat "$dest")
    [ "$got" = "$want" ] || { echo "$fam $major $arch: got '$got', want '$want'"; return 1; }
  done
  facts='{"ansible_facts":{"os_family":"RedHat","distribution":"Rocky","distribution_major_version":"9","architecture":"x86_64"}}'
  out=$(ansible-playbook -e "render_dest=$dest" -e "$facts" deploy/ansible/tests/package.yml 2>&1) \
    && { echo "RedHat 9 was accepted"; return 1; }
  echo "$out" | grep -q 'Unsupported platform' || { echo "RedHat 9 failed for another reason:"; echo "$out" | tail -5; return 1; }
}
t_extra_args() {
  grep -q 'nl6_extra_args is not string' "$TASKS" || return 1
  # Evaluate the same conditions the role asserts on a string and on a list.
  ansible localhost -c local -m ansible.builtin.assert \
    -a '{"that": ["nl6_extra_args is sequence", "nl6_extra_args is not string"]}' \
    -e '{"nl6_extra_args":["-auto-count","5"]}' >/dev/null 2>&1 \
    || { echo "list was rejected"; return 1; }
  if ansible localhost -c local -m ansible.builtin.assert \
    -a '{"that": ["nl6_extra_args is sequence", "nl6_extra_args is not string"]}' \
    -e '{"nl6_extra_args":"-auto-count 5"}' >/dev/null 2>&1; then
    echo "string was accepted"
    return 1
  fi
}
t_render() {
  local dest="$ROOT/build/nl6.conf.rendered"
  mkdir -p "$ROOT/build"
  ansible-playbook -e "render_dest=$dest" \
    -e '{"nl6_extra_args": ["-auto-count", "5"], "nl6_pyroscope_url": ""}' \
    deploy/ansible/tests/render.yml >/dev/null || return 1
  [ "$(cat "$dest")" = 'NL6_OPTS="-port 8080 -gnmi-tls=true -auto-count 5"' ] \
    || { echo "unexpected content:"; cat "$dest"; return 1; }
}
# Evaluate the role's own whitespace assert condition against lists.
t_no_whitespace() {
  local cond bad args
  cond=$(sed -n "s/^ *- \(nl6_extra_args | map('string') | select('search'.*\)$/\1/p" "$TASKS")
  [ -n "$cond" ] || { echo "assert condition not found"; return 1; }
  run_assert() { # extra-vars JSON
    local a
    a=$(python3 -I -c 'import json,sys; print(json.dumps({"that":[sys.argv[1]]}))' "$cond")
    ansible localhost -c local -m ansible.builtin.assert -a "$a" -e "$1" >/dev/null 2>&1
  }
  run_assert '{"nl6_extra_args":["-auto-count","5"]}' || { echo "clean list was rejected"; return 1; }
  for bad in 'a b' 'a"b' 'a$b' 'a%b' "a	b"; do
    args=$(python3 -I -c 'import json,sys; print(json.dumps({"nl6_extra_args":[sys.argv[1]]}))' "$bad")
    if run_assert "$args"; then
      echo "element '$bad' was accepted"
      return 1
    fi
  done
}

check "syntax" t_syntax
check "api wait present" t_api_wait
check "interface assert" t_iface
check "sysctl present" t_sysctl
check "version change warns" t_version_warn
check "package checksum" t_checksum
check "EL 10 rpm install" t_el10
check "firewalld warning" t_firewalld
check "package selection per platform" t_package
check "forward policy assert" t_forward_policy
check "extra args list assert" t_extra_args
check "extra args no whitespace assert" t_no_whitespace
check "nl6.conf render" t_render

exit "$fail"
