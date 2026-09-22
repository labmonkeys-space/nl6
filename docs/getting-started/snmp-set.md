# Enable SNMP SET

nl6 serves `SetRequest` at SNMPv1, v2c and v3, on one writable object:
`ifAdminStatus`. That is enough to shut and unshut a simulated interface from a
collector and watch the link telemetry that follows.

:::caution[Writes are off by default]

A stock fleet answers **no** `SET` at any version. `snmpset` against it reports
`Timeout: No Response`, not an SNMP error, because a refused write is discarded
rather than answered. That is what real hardware does with a community it does
not accept.

The device logs the reason once. If `snmpset` times out while `snmpget` works,
that log line is the answer.

:::

Two separate gates, one per protocol family. A v3 message carries no community
and a v1/v2c message carries no security level, so you configure whichever
applies to the version you poll with.

| Version | Gate | Default |
|---------|------|---------|
| v1, v2c | a write community | empty, so no write is admitted |
| v3 | a minimum security level | `authNoPriv` |

## Whole fleet, SNMPv1 and v2c

Start the simulator with a write community. Any string works. It is separate
from the read community, which nl6 never checks.

```bash
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 5 \
  -snmp-write-community s3cret
```

Every device in that fleet now accepts a `SET` carrying `s3cret`:

```bash
snmpset -v2c -c s3cret 192.168.100.1 1.3.6.1.2.1.2.2.1.7.2 i 2
```

Reads are unaffected and still need no community match, so `snmpget -c public`
keeps working. The asymmetry is deliberate: a `SET` changes state, a poll does
not.

## Whole fleet, SNMPv3

Add an engine ID to turn SNMPv3 on. The shipped defaults already reach the
default minimum, so nothing else is needed:

```bash
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 5 \
  -snmpv3-engine-id 800000090300AABBCCDD
```

`-snmpv3-auth` defaults to `md5`, which reaches `authNoPriv`, and the minimum
for a `SET` is `authNoPriv`. The user and password both default to `simadmin`:

```bash
snmpset -v3 -l authNoPriv -u simadmin -a MD5 -A simadmin \
  192.168.100.1 1.3.6.1.2.1.2.2.1.7.2 i 2
```

To require encryption as well, raise the minimum and give the fleet a privacy
protocol. Both are needed: a minimum the fleet cannot reach admits nothing.

```bash
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 5 \
  -snmpv3-engine-id 800000090300AABBCCDD \
  -snmpv3-auth sha1 -snmpv3-priv aes128 \
  -snmp-set-min-security-level priv

snmpset -v3 -l authPriv -u simadmin -a SHA -A simadmin -x AES -X simadmin \
  192.168.100.1 1.3.6.1.2.1.2.2.1.7.2 i 2
```

Running with `-snmpv3-auth none` leaves no reachable level at or above the
default minimum, so no v3 `SET` is admitted at all. The startup log says so in
the line that begins `SNMP write admission`.

## One device at a time

Devices created over the REST API carry their own admission settings.

```bash
curl -X POST http://localhost:8080/api/v1/devices \
  -H "Content-Type: application/json" \
  -d '{
    "start_ip": "192.168.200.1",
    "device_count": 1,
    "netmask": "16",
    "write_community": "device-secret",
    "snmpv3": {
      "enabled": true,
      "engine_id": "800000090300AABBCCDD",
      "username": "simadmin",
      "password": "simadmin",
      "auth_protocol": 1,
      "set_min_security_level": "auth"
    }
  }'
```

`auth_protocol` is `0` for none, `1` for MD5, `2` for SHA1.
`set_min_security_level` takes `none`, `auth` or `priv`.

Either version then works against that device alone:

```bash
snmpset -v2c -c device-secret 192.168.200.1 1.3.6.1.2.1.2.2.1.7.2 i 2

snmpset -v3 -l authNoPriv -u simadmin -a MD5 -A simadmin \
  192.168.200.1 1.3.6.1.2.1.2.2.1.7.2 i 2
```

:::warning[REST devices do not inherit the CLI flags]

A device created over REST takes its admission from the request body alone.
Omit `write_community` there and that device refuses every v1/v2c `SET`, even
on a fleet started with `-snmp-write-community`. The startup log describes the
auto-start batch only.

The write community is write-only. `GET /api/v1/devices` never echoes it, so
there is no way to read back what a device was configured with.

:::

## Disable a network interface

`ifAdminStatus.<N>` is `1.3.6.1.2.1.2.2.1.7.<N>`, where `<N>` is the ifIndex.
The values are `up(1)`, `down(2)` and `testing(3)`. Walk the column first to
see which interfaces a device has:

```bash
snmpwalk -v2c -c public 192.168.100.1 1.3.6.1.2.1.2.2.1.7
```

### With SNMPv1 or v2c

```bash
# Shut interface 2
snmpset -v2c -c s3cret 192.168.100.1 1.3.6.1.2.1.2.2.1.7.2 i 2

# Read both columns back
snmpget -v2c -c public 192.168.100.1 \
  1.3.6.1.2.1.2.2.1.7.2 1.3.6.1.2.1.2.2.1.8.2
```

SNMPv1 works the same way with `-v1`, but reports fewer distinct errors. See
[when a write is refused](#when-a-write-is-refused).

### With SNMPv3

```bash
# Shut interface 2
snmpset -v3 -l authNoPriv -u simadmin -a MD5 -A simadmin \
  192.168.100.1 1.3.6.1.2.1.2.2.1.7.2 i 2

# Read both columns back
snmpget -v3 -l authNoPriv -u simadmin -a MD5 -A simadmin 192.168.100.1 \
  1.3.6.1.2.1.2.2.1.7.2 1.3.6.1.2.1.2.2.1.8.2
```

### What the device does with it

Shutting an interface moves `ifOperStatus` too, stamps `ifLastChange`, pushes an
update to any gNMI `ON_CHANGE` subscriber, and fires the device's link-down trap
and syslog message. Unshutting it fires the link-up pair.

:::note[Re-enabling does not always bring the interface back up]

`ifOperStatus` is derived from `ifAdminStatus` and a modelled link state, and
the rule is asymmetric:

| `SET ifAdminStatus` | `ifOperStatus` becomes |
|---|---|
| `down(2)` | `down(2)`, forced |
| `testing(3)` | `testing(3)`, forced |
| `up(1)` | whatever the link state is, released rather than forced |

So on an interface whose link is down, a `SET` of `up(1)` succeeds and
`ifOperStatus` still reads `2`. That is not a rejected write. `ifAdminStatus`
reads back `1`, and an administrative bounce does not repair a simulated cable
fault. A fleet started with `-if-scenario 3` behaves this way on every
interface.

:::

## When a write is refused

| Symptom | Cause |
|---------|-------|
| `Timeout: No Response` under v1 or v2c | Wrong write community, or none configured. Check the `SNMP write admission` line in the startup log. |
| `Unsupported security level` under v3 | The request is below the minimum. Raise the request's level, or lower `-snmp-set-min-security-level`. |
| `notWritable` | The OID is not `ifAdminStatus`. It is the only writable object. |
| `wrongValue` | The value is outside `up(1)`, `down(2)`, `testing(3)`. |
| `wrongType` | The value is not an INTEGER. |
| `noCreation` | The ifIndex does not exist on that device, or the name has the wrong number of sub-identifiers. |

SNMPv1 has a smaller set of error values, so those four collapse under `-v1`:
`wrongValue` and `wrongType` both report `badValue`, while `notWritable` and
`noCreation` both report `noSuchName`.

To restore the behaviour of earlier releases, where any manager that could
reach the port could write, start with
`-snmp-write-community public -snmp-set-min-security-level none`.

## Next steps

- [SNMP reference](../reference/snmp.md) for the full `SetRequest` error ladder
  and the write-admission rules.
- [CLI flags](../reference/cli-flags.md) for every flag used above.
- [Web API](../reference/web-api.md) for the REST control plane, including
  `POST /api/v1/devices/{ip}/interfaces/{ifIndex}/admin-status`, which does the
  same job over HTTP.
