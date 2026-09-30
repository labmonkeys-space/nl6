# Prometheus service discovery

nl6 publishes the running fleet as a Prometheus [HTTP service discovery](https://prometheus.io/docs/prometheus/latest/http_sd/) endpoint.
Prometheus picks up devices as they are created and drops them when they are deleted or stopped.
There is no static target file to regenerate.

The endpoint is always on.
It needs no flag.

```
GET /api/v1/prometheus/sd
```

## What the targets are

nl6 devices serve no `/metrics` endpoint.
Each target is a device's **SNMP agent**, meant for [snmp_exporter](https://github.com/prometheus/snmp_exporter).
Prometheus scrapes snmp_exporter and passes the device address as the `target` parameter.

The body is a JSON array with one target group per running device, sorted by IP:

```json
[
  {
    "targets": ["10.42.0.1"],
    "labels": {
      "__meta_nl6_resource": "cisco_ios",
      "__meta_nl6_device_type": "Cisco IOS",
      "__meta_nl6_sys_name": "core-rtr-01",
      "__meta_nl6_snmp_port": "161"
    }
  }
]
```

| Field | Meaning |
|-------|---------|
| `targets` | The device IP. On a port other than 161 it is `ip:port`. snmp_exporter accepts both forms. |
| `__meta_nl6_resource` | The device's resource file, lower-cased and without `.json` (for example `cisco_ios`). Add `.json` to use it in `POST /api/v1/devices`. Devices created with no resource file, such as the `-auto-start-ip` batch, report the startup default profile they serve (`asr9k`). Use it to pick an snmp_exporter module. |
| `__meta_nl6_device_type` | The human-readable device type label. |
| `__meta_nl6_sys_name` | The device's `sysName`. |
| `__meta_nl6_snmp_port` | The SNMP UDP port. |

An empty fleet returns `[]`.
Stopped devices are not listed.

Prometheus drops every `__meta_*` label after relabeling.
Keep the ones you want by copying them to a plain label, as the example below does.

## What the body does not carry

**No credentials.**
The SNMP community and SNMPv3 passwords are never in the body.
Prometheus logs and caches SD responses.
Configure credentials in snmp_exporter's `snmp.yml` and select them with the `auth` parameter.

**No module choice.**
nl6 does not guess which snmp_exporter module fits a device type.
Map `__meta_nl6_resource` to `__param_module` in your relabel rules.

## Prometheus configuration

This job discovers the fleet from nl6 on `nl6:8080` and scrapes it through snmp_exporter on `snmp-exporter:9116`.

```yaml
scrape_configs:
  - job_name: nl6-snmp
    http_sd_configs:
      - url: http://nl6:8080/api/v1/prometheus/sd
        refresh_interval: 60s
    metrics_path: /snmp
    params:
      module: [if_mib]
      auth: [public_v2]
    relabel_configs:
      # Hand the device address to snmp_exporter.
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      # Keep the nl6 labels you want on every series.
      - source_labels: [__meta_nl6_sys_name]
        target_label: sys_name
      - source_labels: [__meta_nl6_resource]
        target_label: nl6_resource
      # Optional: a different module for one device family.
      - source_labels: [__meta_nl6_resource]
        regex: juniper_.*
        target_label: __param_module
        replacement: if_mib
      # Scrape snmp_exporter, not the device.
      - target_label: __address__
        replacement: snmp-exporter:9116
```

To scrape a subset of the fleet, add a `keep` rule on any `__meta_nl6_*` label.

New and deleted devices show up on the next `refresh_interval`.

## Reachability

snmp_exporter sends SNMP to the device IPs, so it needs a route into the simulated range (`10.42.0.0/16` by default).
`GET /api/v1/devices/routes` generates a route script for a Debian or Ubuntu host.
See the [web API reference](web-api.md).
