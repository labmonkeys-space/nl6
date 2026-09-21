# Reference capture: Cisco IOS-XE 26.01.02 AVC / NBAR2 IPFIX export

`c8000v-26.01.02-avc.pcap` is IPFIX exported by a real Cisco Catalyst 8000V running IOS-XE 26.01.02 (NBAR engine 56, Advanced Protocol Pack), taken on 2026-09-21 over a containerlab veth link.
It is the pinned reading the NBAR2 design spec asked for (`docs/superpowers/specs/2026-09-18-nbar2-ipfix-l7-export-design.md`, section 1, "the exit if sourcing fails").
The facts read out of it are in `../NOTES.md` under "Reference capture" and are pinned by `cisco_avc_capture_test.go`, which decodes this file with its own template parser.
The Cisco software image is not in this repository and cannot be: it is Cisco-licensed.

## What is in the capture

| | |
|---|---|
| IPFIX messages | 395 |
| AVC data records (template 258) | 1302 |
| HTTP requests that produced them | 400 (5 hosts x 4 URIs x 20 rounds), plus DNS, SSH and ICMP flows |
| Application table rows per burst (template 257) | 1560, engines 1 / 3 / 13 |
| Interface table rows (template 256) | 2 per burst |
| Largest IP datagram | 1420 bytes |

The router's final running configuration for the flow objects and the client-facing interface is `r1-running.cfg`, captured with `show running-config | section flow|interface GigabitEthernet2` before teardown.

## How to regenerate it

Needs an x86_64 Linux host with `/dev/kvm`, docker, [containerlab](https://containerlab.dev) and a `c8000v-universalk9_*_serial.<version>.qcow2` obtained from Cisco (the serial, non-EFI qcow2 is the variant vrnetlab drives).

1. Build the vrnetlab image: clone `https://github.com/srl-labs/vrnetlab`, put the qcow2 in `cisco/c8000v/`, run `make docker-image` there. The install boot sets `license boot level network-premier addon dna-premier`, which is what makes NBAR2 usable without a smart account. The result is `vrnetlab/cisco_c8000v:<version>`; adjust `image:` in `avc.clab.yml` if the version differs.
2. `mkdir pcap && containerlab deploy -t avc.clab.yml` in this directory. The router takes about five minutes; wait for `Startup complete` in `docker logs clab-avc-r1`. Router login is `admin` / `admin` on its management address.
3. Check the monitor bound: `show flow monitor AVC-MON` must report the exporter without `(inactive)` and the cache `allocated`. If the bind was refused, the reason is printed at configuration time and the constraints are in the comment at the top of `r1.cfg`.
4. `docker cp traffic.sh clab-avc-client:/ && docker exec clab-avc-client sh /traffic.sh 20`, then wait about 40 seconds for transaction-end aging and export.
5. The collector container writes `pcap/avc.pcap` continuously. `containerlab destroy -t avc.clab.yml` stops it.

`traffic.sh` sends each HTTP request on its own TCP connection (`Connection: close`) so every request is one transaction with one host and one URI, which is what makes the per-record host and URI values countable against the request list.
