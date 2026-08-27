<!--
Copyright 2026 Ronny Trommer <ronny@no42.org>
SPDX-License-Identifier: Apache-2.0
-->
# Security Considerations for nl6-minion Helm Chart

## Overview

This Helm chart deploys the nl6 network-device simulator with dangerous privileges
that weaken Kubernetes node isolation. It is designed **exclusively** for dedicated
lab and test environments, **NOT** for production clusters or multi-tenant environments.

## Threat Model

### Attack Vectors

1. **Code execution in the simulator container**
   - Via vulnerability in the Go runtime, dependencies, or nl6 code itself
   - Via supply chain compromise of the container image
   - Result: Attacker gains privileged container access with host network visibility

2. **Unauthenticated API access**
   - The nl6 HTTP API (default port 8080) has **no built-in authentication**
   - With `hostNetwork: true`, this port is exposed on the node's IP address
   - Any client that can reach the node can trigger mutating operations
   - Result: Attacker can create/delete devices, trigger network operations, access debug endpoints

3. **Kubernetes RBAC escalation**
   - If an attacker gains access to a ServiceAccount with pod exec/attach permissions
   - They can exec into the privileged nl6 container
   - Result: Direct access to privileged container with host network and device access

### Impact of Compromise

With the privileges granted by this chart, an attacker who gains code execution
in the simulator container can:

1. **Affect node networking**
   - Modify routing tables (the simulator installs host routes via `ip route replace`)
   - Write sysctls (`net.ipv4.ip_forward`, `rp_filter`, etc.)
   - Manipulate iptables rules (the simulator adds FORWARD rules)
   - Create/destroy network namespaces
   - Interfere with other pods' network connectivity on the node

2. **Escape the container**
   - `privileged: true` grants access to all host devices and disables most security restrictions
   - `CAP_SYS_ADMIN` allows mounting filesystems, loading kernel modules, and other escape paths
   - Access to `/dev/net/tun` provides additional network manipulation capabilities
   - Well-known container escape techniques become trivial

3. **Pivot to node compromise**
   - Once escaped, attacker has root access to the Kubernetes node
   - Can access kubelet credentials, container runtime socket, other pods' filesystems
   - Can pivot to other nodes via cluster networking
   - Can exfiltrate secrets, manipulate workloads, establish persistence

4. **Lateral movement**
   - With `hostNetwork: true`, the pod can reach any service accessible from the node
   - Can scan internal networks, access node-local services (kubelet, container runtime)
   - Can intercept or manipulate traffic to/from other pods on the node

## Required Mitigations

These mitigations are **mandatory** for any deployment of this chart. Failure to
implement them creates an unacceptable security risk.

### 1. Dedicated, Isolated Node

**Requirement:** Deploy only on a node that runs no other workloads.

**Implementation:**
```bash
# Taint the node to prevent other pods from scheduling
kubectl taint nodes <node> nl6-simulator=true:NoSchedule

# Label the node for identification
kubectl label nodes <node> node-role.kubernetes.io/nl6-simulator=true

# In values.yaml:
nodeSelector:
  kubernetes.io/hostname: <node>
  # Or:
  # node-role.kubernetes.io/nl6-simulator: "true"

tolerations:
  - key: nl6-simulator
    operator: Equal
    value: "true"
    effect: NoSchedule
```

**Rationale:** Limits blast radius. If the simulator is compromised, only the
dedicated node is affected, not other workloads.

### 2. Network Policy for API Access Control

**Requirement:** Restrict access to the nl6 HTTP API to only authorized clients.

**Implementation:**
```yaml
# In values.yaml:
security:
  networkPolicy:
    enabled: true
    ingress:
      # Example: Allow only from monitoring namespace
      - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
      # Example: Allow only from specific pods
      - from:
        - podSelector:
            matchLabels:
              app: opennms-core
```

**Rationale:** The API has no built-in authentication. Network-level access control
is the only protection against unauthorized device manipulation and debug endpoint access.

**Note:** Requires a CNI that enforces NetworkPolicy (Calico, Cilium, Weave, etc.).
Verify your CNI supports NetworkPolicy before relying on this mitigation.

### 3. Namespace Isolation

**Requirement:** Deploy in a dedicated namespace with appropriate PodSecurity admission.

**Implementation:**
```bash
# Create namespace with privileged PodSecurity enforcement
kubectl create namespace nl6
kubectl label namespace nl6 \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/audit=privileged \
  pod-security.kubernetes.io/warn=privileged

# Restrict RBAC to this namespace
# Do NOT grant cluster-admin or cross-namespace permissions
```

**Rationale:** Limits the scope of Kubernetes RBAC that can interact with the
privileged pod. Prevents accidental or malicious exec/attach from other namespaces.

### 4. No External Exposure

**Requirement:** Do NOT expose the nl6 API outside the cluster.

**Implementation:**
- Do NOT create a Service of type LoadBalancer or NodePort for the nl6 API
- Do NOT create an Ingress that routes to the nl6 API
- If external access is required, deploy an authenticating reverse proxy
  (oauth2-proxy, Pomerium, etc.) with strong authentication

**Rationale:** The API has no authentication. External exposure allows anyone on
the internet to manipulate the simulator and potentially exploit it for node access.

### 5. Image Provenance and Scanning

**Requirement:** Use only trusted container images and scan for vulnerabilities.

**Implementation:**
```bash
# Verify image signatures (if available)
cosign verify ghcr.io/labmonkeys-space/nl6:<tag>

# Scan for vulnerabilities
trivy image ghcr.io/labmonkeys-space/nl6:<tag>

# Use a specific tag, not :latest
# In values.yaml:
nl6:
  image:
    tag: "0.21.0"  # Pin to a specific version
```

**Rationale:** Supply chain compromise is a primary attack vector for privileged
containers. Verify you're running the code you expect.

### 6. Monitoring and Alerting

**Requirement:** Monitor the simulator pod and node for suspicious activity.

**Implementation:**
- Enable audit logging for pod exec/attach events in this namespace
- Monitor node syscalls for unexpected namespace/network operations
- Alert on unexpected network connections from the simulator pod
- Monitor the nl6 API access logs (if exposed via reverse proxy)

**Rationale:** Early detection of compromise allows faster response and limits impact.

## Risk Acceptance

By setting `security.acknowledgeRisks: true` in values.yaml, you acknowledge that:

1. You understand this deployment grants privileges that can be used for container
   escape and node compromise.

2. You have implemented ALL required mitigations listed above.

3. You accept the residual risk that a vulnerability in nl6, its dependencies, or
   the container runtime could lead to node compromise.

4. You understand this is a lab/test deployment and is NOT suitable for production
   or multi-tenant environments.

5. You will monitor for security updates to nl6, the base image, and Kubernetes,
   and will apply them promptly.

## Alternatives

If these security requirements are unacceptable for your environment, consider:

1. **Bare-metal deployment** — Run nl6 on a dedicated Linux host outside Kubernetes.
   See `docs/getting-started/quick-start.md`.

2. **Docker on a single host** — Run nl6 in Docker on a dedicated machine.
   See `docs/getting-started/docker.md`.

3. **VM-based isolation** — Run nl6 in a dedicated VM with no other workloads.

All three alternatives provide the same functionality without the Kubernetes-specific
risks of privileged pods in a shared cluster.

## Reporting Security Issues

If you discover a security vulnerability in nl6 or this Helm chart, please report
it responsibly:

1. Do NOT open a public GitHub issue
2. Email the maintainers (see repository README for contact information)
3. Include a detailed description of the vulnerability and steps to reproduce
4. Allow reasonable time for a fix before public disclosure

## References

- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST Application Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
- [nl6 Kubernetes Documentation](../../../docs/ops/kubernetes.md)
