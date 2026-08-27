# Security Patch Summary: nl6-minion Helm Chart

## Overview

This patch addresses a security finding related to privileged host-networked pods
in the nl6-minion Helm chart. The chart deploys a network simulator with dangerous
privileges that can be exploited for container escape and node compromise.

## Changes Made

### 1. Security Acknowledgment Requirement (deployment.yaml)

**Added:** Pre-deployment validation that fails unless `security.acknowledgeRisks: true`
is explicitly set in values.yaml.

**Rationale:** Forces operators to consciously acknowledge the security risks before
deployment, preventing accidental deployment in inappropriate environments.

**Impact:** Existing deployments will fail to upgrade unless values.yaml is updated.
This is intentional — operators must review and acknowledge the new security guidance.

### 2. Node Selector Requirement (deployment.yaml)

**Added:** Pre-deployment validation that fails unless `nodeSelector` is configured.

**Rationale:** The simulator mutates the node's network stack. Placement must be
stable and on a dedicated, isolated node. Preventing deployment without explicit
node selection reduces the risk of accidental deployment on shared nodes.

**Impact:** Existing deployments must specify a nodeSelector to upgrade.

### 3. NetworkPolicy Template (networkpolicy.yaml)

**Added:** Optional NetworkPolicy to restrict access to the nl6 HTTP API.

**Configuration:**
```yaml
security:
  networkPolicy:
    enabled: true
    ingress:
      - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring
```

**Rationale:** The nl6 API has no built-in authentication. With `hostNetwork: true`,
the API port is exposed on the node's IP. NetworkPolicy provides network-level
access control as the only protection against unauthorized API access.

**Impact:** Requires a CNI that enforces NetworkPolicy (Calico, Cilium, Weave).
Disabled by default for compatibility, but strongly recommended.

### 4. Enhanced Security Documentation

**Added:**
- `SECURITY.md` — Comprehensive security considerations, threat model, required
  mitigations, and risk acceptance guidance
- Security warnings in `values.yaml` with detailed explanations of each privilege
  and its implications
- Security warnings in `deployment.yaml` comments explaining why `hostNetwork: true`
  is dangerous
- Security warnings in `README.md` with step-by-step secure deployment instructions
- Security warnings in `NOTES.txt` displayed after deployment
- Example secure configuration in `examples/secure-values.yaml`

**Rationale:** Operators must understand the risks to make informed decisions.
Documentation explains what each privilege does, why it's dangerous, and what
mitigations are required.

### 5. Explicit Capability Documentation (values.yaml)

**Changed:** Expanded `nl6.securityContext` comments to explain:
- What `privileged: true` grants (unrestricted host access, container escape paths)
- What `CAP_SYS_ADMIN` allows (namespace manipulation, "new root")
- What `CAP_NET_ADMIN` allows (network config, iptables, sysctls)
- Why these are dangerous when combined with `hostNetwork: true`
- What mitigations are required

**Added:** Explicit `capabilities.drop: [ALL]` (only effective if `privileged: false`)
to document the principle of least privilege.

### 6. Chart Metadata Updates (Chart.yaml)

**Changed:**
- Version bumped from 0.1.4 to 0.1.5
- Added security warning to description
- Added `sources` field pointing to GitHub repository
- Added Artifact Hub annotations documenting the security update

### 7. Deployment Notes Enhancement (NOTES.txt)

**Added:**
- Security warning banner displayed after deployment
- Check for NetworkPolicy enabled/disabled status
- Warning about unauthenticated API exposure
- Reminder of required mitigations

## Required Mitigations (Documented)

The patch documents that operators MUST implement ALL of the following:

1. **Dedicated, isolated node** — Deploy only on a node with no other workloads
2. **Node taints** — Prevent other pods from co-locating on the simulator node
3. **NetworkPolicy** — Restrict API access to authorized clients only
4. **Namespace isolation** — Deploy in a dedicated namespace with PodSecurity=privileged
5. **No external exposure** — Do NOT expose the API via LoadBalancer/Ingress
6. **Risk acknowledgment** — Explicitly set `security.acknowledgeRisks: true`

## What This Patch Does NOT Do

This patch does NOT:

1. **Remove the dangerous privileges** — The simulator requires them to function.
   The architecture fundamentally needs `hostNetwork`, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`,
   and `/dev/net/tun` access. Removing them would break the simulator.

2. **Add authentication to the API** — This would require changes to the nl6
   application itself, not just the Helm chart. The patch documents that operators
   must use NetworkPolicy or a reverse proxy for access control.

3. **Eliminate the container escape risk** — `privileged: true` and `CAP_SYS_ADMIN`
   provide well-known escape paths. The patch documents this risk and requires
   deployment on isolated nodes to limit blast radius.

4. **Make the deployment production-ready** — This remains a lab/test deployment.
   The patch makes the risks explicit and requires conscious acknowledgment, but
   does not change the fundamental architecture.

## Migration Guide for Existing Deployments

If you have an existing nl6-minion deployment, you must update your values.yaml
before upgrading:

```yaml
# REQUIRED: Add security acknowledgment
security:
  acknowledgeRisks: true

# REQUIRED: Add node selector (if not already present)
nodeSelector:
  kubernetes.io/hostname: your-node-name

# RECOMMENDED: Enable NetworkPolicy
security:
  networkPolicy:
    enabled: true
    ingress:
      - from:
        - namespaceSelector:
            matchLabels:
              name: monitoring

# RECOMMENDED: Add node taints and tolerations
# On the node:
#   kubectl taint nodes <node> nl6-simulator=true:NoSchedule
# In values.yaml:
tolerations:
  - key: nl6-simulator
    operator: Equal
    value: "true"
    effect: NoSchedule
```

Then upgrade:
```bash
helm upgrade nl6-lab deploy/helm/nl6-minion -n nl6 -f values.yaml
```

## Testing

To verify the security controls:

1. **Test deployment without acknowledgment:**
   ```bash
   helm install test deploy/helm/nl6-minion -n test --create-namespace \
     --set nodeSelector."kubernetes\.io/hostname"=node1
   # Should FAIL with security acknowledgment error
   ```

2. **Test deployment without nodeSelector:**
   ```bash
   helm install test deploy/helm/nl6-minion -n test --create-namespace \
     --set security.acknowledgeRisks=true
   # Should FAIL with node selector error
   ```

3. **Test successful deployment:**
   ```bash
   helm install test deploy/helm/nl6-minion -n test --create-namespace \
     --set security.acknowledgeRisks=true \
     --set nodeSelector."kubernetes\.io/hostname"=node1 \
     --set minion.kafka.bootstrapServers=kafka:9092 \
     --set minion.httpUrl=http://opennms:8980/opennms
   # Should SUCCEED and display security warnings in NOTES
   ```

4. **Test NetworkPolicy (if CNI supports it):**
   ```bash
   # Deploy with NetworkPolicy enabled
   helm install test deploy/helm/nl6-minion -n test -f secure-values.yaml
   
   # Verify NetworkPolicy exists
   kubectl -n test get networkpolicy
   
   # Test that API is blocked from unauthorized pods
   kubectl run -n default test-pod --rm -it --image=busybox -- \
     wget -O- http://<pod-ip>:8080/api/v1/version
   # Should timeout or be rejected
   
   # Test that API is accessible from authorized namespace
   kubectl run -n monitoring test-pod --rm -it --image=busybox -- \
     wget -O- http://<pod-ip>:8080/api/v1/version
   # Should succeed
   ```

## Residual Risks

Even with all mitigations implemented, the following risks remain:

1. **Container escape is still possible** — `privileged: true` and `CAP_SYS_ADMIN`
   provide escape paths. Mitigation: isolated node limits blast radius.

2. **Node compromise affects the cluster** — An attacker who escapes to the node
   can access kubelet credentials and pivot to other nodes. Mitigation: network
   segmentation, node-level monitoring.

3. **API has no authentication** — NetworkPolicy provides network-level access
   control, but any pod in an authorized namespace can access the API. Mitigation:
   minimize the number of authorized namespaces, use a reverse proxy for
   authentication if external access is needed.

4. **Host network mutation is unavoidable** — The simulator's architecture requires
   it. Mitigation: dedicated node, no other workloads.

These risks are inherent to the simulator's design and cannot be eliminated by
Helm chart changes alone. Operators must accept these residual risks or use an
alternative deployment method (bare-metal, Docker, VM).

## Conclusion

This patch does not eliminate the security risks of the nl6-minion deployment —
that would require fundamental architectural changes to the simulator itself.
Instead, it:

1. **Makes the risks explicit** through comprehensive documentation
2. **Requires conscious acknowledgment** before deployment
3. **Provides mitigation controls** (NetworkPolicy, node isolation guidance)
4. **Prevents accidental deployment** in inappropriate environments

The deployment remains suitable only for dedicated lab/test environments with
isolated nodes. Operators who deploy this chart accept responsibility for
implementing all required mitigations and monitoring for compromise.
