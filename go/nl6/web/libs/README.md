# Bundled graph-visualization libraries

Self-hosted (no CDN) so the web console renders the topology view offline /
inside the `nl6sim` network namespace.

| File | Package | Version | License |
|------|---------|---------|---------|
| `graphology.umd.min.js` | graphology | 0.25.4 | MIT |
| `sigma.min.js` | sigma | 3.0.1 | MIT |

The force layout is hand-rolled in `topology_logic.js` (no vendored layout
package), so graphology-layout-forceatlas2 / graphology-library are not
bundled. Update by re-fetching the pinned versions from unpkg.
