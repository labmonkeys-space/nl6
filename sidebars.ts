import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

// Three independent sidebars, one per top-level section. The navbar items in
// docusaurus.config.ts select which sidebar to render via `sidebarId`.
const sidebars: SidebarsConfig = {
  gettingStarted: [
    {
      type: 'category',
      label: 'Getting Started',
      collapsed: false,
      items: [
        'getting-started/quick-start',
        'getting-started/install-packages',
        'getting-started/docker',
        'getting-started/fleet',
        'getting-started/dns',
      ],
    },
  ],

  ops: [
    {
      type: 'category',
      label: 'Ops',
      collapsed: false,
      items: [
        'ops/scaling',
        'ops/network-namespace',
        'ops/flow-export',
        'ops/snmp-traps',
        'ops/syslog-export',
        'ops/migration-per-device-exports',
        'ops/kubernetes',
        'ops/troubleshooting',
      ],
    },
  ],

  reference: [
    {
      type: 'category',
      label: 'Reference',
      collapsed: false,
      items: [
        'reference/architecture',
        'reference/cli-flags',
        'reference/web-api',
        'reference/device-types',
        'reference/snmp',
        'reference/snmp-traps',
        'reference/syslog-export',
        'reference/flow-export',
        'reference/gnmi',
        'reference/gnmi-dial-out',
        'reference/interface-state',
        'reference/lldp-topology',
        'reference/dns-service-discovery',
        {
          type: 'category',
          label: 'Load-test scenarios',
          // The runbook is the operator entry point; clicking the category
          // label lands there, with the API + report schema as sub-pages.
          link: {type: 'doc', id: 'reference/loadtest-runbook'},
          items: [
            'reference/loadtest-api',
            'reference/loadtest-report-schema',
          ],
        },
        'reference/resource-files',
        {
          type: 'category',
          label: 'GPU Simulation',
          // Clicking the category label takes the reader to the GPU overview
          // page directly; the nested children become the sub-pages below it.
          // Avoids the confusing "GPU Simulation > index" sidebar shape.
          link: {type: 'doc', id: 'reference/gpu/index'},
          items: [
            'reference/gpu/proto-model',
            'reference/gpu/pollaris',
            'reference/gpu/dcgm',
          ],
        },
      ],
    },
  ],
};

export default sidebars;
