import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

// One sidebar for the whole site, so a reader on any page can see every
// section. Each top-level category has a generated index page at the slug the
// navbar links to (docusaurus.config.ts). Doc ids are file paths under docs/,
// so regrouping here never changes a URL.
const sidebars: SidebarsConfig = {
  docs: [
    {
      type: 'category',
      label: 'Getting Started',
      collapsed: false,
      link: {
        type: 'generated-index',
        slug: '/getting-started',
        description: 'Install nl6, start a fleet, and try the first tasks.',
      },
      items: [
        {
          type: 'category',
          label: 'Install',
          collapsed: false,
          items: [
            'getting-started/quick-start',
            'getting-started/install-packages',
            'getting-started/ansible',
            'getting-started/docker',
          ],
        },
        {
          type: 'category',
          label: 'First tasks',
          collapsed: false,
          items: [
            'getting-started/fleet',
            'getting-started/dns',
            'getting-started/snmp-set',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'Ops',
      link: {
        type: 'generated-index',
        slug: '/ops',
        description: 'Run, scale, troubleshoot and profile a fleet, and operate its exports and load tests.',
      },
      items: [
        'ops/scaling',
        'ops/network-namespace',
        'ops/troubleshooting',
        'ops/profiling',
        {
          type: 'category',
          label: 'Export',
          items: ['ops/flow-export', 'ops/snmp-traps', 'ops/syslog-export'],
        },
        {
          type: 'category',
          label: 'Load-test scenarios',
          // No landing link here: a doc can be the link of one category only,
          // or its breadcrumbs and prev/next follow the wrong one. The
          // overview page is the Reference load-test landing.
          items: ['ops/loadtest-scenarios', 'ops/loadtest-runbooks'],
        },
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      link: {
        type: 'generated-index',
        slug: '/reference',
        description: 'Flags, endpoints, device data, protocols and wire formats.',
      },
      items: [
        {
          type: 'category',
          label: 'Control surface',
          items: ['reference/cli-flags', 'reference/web-api'],
        },
        {
          type: 'category',
          label: 'Device data',
          items: [
            'reference/device-types',
            'reference/resource-files',
            'reference/snmp-data-validation',
            {
              type: 'category',
              label: 'GPU simulation',
              link: {type: 'doc', id: 'reference/gpu/index'},
              items: ['reference/gpu/dcgm'],
            },
          ],
        },
        {
          type: 'category',
          label: 'Polling',
          items: [
            'reference/snmp',
            'reference/gnmi',
            'reference/gnmi-dial-out',
            'reference/netconf',
            'reference/interface-state',
            'reference/lldp-topology',
          ],
        },
        {
          type: 'category',
          label: 'Export',
          items: [
            'reference/snmp-traps',
            'reference/syslog-export',
            'reference/flow-export',
          ],
        },
        {
          type: 'category',
          label: 'Optical',
          items: ['reference/optical-telemetry', 'reference/optical-limitations'],
        },
        {
          type: 'category',
          label: 'Discovery',
          items: ['reference/dns-service-discovery', 'reference/prometheus-sd'],
        },
        {
          type: 'category',
          label: 'Load-test scenarios',
          link: {type: 'doc', id: 'reference/loadtest-overview'},
          items: ['reference/loadtest-api', 'reference/loadtest-report-schema'],
        },
      ],
    },
    {
      type: 'category',
      label: 'Explanation',
      link: {
        type: 'generated-index',
        slug: '/explanation',
        description: 'Why nl6 is built the way it is, and how far to trust what it serves.',
      },
      items: [
        'explanation/architecture',
        'explanation/kubernetes',
        'explanation/snmp-data-fidelity',
        'explanation/loadtest-collector-ceiling',
      ],
    },
  ],
};

export default sidebars;
