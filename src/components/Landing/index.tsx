import React, {useState} from 'react';
import useBaseUrl from '@docusaurus/useBaseUrl';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Terminal from './Terminal';
import {FEATURES, CATEGORIES, DOCS, STATUS} from './data';

type HeroMeta = {appVersion: string; license: string; goVersion: string};

function Panel({title, meta, children}: {title?: string; meta?: string; children: React.ReactNode}) {
  return (
    <div className="nl6-panel">
      {title && (
        <div className="nl6-panel__hd">
          <span className="nl6-panel__title">{title}</span>
          {meta && <span className="nl6-panel__meta">{meta}</span>}
        </div>
      )}
      <div className="nl6-panel__bd">{children}</div>
    </div>
  );
}

function Stat({label, value, unit}: {label: string; value: string; unit?: string}) {
  return (
    <div className="nl6-stat">
      <div className="nl6-stat__label">{label}</div>
      <div className="nl6-stat__val">
        <span className="nl6-stat__num">{value}</span>
        {unit && <span className="nl6-stat__unit">{unit}</span>}
      </div>
    </div>
  );
}

function Copyable({text, prompt = '$'}: {text: string; prompt?: string}) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="nl6-copy">
      <span className="nl6-copy__prompt">{prompt}</span>
      <code className="nl6-copy__text">{text}</code>
      <button
        type="button"
        className="nl6-copy__btn"
        onClick={() => {
          navigator.clipboard?.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        }}
      >
        {copied ? 'copied' : 'copy'}
      </button>
    </div>
  );
}

function Icon({name}: {name: string}) {
  const c = {width: 18, height: 18, viewBox: '0 0 18 18', fill: 'none', stroke: 'currentColor', strokeWidth: 1} as const;
  switch (name) {
    case 'scale':
      return (
        <svg {...c}>
          {[0, 1, 2].flatMap(r => [0, 1, 2].map(col => (
            <rect key={`${r}-${col}`} x={2 + col * 5} y={2 + r * 5} width="4" height="4" />
          )))}
        </svg>
      );
    case 'proto':
      return (
        <svg {...c}>
          <path d="M2 5h14M2 9h14M2 13h14" />
          <circle cx="5" cy="5" r="0.8" fill="currentColor" />
          <circle cx="10" cy="9" r="0.8" fill="currentColor" />
          <circle cx="13" cy="13" r="0.8" fill="currentColor" />
        </svg>
      );
    case 'devices':
      return (<svg {...c}><rect x="2" y="3" width="14" height="9" /><path d="M6 15h6M9 12v3" /></svg>);
    case 'gpu':
      return (<svg {...c}><rect x="2" y="4" width="14" height="10" /><rect x="4" y="6" width="4" height="3" /><rect x="10" y="6" width="4" height="3" /><path d="M4 11h10" /></svg>);
    case 'isol':
      return (<svg {...c}><rect x="2" y="2" width="14" height="14" strokeDasharray="2 2" /><rect x="5" y="5" width="8" height="8" /></svg>);
    case 'metric':
      return (<svg {...c}><path d="M2 13 L5 9 L8 11 L11 5 L14 8 L16 7" /></svg>);
    default:
      return null;
  }
}

function DocLink({to, t, h}: {to: string; t: string; h: string}) {
  return (
    <a href={to} className="nl6-docs__link">
      <span className="nl6-docs__link-t">{t}</span>
      <span className="nl6-docs__link-h">{h}</span>
      <span className="nl6-docs__link-arr">→</span>
    </a>
  );
}

export default function Landing(): JSX.Element {
  const quickStart = useBaseUrl('/getting-started/quick-start');
  const {siteConfig} = useDocusaurusContext();
  const {appVersion, license, goVersion} = siteConfig.customFields as HeroMeta;
  // Bare version (no leading "v") for package filenames; the release tag keeps
  // the "v". appVersion is resolved at build time, so these stay current.
  const ver = appVersion.replace(/^v/, '');

  return (
    <main className="nl6-page">
      <div className="nl6-container">
        {/* hero */}
        <section className="nl6-hero">
          <div className="nl6-hero__grid">
            <div>
              <div className="nl6-hero__eyebrow">
                <span className="nl6-dot" /> {appVersion} · {license} · {goVersion}
              </div>
              <h1 className="nl6-hero__title">
                A network load target<br />
                for the <span className="nl6-hi">monitoring tools</span><br />
                you're building.
              </h1>
              <p className="nl6-hero__body">
                nl6 simulates up to <b>30,000</b> network devices, GPU servers, storage systems
                and Linux hosts on a single Linux host — each with its own IP, SNMP listener, SSH
                server, HTTPS REST endpoint and flow exporter. Built on TUN interfaces and network
                namespaces.
              </p>
              <div className="nl6-hero__ctas">
                <a className="nl6-btn nl6-btn--primary" href={quickStart}>quick start →</a>
                <a className="nl6-btn" href="https://github.com/labmonkeys-space/nl6">github ↗</a>
              </div>
            </div>
            <div style={{display: 'grid', gap: 16}}>
              <Terminal />
              <div className="nl6-hero__stats">
                <Stat label="devices / host" value="30,000" unit="max" />
                <Stat label="device types"   value="28"     unit="in 8 cat." />
                <Stat label="mem / device"   value="~1"     unit="KB" />
                <Stat label="parallel workers" value="500"  unit="max" />
              </div>
            </div>
          </div>
        </section>

        {/* 01 quick start */}
        <section className="nl6-sec">
          <div className="nl6-sec__hd">
            <span className="nl6-sec__num">01</span>
            <h2 className="nl6-sec__title">quick start</h2>
            <span className="nl6-sec__sub">build from source · install a package · or pull with docker</span>
          </div>
          <div className="nl6-grid-3">
            <Panel title="01 · clone" meta="git">
              <Copyable text="git clone https://github.com/labmonkeys-space/nl6.git" />
              <Copyable text="cd nl6" />
            </Panel>
            <Panel title="02 · build" meta="make · go 1.26+">
              <Copyable text="make tidy" />
              <Copyable text="make build" />
            </Panel>
            <Panel title="03 · run" meta="needs root">
              <Copyable text="sudo ./go/nl6/nl6 -auto-start-ip 10.0.0.1 -auto-count 100" />
            </Panel>
          </div>
          <div className="nl6-sec__or"><span>or install a package</span></div>
          <div className="nl6-grid-2">
            <Panel title="01 · download & install" meta=".deb / .rpm · from releases">
              <Copyable text={`curl -LO https://github.com/labmonkeys-space/nl6/releases/download/v${ver}/nl6_${ver}_amd64.deb`} />
              <Copyable text={`sudo apt install ./nl6_${ver}_amd64.deb`} />
              <Copyable text={`curl -LO https://github.com/labmonkeys-space/nl6/releases/download/v${ver}/nl6-${ver}-1.x86_64.rpm`} />
              <Copyable text={`sudo dnf install ./nl6-${ver}-1.x86_64.rpm`} />
            </Panel>
            <Panel title="02 · configure & start" meta="systemd · needs root">
              <Copyable text="sudoedit /etc/nl6/nl6.conf" />
              <Copyable text="sudo systemctl enable --now nl6" />
            </Panel>
          </div>
          <div className="nl6-sec__or"><span>or on nixos · cachix-cached flake</span></div>
          <div className="nl6-grid-2">
            <Panel title="01 · trust the cache" meta="cachix · prebuilt">
              <Copyable text="nix profile install nixpkgs#cachix" />
              <Copyable text="cachix use nl6" />
            </Panel>
            <Panel title="02 · enable the module" meta="services.nl6 · declarative">
              <Copyable text="services.nl6.enable = true;" prompt="#" />
            </Panel>
          </div>
          <div className="nl6-sec__or"><span>or with docker</span></div>
          <div className="nl6-grid-2">
            <Panel title="01 · pull" meta="no toolchain">
              <Copyable text="docker pull ghcr.io/labmonkeys-space/nl6:latest" />
            </Panel>
            <Panel title="02 · run" meta="needs --cap-add=net_admin">
              <Copyable text={`docker run --rm -it \\
  --cap-add=NET_ADMIN \\
  --device=/dev/net/tun \\
  --network=host \\
  ghcr.io/labmonkeys-space/nl6:latest \\
  -auto-start-ip 10.0.0.1 -auto-count 100`} />
            </Panel>
          </div>
        </section>

        {/* 02 features */}
        <section className="nl6-sec">
          <div className="nl6-sec__hd">
            <span className="nl6-sec__num">02</span>
            <h2 className="nl6-sec__title">what's in the box</h2>
            <span className="nl6-sec__sub">six pillars</span>
          </div>
          <div className="nl6-features">
            {FEATURES.map((f, i) => (
              <div key={f.title} className="nl6-panel">
                <div className="nl6-panel__hd">
                  <span className="nl6-panel__meta" style={{color: 'var(--nl6-fg-mute)'}}>{String(i + 1).padStart(2, '0')}</span>
                </div>
                <div className="nl6-panel__bd">
                  <div className="nl6-feat__ic"><Icon name={f.icon} /></div>
                  <div className="nl6-feat__t">{f.title}</div>
                  <p className="nl6-feat__b">{f.body}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* 03 catalog */}
        <section className="nl6-sec">
          <div className="nl6-sec__hd">
            <span className="nl6-sec__num">03</span>
            <h2 className="nl6-sec__title">device catalog</h2>
            <span className="nl6-sec__sub">28 types · 8 categories · 341 resource files</span>
          </div>
          <div className="nl6-grid-4">
            {CATEGORIES.map(cat => (
              <Panel key={cat.name} title={cat.name.toLowerCase()} meta={`${cat.items.length}`}>
                <ul className="nl6-cat__list">
                  {cat.items.map(i => (<li key={i}><span className="nl6-cat__bullet">›</span>{i}</li>))}
                </ul>
              </Panel>
            ))}
          </div>
        </section>

        {/* 04 status & scale */}
        <section className="nl6-sec">
          <div className="nl6-sec__hd">
            <span className="nl6-sec__num">04</span>
            <h2 className="nl6-sec__title">status & scale</h2>
            <span className="nl6-sec__sub">what works · how big</span>
          </div>
          <div className="nl6-grid-3">
            {STATUS.map(s => (
              <Panel key={s.k} title={s.k.toLowerCase()} meta={`${s.items.length}`}>
                <ul className="nl6-status__list">
                  {s.items.map(i => (<li key={i}><span className="nl6-status__tick">■</span>{i}</li>))}
                </ul>
              </Panel>
            ))}
          </div>
          <div className="nl6-scale">
            <Stat label="concurrent devices" value="30,000" unit="tested" />
            <Stat label="device types"       value="28" />
            <Stat label="resource files"     value="341" unit="json" />
            <Stat label="world cities"       value="98"  unit="sysLocation" />
            <Stat label="ssh commands"       value="36+" unit="linux" />
          </div>
        </section>

        {/* 05 docs map */}
        <section className="nl6-sec">
          <div className="nl6-sec__hd">
            <span className="nl6-sec__num">05</span>
            <h2 className="nl6-sec__title">documentation map</h2>
            <span className="nl6-sec__sub">jump in</span>
          </div>
          <div className="nl6-grid-4">
            {DOCS.map(d => (
              <Panel key={d.group} title={d.group.toLowerCase()}>
                <p className="nl6-docs__body">{d.body}</p>
                <ul className="nl6-docs__links">
                  {d.links.map(l => (
                    <li key={l.h}><DocLinkBU t={l.t} h={l.h} /></li>
                  ))}
                </ul>
              </Panel>
            ))}
          </div>
        </section>

        {/* cta */}
        <section className="nl6-sec" style={{borderBottom: 'none'}}>
          <Panel>
            <div className="nl6-cta">
              <div>
                <div className="nl6-cta__eye">→ get started</div>
                <h2 className="nl6-cta__t">Spin up tens of thousands of devices in&nbsp;seconds.</h2>
                <p className="nl6-cta__b">Apache-2.0. No agents, no cloud, no per-device fees. Just TUN interfaces and a little Go.</p>
              </div>
              <div className="nl6-cta__r">
                <a className="nl6-btn nl6-btn--primary" href={quickStart}>quick start →</a>
                <a className="nl6-btn" href="https://github.com/labmonkeys-space/nl6">github ↗</a>
              </div>
            </div>
          </Panel>
        </section>
      </div>
    </main>
  );
}

// Separate component so we can call the `useBaseUrl` hook per link (hooks cannot
// run inside a .map callback's arrow if we want SSR-safe base-url resolution
// under Docusaurus — this defers it to render time).
function DocLinkBU({t, h}: {t: string; h: string}) {
  const to = useBaseUrl(h);
  return <DocLink to={to} t={t} h={h} />;
}
