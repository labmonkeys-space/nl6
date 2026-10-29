import React from 'react';
import Layout from '@theme/Layout';
import Head from '@docusaurus/Head';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Landing from '@site/src/components/Landing';

// Homepage — replaces the default doc-index at `/` (the docs preset has
// `routeBasePath: '/'`, but `src/pages/index.tsx` wins for the exact `/`
// route and Docusaurus emits the rest of the docs under their own slugs).
export default function Home(): React.JSX.Element {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={siteConfig.title}
      description={siteConfig.tagline}
    >
      <Head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap"
        />
      </Head>
      <Landing />
    </Layout>
  );
}
