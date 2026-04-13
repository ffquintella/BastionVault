import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Translate from '@docusaurus/Translate';
import styles from './index.module.css';
import HomepageFeatures from '../components/HomepageFeatures';
import HomepageCompare from '../components/HomepageCompare';

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();

  return (
    <header className={styles.heroBanner}>
      <div className="container">
        <img
          className={styles.homepageLogo}
          width="120"
          src={require('@site/static/img/bastionvault-logo.svg').default}
          alt="BastionVault Logo"
        />
        <img
          className={styles.homepageBanner}
          width="400"
          src={require('@site/static/img/bastionvault-logo.svg').default}
          alt="BastionVault Logo"
        />
        <h2 className="hero__subtitle">{siteConfig.tagline}</h2>
        <br/>
        <a href="https://github.com/ffquintella/BastionVault" target="_blank" rel="noreferrer">
          <img src="https://img.shields.io/github/stars/ffquintella/BastionVault.svg?style=social&label=Star" alt="GitHub stars"/>
        </a>
        <p>
          <Translate description="PQ description">
            Post-quantum-ready secret management, built in Rust.
          </Translate>
        </p>
        <div className={styles.buttons}>
          <Link
            className="button button--primary button--lg"
            to="/docs/quick-start/">
            <Translate description="The Getting Started button">
            Getting Started
            </Translate>
          </Link>
        </div>
      </div>
    </header>
  );
}

export default function Home() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      description={siteConfig.tagline}>
      <HomepageHeader />
      <main>
        <HomepageFeatures />
        <HomepageCompare />
      </main>
    </Layout>
  );
}
