import React from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import Translate from '@docusaurus/Translate';
import styles from './HomepageCompare.module.css';

export default function render() {
  return (
    <section className={clsx('home-section', 'home-section-alt', styles.features)}>
      <div className="container">
        <div className="row">
          <div className={clsx('col col--12')}>
            <h2 className="text--center">
              <Translate description="The architecture heading">
                📖 Architecture Diagram
              </Translate>
              </h2>
            <p className="text--center">
              <Link to="https://github.com/ffquintella/BastionVault">BastionVault</Link> &nbsp;
              <Translate description="The architecture description">
                is structured into three principal components: BastionVault Core, 
                BastionVault Modules and BastionVault Surface.
              </Translate>
            </p>
            <div className="text--center padding-horiz--md">
              <img className={styles.seaography} src="/img/BastionVault-arch.svg"/>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
