import React from 'react';
import clsx from 'clsx';
import styles from './HomepageFeatures.module.css';
import { MdCloud, MdCheckCircle, MdFlashOn, MdLock } from "react-icons/md";
import ReactMarkdown from 'react-markdown';
import Translate from '@docusaurus/Translate';

const FeatureList = [
  {
    title: <Translate description="The features title">Working Mode</Translate>,
    icon: <MdFlashOn size={26} />,
    description: `
- Standalone process with HTTP APIs
- Rust crate that integrates into your own application
    `,
  },
  {
    title: 'Post-Quantum Cryptography',
    icon: <MdLock size={26} />,
    description: `
- ChaCha20-Poly1305 payload encryption
- ML-KEM-768 key encapsulation
- ML-DSA-65 digital signatures
- rustls TLS stack
`,
  },
  {
    title: 'API',
    icon: <MdCheckCircle size={26} />,
    description: `RESTful API, compatible with HashiCorp Vault`,
  },
  {
    title: 'Authentication',
    icon: <MdCloud size={26} />,
    description: `
- Token-based
- AppRole
- Username/password
- Certificate (mTLS)
- Path-based ACL policies`,
  },
];

function Feature({icon, title, description}) {
  return (
    <div className={clsx('col col--6')}>
      <div style={{ paddingBottom: '20px', paddingTop: '20px' }}>
        <div style={{ display: 'flex' }}>
          <div style={{ paddingRight: '22px' }}>{icon}</div>
          <h3 style={{ fontSize: '20px', color: 'var(--ifm-color-primary)' }}>{title}</h3>
        </div>
        <ReactMarkdown>{description}</ReactMarkdown>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={clsx('home-section', 'home-section-alt', styles.features)}>
      <div className="container">
        <div className="row">
          <div className="col col--11 col--offset-1">
            <div className="row">
              {FeatureList.map((props, idx) => (
                <Feature key={idx} {...props} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
