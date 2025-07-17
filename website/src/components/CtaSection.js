import React from 'react';
import Link from '@docusaurus/Link';
import { communityButtons } from '../data/landingPageData';
import useBaseUrl from '@docusaurus/useBaseUrl';
import CncLogo from '@site/static/img/cncf-logo.png';

export default function CtaSection() {
return (
    <>
      <section className="cncf-section">
        <p className="cncf-text">
        Copacetic is a{' '}
        <span className="cncf-highlight">Cloud Native Computing Foundation</span>{' '}
        Sandbox project
        </p>
        <img
        className="cncf-logo"
        alt="CNCF Logo"
        src={CncLogo}/>
      </section>
      <section className="community-section">
      <h2 className="section-title community-title">Join the Community!</h2>
      <div className="community-buttons">
        {communityButtons.map((button, index) => (
          <Link key={index} to={button.href} className="button community-button">
            <img
              className="community-icon"
              alt={`${button.title} icon`}
              src={useBaseUrl(button.icon)}
            />
            <span className="community-button-text">{button.title}</span>
          </Link>
        ))}
      </div>
    </section>
    </>
  )
}
