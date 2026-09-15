import React from 'react';
import Link from '@docusaurus/Link';
import { communityButtons } from '../data/landingPageData';
import CncLogo from '@site/static/img/cncf-logo.svg';

export default function CtaSection() {
return (
    <>
      <section className="cncf-section">
        <p className="cncf-text">
        Copacetic is a{' '}
        <span className="cncf-highlight">Cloud Native Computing Foundation</span>{' '}
        Sandbox project
        </p>
        <CncLogo
        className="cncf-logo"
        alt="CNCF Logo"/>
      </section>
      <section className="community-section">
      <h2 className="section-title community-title">Join the Community!</h2>
      <div className="community-buttons">
        {communityButtons.map(({title, Icon, href}, index) => (
          <Link key={index} to={href} className="button community-button">
            <Icon className="community-icon" />
            <span className="community-button-text">{title}</span>
          </Link>
        ))}
      </div>
    </section>
    </>
  )
}
