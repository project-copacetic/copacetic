import React from 'react';
import Link from '@docusaurus/Link';
import CopaLogo from '@site/static/img/copa-logo.png';
import Download from '@site/static/img/icon-download.png';

export default function HeroSection() {
  return (
    <section className="hero-section">
      <div className="hero-logo-container">
        <img
          className="hero-logo"
          alt="Copa Logo"
          src={CopaLogo}
        />
      </div>

      <h1 className="hero-title">
        <span className="title-light">Directly </span>
        <span className="title-bold">patch</span>
        <span className="title-light"> container image vulnerabilities</span>
      </h1>

      <p className="hero-description">
        copa is an <span className="desc-highlight">Open Source</span> CLI tool 
        written in <Link to="https://go.dev/" className="desc-link">Go</Link> and 
        based on <Link to="https://docs.docker.com/build/buildkit/" className="desc-link">buildkit</Link> that 
        can be used to directly patch container images without full rebuilds. It can also patch 
        container images using the vulnerability scanning results from popular tools like{' '}
        <Link to="https://github.com/aquasecurity/trivy" className="desc-link">Trivy</Link>.
      </p>

      <div className="hero-buttons">
        <Link to="/introduction" className="button get-started-button">
          Get Started
        </Link>
        <Link to="/installation" className="button download-button">
          <img src={Download} alt="Download Icon" className="download-icon" />
          Download
        </Link>
      </div>
    </section>
  );
}
