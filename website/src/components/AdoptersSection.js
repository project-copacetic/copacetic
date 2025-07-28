import React from 'react';
import useBaseUrl from '@docusaurus/useBaseUrl';
import Link from '@docusaurus/Link';
import { adopters } from '../data/landingPageData';

export default function AdoptersSection() {
  return (
    <section className="adopters-section">
      <h2 className="section-title">Adopted by</h2>
      <div className="adopters-grid">
        {adopters.map((adopter, index) => (
          <Link to={adopter.link} key={index} className="adopter-card">
            <div className="adopter-header">
              <img 
                className="adopter-logo-img"
                src={useBaseUrl(adopter.logo)} 
                alt={`${adopter.name} logo`} 
              />
            </div>
            <p className="adopter-description">{adopter.description}</p>
          </Link>
        ))}
      </div>
    </section>
  );
}
