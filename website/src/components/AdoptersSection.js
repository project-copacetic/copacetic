import React from 'react';
import { adopters } from '../data/landingPageData';
import useBaseUrl from '@docusaurus/useBaseUrl';

export default function AdoptersSection() {
  return (
    <section className="adopters-section">
      <h2 className="section-title">Adopted by</h2>
      <div className="adopters-container">
        {adopters.map((adopter, index) => (
          <div key={index} className="adopter-logo">
            <img src={useBaseUrl(adopter.logo)} alt={`${adopter.name} logo`} />
            {adopter.text && <span>{adopter.text}</span>}
          </div>
        ))}
      </div>
    </section>
  );
}
