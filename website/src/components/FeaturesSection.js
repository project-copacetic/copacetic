import React from 'react';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import { featureCards } from '../data/landingPageData';

export default function FeaturesSection() {
  return (
    <section className="features-section">
      <div className="features-grid">
        {featureCards.map((card, index) => (
          <Link key={index} to={useBaseUrl(card.link)} className="feature-card feature-card-link">
            <div className="feature-card-header">
              {card.icon && (
                <img
                  className="feature-icon"
                  alt={`${card.title} icon`}
                  src={useBaseUrl(card.icon)}
                />
              )}
              <h3 className="feature-title">{card.title}</h3>
            </div>
            <div className="feature-content">
              <p className="feature-description">{card.description}</p>
            </div>
          </Link>
        ))}
      </div>
    </section>
  );
}
