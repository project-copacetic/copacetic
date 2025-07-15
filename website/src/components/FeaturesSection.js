import React from 'react';
import { featureCards } from '../data/landingPageData';
import useBaseUrl from '@docusaurus/useBaseUrl'; // Import the useBaseUrl hook

export default function FeaturesSection() {
  return (
    <section className="features-section">
      <div className="features-grid">
        {featureCards.map((card, index) => (
          <div key={index} className="feature-card">
            <div className="feature-card-header">
              {card.icon && (
                <img
                  className="feature-icon"
                  alt={`${card.title} icon`}
                  src={useBaseUrl(card.icon)} // Use the hook to get the correct path
                />
              )}
              <h3 className="feature-title">{card.title}</h3>
            </div>
            <div className="feature-content">
              <p className="feature-description">{card.description}</p>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
