import React from 'react';
import { featuredTalks } from '../data/landingPageData';

export default function TalksSection() {
  return (
    <section className="talks-section">
      <h2 className="section-title">Featured Talks</h2>
      <div className="talks-grid">
        {featuredTalks.map((talk, index) => (
          <div key={index} className="talk-item">
            <div className="video-container">
              <iframe
                src={`https://www.youtube.com/embed/${talk.youtubeId}`}
                frameBorder="0"
                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                allowFullScreen
                title={talk.title}
              ></iframe>
            </div>
            <p className="talk-description">{talk.title}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
