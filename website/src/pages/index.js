import React from 'react';
import Layout from '@theme/Layout';
import HeroSection from '../components/HeroSection';
import FeaturesSection from '../components/FeaturesSection';
import AdoptersSection from '../components/AdoptersSection';
import TalksSection from '../components/TalksSection';
import CtaSection from '../components/CtaSection';

export default function Home() {
  return (
    <Layout
      title="Home"
      description="Directly patch container image vulnerabilities with Copacetic (copa)."
    >
      <main className="landing-page-main">
        <HeroSection />
        <FeaturesSection />
        <AdoptersSection />
        <TalksSection />
        <CtaSection />
      </main>
    </Layout>
  );
}
