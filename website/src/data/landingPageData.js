import GithubIcon from '@site/static/img/icon-github.svg';
import SlackIcon from '@site/static/img/icon-slack.png';
import MeetingsIcon from '@site/static/img/icon-meetings.png';
import useBaseUrl from '@docusaurus/useBaseUrl';

export const featureCards = [
  {
    title: "Direct Vulnerability Patching",
    description: "Patches container images instantly without requiring full rebuilds - just adds a lightweight patch layer on top of existing images.",
    icon: "/img/feature-patching.png",
    link: "/quick-start",
  },
  {
    title: "Multi-Package Manager Support",
    description: "Supports multiple package managers, covering a wide range of base images like Alpine, Debian, Ubuntu, RHEL and many more.",
    icon: "/img/feature-pkg-manager.png",
    link: "/faq#how-does-copa-determine-what-tooling-image-to-use",
  },
  {
    title: "Multi-Platform Support",
    description: "Copa can automatically detect and patch multi-platform images across all supported platforms or target specific architectures.",
    icon: "/img/feature-multi-platform.png",
    link: "/multiplatform-patching",
  },
  {
    title: "Distroless Image Support",
    description: "Copacetic also supports patching of distroless DPKG and RPM based distroless images by spinning up a build tooling container.",
    icon: "/img/feature-distroless.png",
    link: "/multiplatform-patching",
  },
  {
    title: "Ecosystem & Scanner Compatible",
    description: "Built-in Trivy support with third-party scanners support, can be used in any CI/CD pipeline and we have a Docker-Desktop Extension.",
    icon: "/img/feature-ecosystem.png",
    link: "/scanner-plugins",
  },
];

export const adopters = [
  { 
    name: "Azure", 
    logo: "/img/adopter-azure.png",
    description: "Azure Container Registry (ACR) Continuous Patching uses Copa to automate the detection and remediation of vulnerabilities in container images.",
    link: "https://learn.microsoft.com/en-us/azure/container-registry/key-concept-continuous-patching",
  },
  { 
    name: "Kubescape", 
    logo: "/img/adopter-kubescape.png",
    description: "Kubescape (CNCF incubating) uses Copa to patch container images using the Grype image scanning tool.",
    link: "https://kubescape.io/blog/2024/07/14/kubescape-3-image-patching/",

  },
  { 
    name: "Devtron", 
    logo: "/img/adopter-devtron.png",
    description: "Devtron uses Copa to patch container image vulnerabilities traced by the security scan performed on the image.",
    link: "https://docs.devtron.ai/usage/plugins/plugin-list/copacetic",
  },
  { 
    name: "Helmper", 
    logo: "/img/adopter-helmper.png",
    description: "Helmper uses Copa to patch container images used in Helm charts.",
    link: "https://christoffernissen.github.io/helmper/",
  },
];

export const featuredTalks = [
  {
    title: "Session Presentation at KubeCon North America 2024",
    youtubeId: "UsHBGZ7np2Q",
  },
  {
    title: "Session Presentation at OpenSSF SOSS Fusion Conference 2024",
    youtubeId: "ros-UPDZum8",
  },
  {
    title: "Project lightning talk at KubeCon North America 2024",
    youtubeId: "g_8xDwXJRDM",
  },
];

export const communityButtons = [
  {
    title: "Join our Slack Channel",
    Icon: () => <img src={useBaseUrl(SlackIcon)} alt="Slack Icon" className='community-icon'/>,
    href: "https://cloud-native.slack.com/archives/C071UU5QDKJ"
  },
  {
    title: "Contribute on GitHub",
    Icon: GithubIcon,
    href: "https://github.com/project-copacetic/copacetic"
  },
  {
    title: "Community Meetings",
    Icon: () => <img src={useBaseUrl(MeetingsIcon)} alt="Meetings Icon" className='community-icon'/>,
    href: "https://docs.google.com/document/d/1QdskbeCtgKcdWYHI6EXkLFxyzTCyVT6e8MgB3CaAhWI/edit?usp=sharing" 
  },
];
