import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true
  },
  // GitHub Pages configuration
  basePath: '/project-medusa',
  assetPrefix: '/project-medusa/static/',
};

export default nextConfig;
