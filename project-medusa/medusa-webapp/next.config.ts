import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Use standalone output for Docker, static export for GitHub Pages
  // Check if we're building for Docker (has API routes) or static export
  ...(process.env.DOCKER_BUILD === 'true' ? {
    output: 'standalone',
    // Remove basePath for Docker builds
    eslint: {
      // Ignore ESLint errors during Docker builds
      ignoreDuringBuilds: true,
    },
    typescript: {
      // Ignore TypeScript errors during Docker builds
      ignoreBuildErrors: true,
    },
  } : {
    output: 'export',
    trailingSlash: true,
    images: {
      unoptimized: true
    },
    // GitHub Pages typically serves from a subdirectory
    basePath: process.env.NODE_ENV === 'production' ? '/project-medusa' : '',
    assetPrefix: process.env.NODE_ENV === 'production' ? '/project-medusa/' : '',
  }),
};

export default nextConfig;
