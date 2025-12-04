import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Only use static export for production builds (GitHub Pages)
  ...(process.env.NODE_ENV === 'production' ? { output: 'export' } : {}),
  trailingSlash: true,
  images: {
    unoptimized: true
  },
  // GitHub Pages typically serves from a subdirectory
  basePath: process.env.NODE_ENV === 'production' ? '/project-medusa' : '',
  assetPrefix: process.env.NODE_ENV === 'production' ? '/project-medusa/' : '',
  // Disable ESLint during build for demo
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
