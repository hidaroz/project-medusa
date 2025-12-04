import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Don't use static export for server deployment (we're using Nginx, not GitHub Pages)
  // output: 'export' is only for static hosting - we're running a Node.js server
  trailingSlash: true,
  images: {
    unoptimized: true
  },
  // Disable ESLint during build
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
