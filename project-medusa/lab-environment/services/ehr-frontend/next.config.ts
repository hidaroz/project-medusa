import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // For EHR system, we want server-side rendering, not static export
  // output: 'export',  // Commented out for server mode
  trailingSlash: true,
  images: {
    unoptimized: true
  },
  // No basePath needed for EHR system
  // basePath: process.env.NODE_ENV === 'production' ? '/project-medusa' : '',
  // assetPrefix: process.env.NODE_ENV === 'production' ? '/project-medusa/' : '',
};

export default nextConfig;
