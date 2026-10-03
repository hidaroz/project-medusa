/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  // Disable static page generation errors for dynamic dashboard
  // This is a real-time monitoring dashboard that requires dynamic rendering
  experimental: {
    missingSuspenseWithCSRBailout: false,
  },
};

module.exports = nextConfig;

