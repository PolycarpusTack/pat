/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    appDir: true,
  },
  typescript: {
    // Type checking is handled by our CI/CD pipeline
    ignoreBuildErrors: false,
  },
  eslint: {
    // ESLint is handled by our CI/CD pipeline
    ignoreDuringBuilds: false,
  },
  env: {
    GRAPHQL_ENDPOINT: process.env.GRAPHQL_ENDPOINT || 'http://localhost:4000/graphql',
    GRAPHQL_WS_ENDPOINT: process.env.GRAPHQL_WS_ENDPOINT || 'ws://localhost:4000/graphql',
  },
  async redirects() {
    return [
      {
        source: '/',
        destination: '/dashboard',
        permanent: false,
      },
    ];
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
        ],
      },
    ];
  },
  webpack: (config, { dev, isServer }) => {
    // Bundle analyzer
    if (process.env.ANALYZE === 'true') {
      const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer');
      config.plugins.push(
        new BundleAnalyzerPlugin({
          analyzerMode: 'static',
          openAnalyzer: false,
        })
      );
    }

    return config;
  },
};

module.exports = nextConfig;