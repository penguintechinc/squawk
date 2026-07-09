/** @type {import('next').NextConfig} */
const nextConfig = {
  // Enable static export for Cloudflare Pages
  output: 'export',
  
  // Disable image optimization for static export
  images: {
    unoptimized: true
  },
  
  // Configure trailing slash to match static export behavior
  trailingSlash: true,
  
  // Ensure proper asset handling for Cloudflare Pages
  assetPrefix: '',
  
  // Environment variables
  env: {
    CUSTOM_VERSION: process.env.npm_package_version || '1.1.1',
  },
  
  // Disable x-powered-by header
  poweredByHeader: false,
  
  // Optimize for static export
  generateEtags: false,
  
  // Note: redirects and headers don't work with static export
  // These are handled by _redirects and _headers files instead
}

module.exports = nextConfig