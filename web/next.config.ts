import type { NextConfig } from "next";

// The web app talks to the API through a same-origin rewrite (/api/*), which
// keeps cookies first-party and removes CORS from the equation. The target is
// baked at build time; compose builds with ARGUS_API_BASE=http://server:8080.
const apiBase = process.env.ARGUS_API_BASE ?? "http://127.0.0.1:8080";

const nextConfig: NextConfig = {
  output: "standalone",
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${apiBase}/:path*` }];
  },
};

export default nextConfig;
