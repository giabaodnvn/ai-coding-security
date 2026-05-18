/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  async rewrites() {
    // BACKEND_URL is server-side (used by Next.js proxy, not baked into client bundle).
    // In Docker Compose set BACKEND_URL=http://backend:8080; locally defaults to localhost.
    const apiUrl = process.env.BACKEND_URL || "http://localhost:8080";
    return [{ source: "/api/:path*", destination: `${apiUrl}/api/:path*` }];
  },
};
export default nextConfig;
