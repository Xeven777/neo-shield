import type { NextConfig } from "next"

const nextConfig: NextConfig = {
  // Required for the minimal Docker runtime image.
  output: "standalone",
}

export default nextConfig
