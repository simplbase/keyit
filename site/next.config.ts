import { createMDX } from "fumadocs-mdx/next";
import type { NextConfig } from "next";

const withMDX = createMDX();

const nextConfig: NextConfig = {
  agentRules: false,
  reactStrictMode: true,
};

export default withMDX(nextConfig);
