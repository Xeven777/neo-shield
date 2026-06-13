import { config } from "dotenv"
import { defineConfig } from "drizzle-kit"

config({ path: ".env.local", quiet: true })
config({ path: ".env", quiet: true })

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL is required for drizzle-kit. Copy .env.example to .env.local and set your Neon connection string."
  )
}

export default defineConfig({
  dialect: "postgresql",
  schema: "./lib/db/schema.ts",
  out: "./drizzle",
  dbCredentials: { url: process.env.DATABASE_URL },
  verbose: true,
})
