import "server-only"
import { drizzle } from "drizzle-orm/neon-http"

import { serverEnv } from "@/lib/env"

function createDb() {
  // Drizzle v1 relational queries use defineRelations(); this app only uses the
  // SQL-like builder, so the schema does not need to be registered here.
  return drizzle(serverEnv().DATABASE_URL)
}

type Database = ReturnType<typeof createDb>

let cached: Database | undefined

/**
 * Lazily creates the Neon HTTP Drizzle client.
 *
 * The HTTP driver is a good fit for short-lived Next.js requests. The Python
 * worker uses a long-lived psycopg connection instead and performs direct
 * writes to the tables it owns (see docs/architecture.md).
 */
export function getDb(): Database {
  cached ??= createDb()
  return cached
}

