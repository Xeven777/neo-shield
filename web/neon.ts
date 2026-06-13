import { defineConfig } from "@neon/config/v1"

export default defineConfig({
  // Declare your Neon services here
  // Neon Auth is disabled: authentication is handled by the app's own
  // Better Auth + Drizzle setup in the public schema.
  auth: false,
  // Branch policy: per-branch tuning
  branch: (branch) => {
    if (branch.isDefault) {
      // Default branch: no overrides, uses project defaults
      return {}
    }
    if (!branch.exists) {
      // New non-default branches: auto-expire
      // Run `neon checkout <name>` to create a new branch with these settings
      return { ttl: "7d" }
    }
    // Existing branch: no changes
    return {}
  },
})
