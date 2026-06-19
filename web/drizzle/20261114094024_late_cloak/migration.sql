CREATE TYPE "ai_target_type" AS ENUM('finding', 'incident');--> statement-breakpoint
CREATE TYPE "remediation_status" AS ENUM('planned', 'in_progress', 'fixed', 'verified');--> statement-breakpoint
ALTER TYPE "incident_event_type" ADD VALUE 'reopened';--> statement-breakpoint
CREATE TABLE "ai_explanation" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"target_type" "ai_target_type" NOT NULL,
	"finding_id" uuid,
	"incident_id" uuid,
	"provider" text NOT NULL,
	"model" text NOT NULL,
	"input_digest" text NOT NULL,
	"output" text NOT NULL,
	"created_by_user_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "finding_note" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"finding_id" uuid NOT NULL,
	"actor_user_id" text,
	"body" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "incident_security_event" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"incident_id" uuid NOT NULL,
	"security_event_id" uuid NOT NULL,
	"reason" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "incident_security_event_incident_event_key" UNIQUE("incident_id","security_event_id")
);
--> statement-breakpoint
CREATE TABLE "remediation" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"finding_id" uuid NOT NULL,
	"recommendation" text NOT NULL,
	"status" "remediation_status" DEFAULT 'planned'::"remediation_status" NOT NULL,
	"owner_user_id" text,
	"created_by_user_id" text,
	"verified_scan_run_id" uuid,
	"verified_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "remediation_event" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"remediation_id" uuid NOT NULL,
	"from_status" "remediation_status",
	"to_status" "remediation_status" NOT NULL,
	"actor_user_id" text,
	"note" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "finding" ADD COLUMN "owner_user_id" text;--> statement-breakpoint
ALTER TABLE "incident" ADD COLUMN "owner_user_id" text;--> statement-breakpoint
ALTER TABLE "incident" ADD COLUMN "auto_resolved_at" timestamp with time zone;--> statement-breakpoint
CREATE INDEX "ai_explanation_workspace_id_idx" ON "ai_explanation" ("workspace_id");--> statement-breakpoint
CREATE INDEX "ai_explanation_finding_id_idx" ON "ai_explanation" ("finding_id");--> statement-breakpoint
CREATE INDEX "ai_explanation_incident_id_idx" ON "ai_explanation" ("incident_id");--> statement-breakpoint
CREATE INDEX "finding_note_finding_id_idx" ON "finding_note" ("finding_id");--> statement-breakpoint
CREATE INDEX "incident_security_event_event_id_idx" ON "incident_security_event" ("security_event_id");--> statement-breakpoint
CREATE INDEX "remediation_workspace_id_status_idx" ON "remediation" ("workspace_id","status");--> statement-breakpoint
CREATE INDEX "remediation_finding_id_idx" ON "remediation" ("finding_id");--> statement-breakpoint
CREATE INDEX "remediation_event_remediation_id_idx" ON "remediation_event" ("remediation_id");--> statement-breakpoint
ALTER TABLE "ai_explanation" ADD CONSTRAINT "ai_explanation_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "ai_explanation" ADD CONSTRAINT "ai_explanation_finding_id_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "finding"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "ai_explanation" ADD CONSTRAINT "ai_explanation_incident_id_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incident"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "ai_explanation" ADD CONSTRAINT "ai_explanation_created_by_user_id_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "user"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "finding" ADD CONSTRAINT "finding_owner_user_id_user_id_fkey" FOREIGN KEY ("owner_user_id") REFERENCES "user"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "finding_note" ADD CONSTRAINT "finding_note_finding_id_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "finding"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "finding_note" ADD CONSTRAINT "finding_note_actor_user_id_user_id_fkey" FOREIGN KEY ("actor_user_id") REFERENCES "user"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "incident" ADD CONSTRAINT "incident_owner_user_id_user_id_fkey" FOREIGN KEY ("owner_user_id") REFERENCES "user"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "incident_security_event" ADD CONSTRAINT "incident_security_event_incident_id_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incident"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "incident_security_event" ADD CONSTRAINT "incident_security_event_lsI9qTyw0ryk_fkey" FOREIGN KEY ("security_event_id") REFERENCES "security_event"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "remediation" ADD CONSTRAINT "remediation_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "remediation" ADD CONSTRAINT "remediation_finding_id_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "finding"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "remediation" ADD CONSTRAINT "remediation_owner_user_id_user_id_fkey" FOREIGN KEY ("owner_user_id") REFERENCES "user"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "remediation" ADD CONSTRAINT "remediation_created_by_user_id_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "user"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "remediation" ADD CONSTRAINT "remediation_verified_scan_run_id_scan_run_id_fkey" FOREIGN KEY ("verified_scan_run_id") REFERENCES "scan_run"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "remediation_event" ADD CONSTRAINT "remediation_event_remediation_id_remediation_id_fkey" FOREIGN KEY ("remediation_id") REFERENCES "remediation"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "remediation_event" ADD CONSTRAINT "remediation_event_actor_user_id_user_id_fkey" FOREIGN KEY ("actor_user_id") REFERENCES "user"("id") ON DELETE SET NULL;