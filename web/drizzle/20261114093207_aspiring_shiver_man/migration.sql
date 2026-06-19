CREATE TYPE "incident_event_type" AS ENUM('created', 'signal_changed', 'status_changed', 'note', 'auto_resolved');--> statement-breakpoint
CREATE TYPE "incident_status" AS ENUM('new', 'investigating', 'contained', 'resolved', 'closed');--> statement-breakpoint
CREATE TYPE "score_scope" AS ENUM('workspace', 'project');--> statement-breakpoint
CREATE TABLE "incident" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"correlation_rule" text NOT NULL,
	"correlation_key" text NOT NULL,
	"title" text NOT NULL,
	"summary" text NOT NULL,
	"reason" text NOT NULL,
	"severity" "finding_severity" NOT NULL,
	"status" "incident_status" DEFAULT 'new'::"incident_status" NOT NULL,
	"evidence" jsonb DEFAULT '{}' NOT NULL,
	"first_detected_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_detected_at" timestamp with time zone DEFAULT now() NOT NULL,
	"resolved_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "incident_workspace_rule_key_key" UNIQUE("workspace_id","correlation_rule","correlation_key")
);
--> statement-breakpoint
CREATE TABLE "incident_event" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"incident_id" uuid NOT NULL,
	"type" "incident_event_type" NOT NULL,
	"from_status" "incident_status",
	"to_status" "incident_status",
	"actor_user_id" text,
	"note" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "incident_finding" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"incident_id" uuid NOT NULL,
	"finding_id" uuid NOT NULL,
	"reason" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "incident_finding_incident_finding_key" UNIQUE("incident_id","finding_id")
);
--> statement-breakpoint
CREATE TABLE "score_snapshot" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"project_id" uuid,
	"scope" "score_scope" NOT NULL,
	"score" integer NOT NULL,
	"risk_points" real NOT NULL,
	"open_finding_count" integer DEFAULT 0 NOT NULL,
	"algorithm_version" text NOT NULL,
	"breakdown" jsonb DEFAULT '{"bySeverity":{"critical":{"count":0,"points":0},"high":{"count":0,"points":0},"medium":{"count":0,"points":0},"low":{"count":0,"points":0},"informational":{"count":0,"points":0}},"byAssetType":{},"byExposure":{}}' NOT NULL,
	"computed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "incident_workspace_status_idx" ON "incident" ("workspace_id","status");--> statement-breakpoint
CREATE INDEX "incident_workspace_last_detected_idx" ON "incident" ("workspace_id","last_detected_at");--> statement-breakpoint
CREATE INDEX "incident_project_id_idx" ON "incident" ("project_id");--> statement-breakpoint
CREATE INDEX "incident_event_incident_id_idx" ON "incident_event" ("incident_id");--> statement-breakpoint
CREATE INDEX "incident_finding_finding_id_idx" ON "incident_finding" ("finding_id");--> statement-breakpoint
CREATE INDEX "score_snapshot_workspace_scope_idx" ON "score_snapshot" ("workspace_id","project_id","computed_at");--> statement-breakpoint
ALTER TABLE "incident" ADD CONSTRAINT "incident_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "incident" ADD CONSTRAINT "incident_project_id_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "project"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "incident_event" ADD CONSTRAINT "incident_event_incident_id_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incident"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "incident_event" ADD CONSTRAINT "incident_event_actor_user_id_user_id_fkey" FOREIGN KEY ("actor_user_id") REFERENCES "user"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "incident_finding" ADD CONSTRAINT "incident_finding_incident_id_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incident"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "incident_finding" ADD CONSTRAINT "incident_finding_finding_id_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "finding"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "score_snapshot" ADD CONSTRAINT "score_snapshot_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "score_snapshot" ADD CONSTRAINT "score_snapshot_project_id_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "project"("id") ON DELETE CASCADE;