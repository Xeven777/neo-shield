CREATE TYPE "finding_confidence" AS ENUM('low', 'medium', 'high');--> statement-breakpoint
CREATE TYPE "finding_severity" AS ENUM('critical', 'high', 'medium', 'low', 'informational');--> statement-breakpoint
CREATE TYPE "finding_source" AS ENUM('github', 'domain', 'wazuh', 'network', 'aws');--> statement-breakpoint
CREATE TYPE "finding_status" AS ENUM('open', 'acknowledged', 'in_progress', 'resolved', 'accepted_risk', 'false_positive');--> statement-breakpoint
CREATE TYPE "scan_run_status" AS ENUM('running', 'completed', 'partial', 'failed');--> statement-breakpoint
CREATE TABLE "finding" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"asset_id" uuid NOT NULL,
	"source" "finding_source" NOT NULL,
	"source_tool" text NOT NULL,
	"source_rule_id" text,
	"stable_key" text NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"category" text NOT NULL,
	"severity" "finding_severity" NOT NULL,
	"confidence" "finding_confidence",
	"cve_id" text,
	"cvss_score" real,
	"remediation" text,
	"references" jsonb DEFAULT '[]' NOT NULL,
	"status" "finding_status" DEFAULT 'open'::"finding_status" NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"resolved_at" timestamp with time zone,
	"occurrence_count" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "finding_asset_id_stable_key_key" UNIQUE("asset_id","stable_key")
);
--> statement-breakpoint
CREATE TABLE "finding_evidence" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"finding_id" uuid NOT NULL CONSTRAINT "finding_evidence_finding_id_key" UNIQUE,
	"scan_run_id" uuid,
	"file_path" text,
	"package_name" text,
	"package_version" text,
	"fixed_version" text,
	"evidence" jsonb DEFAULT '{}' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "finding_status_event" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"finding_id" uuid NOT NULL,
	"from_status" "finding_status",
	"to_status" "finding_status" NOT NULL,
	"actor_user_id" text,
	"note" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "github_installation" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL CONSTRAINT "github_installation_workspace_id_key" UNIQUE,
	"installation_id" text NOT NULL CONSTRAINT "github_installation_installation_id_key" UNIQUE,
	"account_login" text NOT NULL,
	"account_type" text NOT NULL,
	"installed_by_user_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "github_repository" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"installation_id" text NOT NULL,
	"github_id" text NOT NULL,
	"owner" text NOT NULL,
	"name" text NOT NULL,
	"full_name" text NOT NULL,
	"default_branch" text NOT NULL,
	"private" boolean DEFAULT false NOT NULL,
	"project_id" uuid,
	"asset_id" uuid,
	"selected" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "github_repository_workspace_id_github_id_key" UNIQUE("workspace_id","github_id")
);
--> statement-breakpoint
CREATE TABLE "scan_run" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"asset_id" uuid NOT NULL,
	"scan_job_id" uuid,
	"scanner" text DEFAULT 'repository' NOT NULL,
	"status" "scan_run_status" DEFAULT 'running'::"scan_run_status" NOT NULL,
	"target_snapshot" jsonb DEFAULT '{}' NOT NULL,
	"tools" jsonb DEFAULT '[]' NOT NULL,
	"finding_count" integer DEFAULT 0 NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone,
	"error_summary" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "finding_workspace_id_status_idx" ON "finding" ("workspace_id","status");--> statement-breakpoint
CREATE INDEX "finding_workspace_id_severity_idx" ON "finding" ("workspace_id","severity");--> statement-breakpoint
CREATE INDEX "finding_project_id_idx" ON "finding" ("project_id");--> statement-breakpoint
CREATE INDEX "finding_last_seen_at_idx" ON "finding" ("last_seen_at");--> statement-breakpoint
CREATE INDEX "finding_status_event_finding_id_idx" ON "finding_status_event" ("finding_id");--> statement-breakpoint
CREATE INDEX "github_repository_workspace_id_idx" ON "github_repository" ("workspace_id");--> statement-breakpoint
CREATE INDEX "scan_run_workspace_id_idx" ON "scan_run" ("workspace_id");--> statement-breakpoint
CREATE INDEX "scan_run_asset_id_started_at_idx" ON "scan_run" ("asset_id","started_at");--> statement-breakpoint
ALTER TABLE "finding" ADD CONSTRAINT "finding_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "finding" ADD CONSTRAINT "finding_project_id_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "project"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "finding" ADD CONSTRAINT "finding_asset_id_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "asset"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "finding_evidence" ADD CONSTRAINT "finding_evidence_finding_id_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "finding"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "finding_evidence" ADD CONSTRAINT "finding_evidence_scan_run_id_scan_run_id_fkey" FOREIGN KEY ("scan_run_id") REFERENCES "scan_run"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "finding_status_event" ADD CONSTRAINT "finding_status_event_finding_id_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "finding"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "finding_status_event" ADD CONSTRAINT "finding_status_event_actor_user_id_user_id_fkey" FOREIGN KEY ("actor_user_id") REFERENCES "user"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "github_installation" ADD CONSTRAINT "github_installation_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "github_installation" ADD CONSTRAINT "github_installation_installed_by_user_id_user_id_fkey" FOREIGN KEY ("installed_by_user_id") REFERENCES "user"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "github_repository" ADD CONSTRAINT "github_repository_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "github_repository" ADD CONSTRAINT "github_repository_project_id_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "project"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "github_repository" ADD CONSTRAINT "github_repository_asset_id_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "asset"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "scan_run" ADD CONSTRAINT "scan_run_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "scan_run" ADD CONSTRAINT "scan_run_project_id_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "project"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "scan_run" ADD CONSTRAINT "scan_run_asset_id_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "asset"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "scan_run" ADD CONSTRAINT "scan_run_scan_job_id_scan_job_id_fkey" FOREIGN KEY ("scan_job_id") REFERENCES "scan_job"("id") ON DELETE SET NULL;