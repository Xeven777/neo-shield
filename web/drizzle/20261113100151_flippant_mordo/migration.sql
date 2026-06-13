CREATE TYPE "asset_type" AS ENUM('repository', 'domain', 'endpoint', 'network', 'aws_account');--> statement-breakpoint
CREATE TYPE "integration_provider" AS ENUM('github', 'wazuh', 'aws', 'worker');--> statement-breakpoint
CREATE TYPE "integration_status" AS ENUM('pending', 'connected', 'disconnected', 'error');--> statement-breakpoint
CREATE TYPE "project_criticality" AS ENUM('low', 'medium', 'high');--> statement-breakpoint
CREATE TYPE "project_environment" AS ENUM('development', 'staging', 'production', 'lab');--> statement-breakpoint
CREATE TYPE "scan_job_status" AS ENUM('queued', 'leased', 'running', 'completed', 'failed', 'cancelled');--> statement-breakpoint
CREATE TYPE "scan_type" AS ENUM('repository', 'domain', 'endpoint', 'network', 'aws');--> statement-breakpoint
CREATE TYPE "worker_status" AS ENUM('active', 'revoked');--> statement-breakpoint
CREATE TYPE "workspace_role" AS ENUM('owner', 'admin', 'member');--> statement-breakpoint
CREATE TABLE "account" (
	"id" text PRIMARY KEY,
	"account_id" text NOT NULL,
	"provider_id" text NOT NULL,
	"user_id" text NOT NULL,
	"access_token" text,
	"refresh_token" text,
	"id_token" text,
	"access_token_expires_at" timestamp with time zone,
	"refresh_token_expires_at" timestamp with time zone,
	"scope" text,
	"password" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "asset" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"project_id" uuid NOT NULL,
	"type" "asset_type" NOT NULL,
	"display_name" text NOT NULL,
	"identifier" text NOT NULL,
	"config" jsonb DEFAULT '{}' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "asset_project_id_type_identifier_key" UNIQUE("project_id","type","identifier")
);
--> statement-breakpoint
CREATE TABLE "audit_log" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid,
	"actor_user_id" text,
	"action" text NOT NULL,
	"target_type" text,
	"target_id" text,
	"metadata" jsonb DEFAULT '{}' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "integration" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"project_id" uuid,
	"provider" "integration_provider" NOT NULL,
	"display_name" text NOT NULL,
	"status" "integration_status" DEFAULT 'pending'::"integration_status" NOT NULL,
	"metadata" jsonb DEFAULT '{}' NOT NULL,
	"last_synced_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "project" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"environment" "project_environment" DEFAULT 'development'::"project_environment" NOT NULL,
	"criticality" "project_criticality" DEFAULT 'medium'::"project_criticality" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "project_workspace_id_name_key" UNIQUE("workspace_id","name")
);
--> statement-breakpoint
CREATE TABLE "scan_job" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"asset_id" uuid NOT NULL,
	"type" "scan_type" NOT NULL,
	"status" "scan_job_status" DEFAULT 'queued'::"scan_job_status" NOT NULL,
	"idempotency_key" text NOT NULL UNIQUE,
	"parameters" jsonb DEFAULT '{}' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"max_attempts" integer DEFAULT 3 NOT NULL,
	"leased_by_worker_id" uuid,
	"lease_expires_at" timestamp with time zone,
	"available_at" timestamp with time zone DEFAULT now() NOT NULL,
	"started_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"error_summary" text,
	"created_by_user_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "session" (
	"id" text PRIMARY KEY,
	"expires_at" timestamp with time zone NOT NULL,
	"token" text NOT NULL UNIQUE,
	"ip_address" text,
	"user_agent" text,
	"user_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "user" (
	"id" text PRIMARY KEY,
	"name" text NOT NULL,
	"email" text NOT NULL UNIQUE,
	"email_verified" boolean DEFAULT false NOT NULL,
	"image" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "verification" (
	"id" text PRIMARY KEY,
	"identifier" text NOT NULL,
	"value" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "worker" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"name" text NOT NULL,
	"token_hash" text NOT NULL UNIQUE,
	"token_prefix" text NOT NULL,
	"scopes" jsonb DEFAULT '[]' NOT NULL,
	"status" "worker_status" DEFAULT 'active'::"worker_status" NOT NULL,
	"version" text,
	"hostname" text,
	"last_seen_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "workspace" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"name" text NOT NULL,
	"slug" text NOT NULL UNIQUE,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "workspace_member" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"user_id" text NOT NULL,
	"role" "workspace_role" DEFAULT 'member'::"workspace_role" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "workspace_member_workspace_id_user_id_key" UNIQUE("workspace_id","user_id")
);
--> statement-breakpoint
CREATE INDEX "asset_project_id_idx" ON "asset" ("project_id");--> statement-breakpoint
CREATE INDEX "audit_log_workspace_id_idx" ON "audit_log" ("workspace_id");--> statement-breakpoint
CREATE INDEX "integration_workspace_id_idx" ON "integration" ("workspace_id");--> statement-breakpoint
CREATE INDEX "project_workspace_id_idx" ON "project" ("workspace_id");--> statement-breakpoint
CREATE INDEX "scan_job_claim_idx" ON "scan_job" ("status","available_at");--> statement-breakpoint
CREATE INDEX "scan_job_workspace_id_idx" ON "scan_job" ("workspace_id");--> statement-breakpoint
CREATE INDEX "scan_job_asset_id_idx" ON "scan_job" ("asset_id");--> statement-breakpoint
CREATE INDEX "worker_workspace_id_idx" ON "worker" ("workspace_id");--> statement-breakpoint
CREATE INDEX "workspace_member_user_id_idx" ON "workspace_member" ("user_id");--> statement-breakpoint
ALTER TABLE "account" ADD CONSTRAINT "account_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "asset" ADD CONSTRAINT "asset_project_id_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "project"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_actor_user_id_user_id_fkey" FOREIGN KEY ("actor_user_id") REFERENCES "user"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "integration" ADD CONSTRAINT "integration_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "integration" ADD CONSTRAINT "integration_project_id_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "project"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "project" ADD CONSTRAINT "project_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "scan_job" ADD CONSTRAINT "scan_job_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "scan_job" ADD CONSTRAINT "scan_job_asset_id_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "asset"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "scan_job" ADD CONSTRAINT "scan_job_leased_by_worker_id_worker_id_fkey" FOREIGN KEY ("leased_by_worker_id") REFERENCES "worker"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "scan_job" ADD CONSTRAINT "scan_job_created_by_user_id_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "user"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "session" ADD CONSTRAINT "session_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "worker" ADD CONSTRAINT "worker_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "workspace_member" ADD CONSTRAINT "workspace_member_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "workspace_member" ADD CONSTRAINT "workspace_member_user_id_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE CASCADE;