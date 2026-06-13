CREATE TABLE "endpoint_agent" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"asset_id" uuid NOT NULL,
	"provider" text DEFAULT 'wazuh' NOT NULL,
	"external_id" text NOT NULL,
	"name" text NOT NULL,
	"ip_address" text,
	"os_name" text,
	"os_version" text,
	"os_platform" text,
	"architecture" text,
	"agent_version" text,
	"status" text DEFAULT 'unknown' NOT NULL,
	"last_seen_at" timestamp with time zone,
	"config" jsonb DEFAULT '{}' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "endpoint_agent_asset_id_provider_external_id_key" UNIQUE("asset_id","provider","external_id")
);
--> statement-breakpoint
CREATE TABLE "network_host" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"asset_id" uuid NOT NULL,
	"address" text NOT NULL,
	"hostname" text,
	"mac_address" text,
	"vendor" text,
	"status" text DEFAULT 'active' NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_scan_run_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "network_host_asset_id_address_key" UNIQUE("asset_id","address")
);
--> statement-breakpoint
CREATE TABLE "network_service" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"host_id" uuid NOT NULL,
	"asset_id" uuid NOT NULL,
	"port" integer NOT NULL,
	"protocol" text DEFAULT 'tcp' NOT NULL,
	"service_name" text,
	"product" text,
	"version" text,
	"extra_info" text,
	"cpe" text,
	"status" text DEFAULT 'active' NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_scan_run_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "network_service_host_id_port_protocol_key" UNIQUE("host_id","port","protocol")
);
--> statement-breakpoint
CREATE TABLE "security_event" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"workspace_id" uuid NOT NULL,
	"project_id" uuid NOT NULL,
	"asset_id" uuid NOT NULL,
	"finding_id" uuid,
	"source" "finding_source" NOT NULL,
	"source_tool" text NOT NULL,
	"external_id" text NOT NULL,
	"event_time" timestamp with time zone NOT NULL,
	"rule_id" text,
	"rule_level" integer,
	"severity" "finding_severity" NOT NULL,
	"category" text NOT NULL,
	"title" text NOT NULL,
	"description" text NOT NULL,
	"agent_id" text,
	"agent_name" text,
	"source_ip" text,
	"evidence" jsonb DEFAULT '{}' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "security_event_workspace_id_source_tool_external_id_key" UNIQUE("workspace_id","source_tool","external_id")
);
--> statement-breakpoint
ALTER TABLE "integration" ADD COLUMN "sync_cursor" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "integration" ADD COLUMN "last_error" text;--> statement-breakpoint
CREATE INDEX "endpoint_agent_workspace_id_idx" ON "endpoint_agent" ("workspace_id");--> statement-breakpoint
CREATE INDEX "endpoint_agent_provider_external_id_idx" ON "endpoint_agent" ("provider","external_id");--> statement-breakpoint
CREATE INDEX "network_host_workspace_id_idx" ON "network_host" ("workspace_id");--> statement-breakpoint
CREATE INDEX "network_host_asset_id_status_idx" ON "network_host" ("asset_id","status");--> statement-breakpoint
CREATE INDEX "network_service_asset_id_idx" ON "network_service" ("asset_id");--> statement-breakpoint
CREATE INDEX "network_service_status_idx" ON "network_service" ("status");--> statement-breakpoint
CREATE INDEX "security_event_workspace_id_event_time_idx" ON "security_event" ("workspace_id","event_time");--> statement-breakpoint
CREATE INDEX "security_event_asset_id_event_time_idx" ON "security_event" ("asset_id","event_time");--> statement-breakpoint
CREATE INDEX "security_event_workspace_id_severity_idx" ON "security_event" ("workspace_id","severity");--> statement-breakpoint
ALTER TABLE "endpoint_agent" ADD CONSTRAINT "endpoint_agent_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "endpoint_agent" ADD CONSTRAINT "endpoint_agent_asset_id_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "asset"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "network_host" ADD CONSTRAINT "network_host_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "network_host" ADD CONSTRAINT "network_host_asset_id_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "asset"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "network_host" ADD CONSTRAINT "network_host_last_scan_run_id_scan_run_id_fkey" FOREIGN KEY ("last_scan_run_id") REFERENCES "scan_run"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "network_service" ADD CONSTRAINT "network_service_host_id_network_host_id_fkey" FOREIGN KEY ("host_id") REFERENCES "network_host"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "network_service" ADD CONSTRAINT "network_service_asset_id_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "asset"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "network_service" ADD CONSTRAINT "network_service_last_scan_run_id_scan_run_id_fkey" FOREIGN KEY ("last_scan_run_id") REFERENCES "scan_run"("id") ON DELETE SET NULL;--> statement-breakpoint
ALTER TABLE "security_event" ADD CONSTRAINT "security_event_workspace_id_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspace"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "security_event" ADD CONSTRAINT "security_event_project_id_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "project"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "security_event" ADD CONSTRAINT "security_event_asset_id_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "asset"("id") ON DELETE CASCADE;--> statement-breakpoint
ALTER TABLE "security_event" ADD CONSTRAINT "security_event_finding_id_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "finding"("id") ON DELETE SET NULL;