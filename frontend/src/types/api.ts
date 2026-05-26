// TypeScript interfaces mirroring Pydantic response models

export interface HealthResponse {
  status: string
  version: string
}

// ── Threats ──────────────────────────────────────────────────────────────────

export interface ThreatSummary {
  id: string
  title: string | null
  url: string | null
  publication_date: string | null
  tlp: string
  status: string
  actors: string[]
  ttps: string[]
  ioc_count: number
}

export interface ThreatDetail extends ThreatSummary {
  summary: string | null
  sectors_targeted: string[]
  geographies_targeted: string[]
  killchain_phases: string[]
  parsed_data: Record<string, unknown>
}

// ── Actors ───────────────────────────────────────────────────────────────────

export interface ActorSummary {
  id: string
  name: string
  aliases: string[]
  country_code: string | null
  sponsor_type: string
  motivations: string[]
  sectors_targeted: string[]
  sophistication: number | null
  attck_group_id: string | null
  tlp: string
  source: string
}

export interface TTPSummary {
  technique_id: string
  name: string | null
  tactics: string[]
  use_note: string | null
}

export interface ActorDetail extends ActorSummary {
  description: string | null
  first_observed: string | null
  geographies_targeted: string[]
  infrastructure_patterns: string | null
  references: string[]
  ttps: TTPSummary[]
}

export interface KillChainView {
  actor_id: string
  actor_name: string
  phases: Record<string, TTPSummary[]>
}

export interface DiamondModel {
  adversary: {
    name: string
    aliases: string[]
    country: string | null
    sponsor_type: string
  }
  capability: {
    technique_count: number
    sample_techniques: string[]
  }
  infrastructure: {
    patterns: string | null
    known_tool_techniques: string[]
  }
  victim: {
    sectors: string[]
    geographies: string[]
  }
}

// ── TTPs ─────────────────────────────────────────────────────────────────────

export interface AttckTechnique {
  technique_id: string
  name: string
  tactics: string[]
  domain: string
  description: string | null
  data_sources: string[]
  is_subtechnique: boolean
  parent_id: string | null
  platforms: string[]
  detection: string | null
  url: string | null
}

export interface HuntQuery {
  id: string
  title: string
  technique_ids: string[]
  severity: string
  tags: string[]
  splunk_spl: string | null
  elastic_kql: string | null
  sentinel_kql: string | null
  sigma_yaml: string | null
  rule_type: string
}

// ── IoCs ─────────────────────────────────────────────────────────────────────

export interface IocSummary {
  id: string
  type: string
  value: string
  pyramid_tier: string
  confidence_source: string   // A-F admiralty source rating
  confidence_info: string     // 1-6 admiralty info rating
  tlp: string
  actor_id: string | null
  actor_name?: string | null
  context: string | null
  source_url: string | null
  technique_ids: string[]
}

export type IocDetail = IocSummary

// ── Rules ────────────────────────────────────────────────────────────────────

export interface DetectionRule {
  id: string
  title: string
  rule_type: string
  severity: string | null
  status: string | null
  source_url: string | null
  technique_ids: string[]
  // Only present on the detail endpoint:
  content?: string
  actor_ids?: string[]
}

export interface HuntQueriesResponse {
  technique_id: string
  technique_name: string | null
  rules: HuntQuery[]
}

// ── Analytics ────────────────────────────────────────────────────────────────

export interface TechniqueGap {
  technique_id: string
  name: string | null
  tactics: string[]
  actor_count: number
}

export interface CoverageReport {
  observed_technique_count: number
  covered_technique_count: number
  coverage_pct: number
  uncovered_count: number
  rule_count: number
  summary: string
  top_uncovered: TechniqueGap[]
  top_covered: TechniqueGap[]
}

export interface SectorRow {
  sector: string
  actor_count: number
  nation_state_count: number
  financially_motivated_count: number
  hacktivist_count: number
  top_actors: string[]
}

export interface SectorReport {
  total_sectors: number
  total_actors_with_sector_data: number
  rows: SectorRow[]
}

// ── AI Threats ───────────────────────────────────────────────────────────────

export interface OWASPItem {
  id: string
  rank: number
  name: string
  description: string | null
  atlas_ids: string[]
  cwe_ids: string[]
  mitigations: string[]
  detection_notes: string | null
  examples: string[]
  references: string[]
}

export interface AIIncident {
  id: string
  date: string | null
  title: string
  description: string | null
  owasp_ids: string[]
  atlas_ids: string[]
  impact: string | null
  source_url: string | null
}

export interface AtlasEntry {
  technique_id: string
  name: string
  tactics: string[]
  subtechniques: string[]
  description: string | null
}

export interface AIThreatsOverview {
  atlas_count: number
  owasp_count: number
  incident_count: number
}

// ── Malware Families ─────────────────────────────────────────────────────────

export interface MalwareFamily {
  id: string
  name: string
  aliases: string[]
  family_type: string | null
  description: string | null
  actor_ids: string[]
  rule_ids: string[]
  references: string[]
  source: string
  source_url: string | null
  malpedia_slug: string | null
  created_at: string | null
}

// ── Watchlist ────────────────────────────────────────────────────────────────

export interface WatchlistSubscription {
  id: string
  name: string
  webhook_url: string
  webhook_type: string
  filter_actor: string | null
  filter_ttp: string | null
  filter_sector: string | null
  created_at: string
}

export interface ParseResponse {
  report_id: string
  title: string | null
  tlp: string
  status: string
}
