import { Grid3x3 } from 'lucide-react'
import { useCoverage } from '@/api/analytics'
import { MitreHeatmap } from '@/components/visualizations/MitreHeatmap'
import { Breadcrumb } from '@/components/layout/Breadcrumb'

export function MitreHeatmapView() {
  const { data: coverage, isLoading, error } = useCoverage(30) // Request more for full page

  const heatmapTechniques = []
  if (coverage) {
    coverage.top_covered.forEach(t => heatmapTechniques.push({
        id: t.technique_id,
        name: t.name || t.technique_id,
        tactic: t.tactics[0] || 'Unknown',
        frequency: t.actor_count
    }))
    coverage.top_uncovered.forEach(t => heatmapTechniques.push({
        id: t.technique_id,
        name: t.name || t.technique_id,
        tactic: t.tactics[0] || 'Unknown',
        frequency: t.actor_count
    }))
  }

  return (
    <div className="flex flex-col space-y-4">
      <div className="flex items-center justify-between">
        <Breadcrumb crumbs={[{ label: 'MITRE ATT&CK Heatmap', to: '/heatmap' }]} />
        <div className="flex items-center gap-2 border border-[#2a2a3e] bg-[#0a0a0f] px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-[#00ff88]/60">
          <Grid3x3 size={12} />
          <span>Matrix Coverage</span>
        </div>
      </div>

      <div className="flex flex-col overflow-hidden rounded-lg border border-[#2a2a3e] bg-[#0a0a0f] shadow-[0_0_20px_rgba(255,51,102,0.03)]">
        <div className="border-b border-[#2a2a3e] bg-[#12121a] px-4 py-3">
          <h2 className="font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-[#e0e0e0]">
            ATT&CK TTP Heatmap
          </h2>
          <p className="mt-1 font-mono text-[9px] text-[#6b7280]">
            {'// Visualizes TTP frequency mapped across the 14 core MITRE ATT&CK tactics.'}
          </p>
        </div>
        
        <div className="p-4 bg-[#050508] relative min-h-[600px]">
          {isLoading && (
            <div className="absolute inset-0 flex items-center justify-center font-mono text-xs uppercase tracking-widest text-[#00ff88] animate-pulse">
              [ AGGREGATING_MATRIX... ]
            </div>
          )}
          {error && (
            <div className="absolute inset-0 flex items-center justify-center font-mono text-xs uppercase tracking-widest text-[#ff3366]">
              [ ERROR_LOADING_DATA ]
            </div>
          )}
          {coverage && (
            <MitreHeatmap techniques={heatmapTechniques} />
          )}
        </div>
      </div>
    </div>
  )
}
