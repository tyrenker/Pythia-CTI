import { useEffect, useState } from 'react'
import { Network, ExternalLink } from 'lucide-react'
import { useGraphData } from '@/api/analytics'
import { ThreatGraph } from '@/components/visualizations/ThreatGraph'
import { Breadcrumb } from '@/components/layout/Breadcrumb'

export function ThreatGraphView() {
  const { data: graphData, isLoading, error } = useGraphData()
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 })

  useEffect(() => {
    function handleResize() {
      const container = document.getElementById('graph-container')
      if (container) {
        setDimensions({
          width: container.clientWidth,
          height: container.clientHeight
        })
      }
    }
    
    window.addEventListener('resize', handleResize)
    // Initial size
    setTimeout(handleResize, 50)

    return () => window.removeEventListener('resize', handleResize)
  }, [])

  return (
    <div className="flex h-[calc(100vh-4rem)] flex-col space-y-4">
      <div className="flex items-center justify-between">
        <Breadcrumb crumbs={[{ label: 'Threat Graph', to: '/graph' }]} />
        <div className="flex items-center gap-2 border border-[#2a2a3e] bg-[#0a0a0f] px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-[#00ff88]/60">
          <Network size={12} />
          <span>Interactive Visualization</span>
        </div>
      </div>

      <div className="flex flex-1 flex-col overflow-hidden rounded-lg border border-[#2a2a3e] bg-[#0a0a0f] shadow-[0_0_20px_rgba(0,255,136,0.03)]">
        <div className="border-b border-[#2a2a3e] bg-[#12121a] px-4 py-3 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <h2 className="font-mono text-[11px] font-bold uppercase tracking-[0.2em] text-[#e0e0e0]">
              Global Threat Landscape
            </h2>
            <span className="font-mono text-[9px] text-[#6b7280]">
              {'// Actor to Malware to Sector Relations'}
            </span>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono text-[#9ca3af]">
             <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#ef4444]"></span>Actors</div>
             <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#3b82f6]"></span>Malware</div>
             <div className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#10b981]"></span>Sectors</div>
          </div>
        </div>
        
        <div id="graph-container" className="flex-1 relative bg-[#050508]">
          {isLoading && (
            <div className="absolute inset-0 flex items-center justify-center font-mono text-xs uppercase tracking-widest text-[#00ff88] animate-pulse">
              [ INITIALIZING_GRAPH_ENGINE... ]
            </div>
          )}
          {error && (
            <div className="absolute inset-0 flex items-center justify-center font-mono text-xs uppercase tracking-widest text-[#ff3366]">
              [ ERROR_LOADING_DATA ]
            </div>
          )}
          {graphData && (
            <ThreatGraph 
              data={graphData} 
              width={dimensions.width} 
              height={dimensions.height} 
            />
          )}
        </div>
      </div>
    </div>
  )
}
