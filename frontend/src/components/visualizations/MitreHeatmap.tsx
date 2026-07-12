import { useMemo } from "react";
import { cn } from "@/lib/utils";

export interface MitreTechnique {
  id: string; // e.g., T1548
  name: string;
  tactic: string;
  frequency: number;
}

interface MitreHeatmapProps {
  techniques: MitreTechnique[];
  maxFrequency?: number;
}

// All 14 Core MITRE ATT&CK Tactics
const TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact"
];

export function MitreHeatmap({ techniques, maxFrequency }: MitreHeatmapProps) {
  // Find the max frequency to relative-color cells
  const computedMax = useMemo(() => {
    if (maxFrequency) return maxFrequency;
    return Math.max(...techniques.map(t => t.frequency), 1);
  }, [techniques, maxFrequency]);

  // Group techniques by tactic
  const groupedTechniques = useMemo(() => {
    const grouped = new Map<string, MitreTechnique[]>();
    TACTICS.forEach(tactic => grouped.set(tactic, []));
    
    techniques.forEach(t => {
      // Find case-insensitive match or fallback
      const foundTactic = TACTICS.find(tac => tac.toLowerCase().replace(/ /g, '') === t.tactic.toLowerCase().replace(/ /g, ''));
      if (foundTactic) {
          grouped.get(foundTactic)?.push(t);
      }
    });

    // Sort techniques within each tactic by frequency (highest first)
    grouped.forEach(techs => techs.sort((a, b) => b.frequency - a.frequency));
    return grouped;
  }, [techniques]);

  // Premium Cyberpunk Intensity Styling
  const getIntensityClass = (freq: number) => {
    if (freq === 0) return "bg-[#12121a] text-[#6b7280] border-[#2a2a3e]";
    
    const ratio = freq / computedMax;
    if (ratio > 0.8) return "bg-red-600/90 text-white border-red-500 shadow-[0_0_15px_rgba(220,38,38,0.4)]";
    if (ratio > 0.6) return "bg-red-700/80 text-white border-red-600 shadow-[0_0_10px_rgba(185,28,28,0.3)]";
    if (ratio > 0.4) return "bg-red-800/70 text-red-100 border-red-700 shadow-[0_0_5px_rgba(153,27,27,0.2)]";
    if (ratio > 0.2) return "bg-red-900/60 text-red-200 border-red-800";
    return "bg-[#3f1619] text-red-300 border-[#5c1c22]";
  };

  return (
    <div className="w-full">
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-4">
        {TACTICS.map(tactic => {
          const techs = groupedTechniques.get(tactic) || [];
          return (
            <div key={tactic} className="flex flex-col gap-2">
              <div className="font-mono text-xs font-semibold bg-[#1a1a24] text-[#e0e0e0] p-2 rounded-t text-center border-b-2 border-[#ff3366]/40 uppercase tracking-wider h-10 flex items-center justify-center shadow-sm">
                {tactic}
              </div>
              <div className="flex flex-col gap-1.5 h-full">
                {techs.length === 0 ? (
                  <div className="flex h-full min-h-[60px] items-center justify-center rounded border border-[#2a2a3e] border-dashed bg-[#0a0a0f]/50 p-2">
                    <span className="font-mono text-[10px] text-[#4b5563] uppercase tracking-widest">[ NULL ]</span>
                  </div>
                ) : (
                  techs.map(t => (
                    <div 
                      key={t.id} 
                      className={cn(
                        "group text-xs p-2 rounded border cursor-crosshair transition-all duration-200 hover:scale-[1.05] hover:z-50 relative overflow-visible backdrop-blur-sm",
                        getIntensityClass(t.frequency)
                      )}
                    >
                      <div className="font-mono opacity-70 text-[9px] uppercase tracking-widest mb-1 pb-1 border-b border-current/20">
                        {t.id}
                      </div>
                      <div className="leading-tight font-medium text-[11px] drop-shadow-sm">
                        {t.name}
                      </div>

                      {/* Custom Hover Tooltip */}
                      <div className="pointer-events-none absolute left-1/2 -translate-x-1/2 bottom-full mb-2 hidden w-max max-w-[220px] flex-col gap-1 rounded border border-[#3f1619] bg-[#0f0f16] p-2 text-center text-xs text-white shadow-[0_0_20px_rgba(0,0,0,0.8)] group-hover:flex z-50">
                        <span className="font-mono font-bold text-[#ff3366]">{t.id}</span>
                        <span className="font-medium leading-snug">{t.name}</span>
                        <div className="mt-1 flex items-center justify-center gap-1 border-t border-white/10 pt-1 text-[10px] text-gray-400">
                           <span className="h-2 w-2 rounded-full bg-[#ff3366] animate-pulse"></span>
                           Observed in <strong className="text-white">{t.frequency}</strong> actor profiles
                        </div>
                        {/* Arrow */}
                        <div className="absolute left-1/2 -bottom-[5px] -translate-x-1/2 border-l-[6px] border-r-[6px] border-t-[6px] border-transparent border-t-[#3f1619]"></div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
