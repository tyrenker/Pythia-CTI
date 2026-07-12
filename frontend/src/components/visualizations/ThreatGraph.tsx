import { useMemo, useState, useRef, useCallback } from "react";
import ForceGraph2D from "react-force-graph-2d";

export interface Node {
  id: string;
  name: string;
  group: string;
  val: number;
}

export interface Link {
  source: string;
  target: string;
  label?: string;
}

export interface GraphData {
  nodes: Node[];
  links: Link[];
}

interface ThreatGraphProps {
  data: GraphData;
  width?: number;
  height?: number;
}

export function ThreatGraph({ data, width = 800, height = 600 }: ThreatGraphProps) {
  const fgRef = useRef<any>();
  const [highlightNodes, setHighlightNodes] = useState(new Set<string>());
  const [highlightLinks, setHighlightLinks] = useState(new Set<Link>());
  const [hoverNode, setHoverNode] = useState<Node | null>(null);

  const isDark = true; // Pythia defaults to dark theme

  // Pre-calculate node colors based on group
  const nodeColors = useMemo(() => {
    return {
      Actor: isDark ? "#ef4444" : "#dc2626",
      Malware: isDark ? "#3b82f6" : "#2563eb",
      Sector: isDark ? "#10b981" : "#059669",
      Campaign: isDark ? "#8b5cf6" : "#7c3aed",
      TTP: isDark ? "#f59e0b" : "#d97706",
      Default: isDark ? "#6b7280" : "#4b5563"
    };
  }, [isDark]);

  const updateHighlight = useCallback(() => {
    setHighlightNodes(highlightNodes);
    setHighlightLinks(highlightLinks);
  }, [highlightNodes, highlightLinks]);

  const handleNodeHover = useCallback((node: Node | null) => {
    highlightNodes.clear();
    highlightLinks.clear();
    if (node) {
      highlightNodes.add(node.id);
      data.links.forEach(link => {
        // react-force-graph replaces source/target string IDs with actual node objects after parsing
        const sourceId = typeof link.source === 'object' ? (link.source as any).id : link.source;
        const targetId = typeof link.target === 'object' ? (link.target as any).id : link.target;
        
        if (sourceId === node.id || targetId === node.id) {
          highlightLinks.add(link);
          highlightNodes.add(sourceId === node.id ? targetId : sourceId);
        }
      });
    }

    setHoverNode(node || null);
    updateHighlight();
  }, [data, updateHighlight]);

  const paintNode = useCallback((node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const label = node.name;
    const fontSize = 12 / globalScale;
    ctx.font = `${fontSize}px Sans-Serif`;
    const textWidth = ctx.measureText(label).width;
    const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2);

    ctx.fillStyle = isDark ? "rgba(30, 41, 59, 0.8)" : "rgba(255, 255, 255, 0.8)";
    ctx.fillRect(
      node.x - bckgDimensions[0] / 2,
      node.y - bckgDimensions[1] / 2,
      bckgDimensions[0],
      bckgDimensions[1]
    );

    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    
    // Determine color
    const group = node.group as keyof typeof nodeColors;
    const color = nodeColors[group] || nodeColors.Default;
    
    if (highlightNodes.size === 0 || highlightNodes.has(node.id)) {
        ctx.fillStyle = color;
    } else {
        ctx.fillStyle = isDark ? "rgba(100, 100, 100, 0.2)" : "rgba(200, 200, 200, 0.5)";
    }
    
    ctx.fillText(label, node.x, node.y);

    node.__bckgDimensions = bckgDimensions;
  }, [highlightNodes, isDark, nodeColors]);

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <ForceGraph2D
        ref={fgRef}
        width={width}
        height={height}
        graphData={data}
        nodeLabel="name"
        nodeColor={(node: any) => {
           const group = node.group as keyof typeof nodeColors;
           return nodeColors[group] || nodeColors.Default;
        }}
        nodeRelSize={6}
        linkColor={(link: any) => highlightLinks.has(link) ? (isDark ? "#f87171" : "#ef4444") : (isDark ? "rgba(255,255,255,0.2)" : "rgba(0,0,0,0.2)")}
        linkWidth={(link: any) => highlightLinks.has(link) ? 3 : 1}
        linkDirectionalParticles={2}
        linkDirectionalParticleWidth={(link: any) => highlightLinks.has(link) ? 4 : 0}
        onNodeHover={handleNodeHover}
        nodeCanvasObject={paintNode}
        nodeCanvasObjectMode={() => "replace"}
      />
    </div>
  );
}
