import * as React from "react";
import {
  ReactFlow,
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  BackgroundVariant,
  NodeTypes,
  Handle,
  Position,
  MarkerType,
  Panel,
  useReactFlow,
  ReactFlowProvider,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import dagre from "@dagrejs/dagre";
import {
  Smartphone,
  Laptop,
  ShieldAlert,
  Server,
  Globe,
  Database,
  MessageSquare,
  Users,
  MapPin,
  PhoneCall,
  Camera,
  Layers,
  AlertTriangle,
  Lock,
  Unlock,
  Maximize2,
  Minimize2,
  RotateCcw,
  ZoomIn,
  ZoomOut,
  Info,
  X,
  Radio,
  FileWarning,
} from "lucide-react";

export interface NetworkGraphProps {
  exfiltrationAnalysis: {
    data_types: string[];
    destinations: string[];
    timing_patterns: string;
    encryption_status: string;
    risk_assessment: string;
  } | null;
  victimImpact: {
    data_accessed: string[];
  } | null;
  malwareInfo: {
    name: string;
    type: string;
  };
}

export type FlowNodeType =
  | "victim"
  | "malware"
  | "c2"
  | "data"
  | "aggregate"
  | "risk"
  | "encryption";

interface FlowNodeData {
  label: string;
  fullLabel?: string;
  category: FlowNodeType;
  typeLabel: string;
  subtext?: string;
  metadata?: Record<string, string>;
  severity?: "critical" | "high" | "medium" | "low" | "neutral";
  iconName?: string;
}

// ---------------------------------------------------------------------------
// Helper: Select icon based on node type and content
// ---------------------------------------------------------------------------
function renderNodeIcon(category: FlowNodeType, label: string, iconName?: string) {
  const l = (label || "").toLowerCase();
  const className = "w-4 h-4";

  if (category === "victim") {
    if (l.includes("windows") || l.includes("pc") || l.includes("laptop")) {
      return <Laptop className={className} />;
    }
    return <Smartphone className={className} />;
  }

  if (category === "malware") {
    return <ShieldAlert className={className} />;
  }

  if (category === "c2") {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(label)) {
      return <Server className={className} />;
    }
    return <Globe className={className} />;
  }

  if (category === "data") {
    if (l.includes("sms") || l.includes("message") || l.includes("otp")) {
      return <MessageSquare className={className} />;
    }
    if (l.includes("contact") || l.includes("user") || l.includes("account")) {
      return <Users className={className} />;
    }
    if (l.includes("gps") || l.includes("location") || l.includes("coordinate")) {
      return <MapPin className={className} />;
    }
    if (l.includes("call") || l.includes("log")) {
      return <PhoneCall className={className} />;
    }
    if (l.includes("photo") || l.includes("camera") || l.includes("media")) {
      return <Camera className={className} />;
    }
    return <Database className={className} />;
  }

  if (category === "aggregate") {
    return <Layers className={className} />;
  }

  if (category === "risk") {
    return <AlertTriangle className={className} />;
  }

  if (category === "encryption") {
    if (l.includes("unencrypted") || l.includes("clear") || l.includes("plain") || l.includes("no")) {
      return <Unlock className={className} />;
    }
    return <Lock className={className} />;
  }

  return <Radio className={className} />;
}

// ---------------------------------------------------------------------------
// Custom Flowchart Node Component
// ---------------------------------------------------------------------------
const InvestigationNode = ({
  data,
  selected,
}: {
  data: FlowNodeData;
  selected?: boolean;
}) => {
  const [showTooltip, setShowTooltip] = React.useState(false);

  // Styling token presets per category
  const theme = React.useMemo(() => {
    switch (data.category) {
      case "victim":
        return {
          cardBg: "bg-[#0c192c]",
          border: selected ? "border-sky-400 ring-2 ring-sky-400/20" : "border-sky-500/40 hover:border-sky-400",
          iconBg: "bg-sky-500/15 text-sky-400",
          tagBg: "bg-sky-500/10 text-sky-400",
        };
      case "malware":
        return {
          cardBg: "bg-[#200c14]",
          border: selected ? "border-rose-400 ring-2 ring-rose-400/20" : "border-rose-500/50 hover:border-rose-400",
          iconBg: "bg-rose-500/15 text-rose-400",
          tagBg: "bg-rose-500/10 text-rose-400",
        };
      case "c2":
        return {
          cardBg: "bg-[#1f1308]",
          border: selected ? "border-amber-400 ring-2 ring-amber-400/20" : "border-amber-500/40 hover:border-amber-400",
          iconBg: "bg-amber-500/15 text-amber-400",
          tagBg: "bg-amber-500/10 text-amber-400",
        };
      case "data":
        return {
          cardBg: "bg-[#160f27]",
          border: selected ? "border-purple-400 ring-2 ring-purple-400/20" : "border-purple-500/40 hover:border-purple-400",
          iconBg: "bg-purple-500/15 text-purple-400",
          tagBg: "bg-purple-500/10 text-purple-400",
        };
      case "aggregate":
        return {
          cardBg: "bg-[#091b22]",
          border: selected ? "border-cyan-400 ring-2 ring-cyan-400/20" : "border-cyan-500/40 hover:border-cyan-400",
          iconBg: "bg-cyan-500/15 text-cyan-400",
          tagBg: "bg-cyan-500/10 text-cyan-400",
        };
      case "risk": {
        const isCritical = data.severity === "critical" || data.label.toLowerCase().includes("critical");
        const isHigh = data.severity === "high" || data.label.toLowerCase().includes("high");
        if (isCritical) {
          return {
            cardBg: "bg-[#250d0d]",
            border: selected ? "border-red-400 ring-2 ring-red-400/20" : "border-red-500/60 hover:border-red-400",
            iconBg: "bg-red-500/20 text-red-400",
            tagBg: "bg-red-500/15 text-red-400",
          };
        }
        if (isHigh) {
          return {
            cardBg: "bg-[#251509]",
            border: selected ? "border-orange-400 ring-2 ring-orange-400/20" : "border-orange-500/50 hover:border-orange-400",
            iconBg: "bg-orange-500/20 text-orange-400",
            tagBg: "bg-orange-500/15 text-orange-400",
          };
        }
        return {
          cardBg: "bg-[#181a08]",
          border: selected ? "border-yellow-400 ring-2 ring-yellow-400/20" : "border-yellow-500/40 hover:border-yellow-400",
          iconBg: "bg-yellow-500/15 text-yellow-400",
          tagBg: "bg-yellow-500/10 text-yellow-400",
        };
      }
      case "encryption": {
        const isCleartext =
          data.label.toLowerCase().includes("unencrypted") ||
          data.label.toLowerCase().includes("clear") ||
          data.label.toLowerCase().includes("none") ||
          data.label.toLowerCase().includes("plain");
        if (isCleartext) {
          return {
            cardBg: "bg-[#210e0e]",
            border: selected ? "border-rose-400 ring-2 ring-rose-400/20" : "border-rose-500/40 hover:border-rose-400",
            iconBg: "bg-rose-500/15 text-rose-400",
            tagBg: "bg-rose-500/10 text-rose-400",
          };
        }
        return {
          cardBg: "bg-[#091e17]",
          border: selected ? "border-emerald-400 ring-2 ring-emerald-400/20" : "border-emerald-500/40 hover:border-emerald-400",
          iconBg: "bg-emerald-500/15 text-emerald-400",
          tagBg: "bg-emerald-500/10 text-emerald-400",
        };
      }
      default:
        return {
          cardBg: "bg-[#101726]",
          border: selected ? "border-slate-300" : "border-slate-700/60 hover:border-slate-500",
          iconBg: "bg-slate-700/30 text-slate-300",
          tagBg: "bg-slate-700/20 text-slate-300",
        };
    }
  }, [data.category, data.severity, data.label, selected]);

  const fullText = data.fullLabel || data.label;
  const isTruncated = fullText !== data.label || fullText.length > 22;

  return (
    <div
      className="relative group cursor-pointer select-none"
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      {/* Top Handle for vertical flowchart alignment */}
      <Handle
        type="target"
        position={Position.Top}
        className="!w-2.5 !h-2.5 !bg-slate-400 !border-2 !border-[#0a0f1d] transition-colors"
      />

      {/* Main Node Card */}
      <div
        className={`w-[230px] min-h-[68px] px-3 py-2.5 rounded-xl border shadow-md transition-all duration-200 ${theme.cardBg} ${theme.border}`}
      >
        <div className="flex items-center space-x-2.5">
          {/* Node Category Icon */}
          <div
            className={`flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center ${theme.iconBg}`}
          >
            {renderNodeIcon(data.category, data.label, data.iconName)}
          </div>

          {/* Node Titles */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between gap-1 mb-0.5">
              <span
                className={`text-[9px] font-semibold tracking-wider uppercase px-1.5 py-0.5 rounded ${theme.tagBg}`}
              >
                {data.typeLabel}
              </span>
              {data.severity && (
                <span
                  className={`text-[8px] font-bold uppercase tracking-wider ${
                    data.severity === "critical"
                      ? "text-red-400"
                      : data.severity === "high"
                      ? "text-orange-400"
                      : "text-yellow-400"
                  }`}
                >
                  {data.severity}
                </span>
              )}
            </div>

            <p
              className="text-xs font-semibold text-slate-100 truncate tracking-tight"
              title={fullText}
            >
              {data.label}
            </p>

            {data.subtext && (
              <p className="text-[10px] text-slate-400 truncate mt-0.5 font-normal">
                {data.subtext}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Handle */}
      <Handle
        type="source"
        position={Position.Bottom}
        className="!w-2.5 !h-2.5 !bg-slate-400 !border-2 !border-[#0a0f1d] transition-colors"
      />

      {/* Clean Hover Popover Tooltip for Truncated Content */}
      {showTooltip && (isTruncated || data.metadata) && (
        <div className="absolute left-1/2 -top-2 -translate-x-1/2 -translate-y-full z-50 pointer-events-none mb-2 w-max max-w-[280px] p-2.5 rounded-lg bg-[#0b1329] border border-slate-700/80 shadow-2xl text-left animate-in fade-in zoom-in-95 duration-150">
          <div className="flex items-center space-x-1.5 mb-1 text-[10px] uppercase font-bold tracking-wider text-slate-400">
            <Info className="w-3 h-3 text-slate-400" />
            <span>{data.typeLabel} Details</span>
          </div>
          <p className="text-xs text-white font-mono break-all leading-tight">
            {fullText}
          </p>
          {data.metadata && (
            <div className="mt-2 pt-1.5 border-t border-slate-800 text-[10px] space-y-0.5 text-slate-300 font-sans">
              {Object.entries(data.metadata).map(([k, v]) => (
                <div key={k} className="flex justify-between gap-2">
                  <span className="text-slate-500 capitalize">{k.replace(/_/g, " ")}:</span>
                  <span className="font-mono text-slate-200 truncate">{v}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const nodeTypes: NodeTypes = {
  flowNode: InvestigationNode,
};

// ---------------------------------------------------------------------------
// Dagre Hierarchical Layout Engine (Top-to-Bottom)
// ---------------------------------------------------------------------------
const NODE_WIDTH = 230;
const NODE_HEIGHT = 68;

function computeLayout(nodes: Node[], edges: Edge[]): { nodes: Node[]; edges: Edge[] } {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));

  g.setGraph({
    rankdir: "TB",
    align: "DL",
    nodesep: 48,
    ranksep: 70,
    marginx: 40,
    marginy: 40,
  });

  nodes.forEach((n) => {
    g.setNode(n.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
  });

  edges.forEach((e) => {
    g.setEdge(e.source, e.target);
  });

  dagre.layout(g);

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPos = g.node(node.id);
    return {
      ...node,
      targetPosition: Position.Top,
      sourcePosition: Position.Bottom,
      position: {
        x: nodeWithPos.x - NODE_WIDTH / 2,
        y: nodeWithPos.y - NODE_HEIGHT / 2,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
}

// ---------------------------------------------------------------------------
// Truncation Helper
// ---------------------------------------------------------------------------
function truncateText(str: string, maxLength = 22): string {
  if (!str) return "";
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + "...";
}

// ---------------------------------------------------------------------------
// Inner Flow Component with Toolbar & Interactive Inspector
// ---------------------------------------------------------------------------
function NetworkGraphInner({
  exfiltrationAnalysis,
  victimImpact,
  malwareInfo,
}: NetworkGraphProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selectedNode, setSelectedNode] = React.useState<Node | null>(null);
  const [isFullscreen, setIsFullscreen] = React.useState(false);
  const containerRef = React.useRef<HTMLDivElement>(null);
  const { fitView, zoomIn, zoomOut } = useReactFlow();

  // Build nodes & edges based on the clear 7-tier flowchart hierarchy
  React.useEffect(() => {
    if (!exfiltrationAnalysis && !victimImpact) {
      setNodes([]);
      setEdges([]);
      return;
    }

    const rawNodes: Node[] = [];
    const rawEdges: Edge[] = [];
    let idGen = 0;
    const nextId = (prefix: string) => `${prefix}-${idGen++}`;

    // 1. TIER 1: Victim Device
    const victimId = nextId("victim");
    rawNodes.push({
      id: victimId,
      type: "flowNode",
      position: { x: 0, y: 0 },
      data: {
        label: "Victim Device",
        fullLabel: "Victim Device (Host Environment)",
        category: "victim",
        typeLabel: "Host Device",
        subtext: malwareInfo.type || "Endpoint Platform",
        metadata: {
          platform: malwareInfo.type || "Unknown Host",
          status: "Compromised / Under Inspection",
        },
      },
    });

    // 2. TIER 2: Malware Threat Artifact
    const malwareId = nextId("malware");
    rawNodes.push({
      id: malwareId,
      type: "flowNode",
      position: { x: 0, y: 0 },
      data: {
        label: truncateText(malwareInfo.name || "Malware Sample", 20),
        fullLabel: malwareInfo.name || "Malware Sample",
        category: "malware",
        typeLabel: "Malware Artifact",
        subtext: "Payload Binary",
        metadata: {
          sample_name: malwareInfo.name,
          platform_type: malwareInfo.type,
        },
      },
    });

    // Edge: Victim -> Malware
    rawEdges.push({
      id: `e-${victimId}-${malwareId}`,
      source: victimId,
      target: malwareId,
      type: "smoothstep",
      label: "Infects",
      animated: true,
      style: { stroke: "#f43f5e", strokeWidth: 1.75 },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: "#f43f5e",
        width: 14,
        height: 14,
      },
      labelStyle: { fill: "#fecdd3", fontSize: 10, fontWeight: 600 },
      labelBgStyle: { fill: "#1c1917", fillOpacity: 0.95, rx: 4, ry: 4 },
      labelBgPadding: [6, 3],
    });

    // 3. TIER 3: C2 Server Destination(s)
    const c2Destinations = exfiltrationAnalysis?.destinations || [];
    const c2NodeIds: string[] = [];

    if (c2Destinations.length > 0) {
      c2Destinations.forEach((dest) => {
        const c2Id = nextId("c2");
        c2NodeIds.push(c2Id);
        const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(dest);

        rawNodes.push({
          id: c2Id,
          type: "flowNode",
          position: { x: 0, y: 0 },
          data: {
            label: truncateText(dest, 22),
            fullLabel: dest,
            category: "c2",
            typeLabel: isIp ? "C2 IP Endpoint" : "C2 Domain",
            subtext: isIp ? "Direct Socket Connection" : "Remote Hostname",
            metadata: {
              endpoint: dest,
              timing: exfiltrationAnalysis?.timing_patterns || "Periodic Beacon",
            },
          },
        });

        // Edge: Malware -> C2
        rawEdges.push({
          id: `e-${malwareId}-${c2Id}`,
          source: malwareId,
          target: c2Id,
          type: "smoothstep",
          label: exfiltrationAnalysis?.timing_patterns ? truncateText(exfiltrationAnalysis.timing_patterns, 18) : "Beacons",
          animated: true,
          style: { stroke: "#f59e0b", strokeWidth: 1.5 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: "#f59e0b",
            width: 14,
            height: 14,
          },
          labelStyle: { fill: "#fef3c7", fontSize: 9, fontWeight: 500 },
          labelBgStyle: { fill: "#1c1917", fillOpacity: 0.9, rx: 4, ry: 4 },
          labelBgPadding: [5, 2],
        });
      });
    }

    // 4. TIER 4: Target Artifacts / Stolen Data Types
    const rawDataList = [
      ...(victimImpact?.data_accessed || []),
      ...(exfiltrationAnalysis?.data_types || []),
    ];
    const uniqueDataTypes = Array.from(
      new Set(rawDataList.map((d) => d.trim()).filter(Boolean))
    );
    const dataNodeIds: string[] = [];

    if (uniqueDataTypes.length > 0) {
      uniqueDataTypes.forEach((dataType) => {
        const dataId = nextId("data");
        dataNodeIds.push(dataId);

        rawNodes.push({
          id: dataId,
          type: "flowNode",
          position: { x: 0, y: 0 },
          data: {
            label: truncateText(dataType, 20),
            fullLabel: dataType,
            category: "data",
            typeLabel: "Target Artifact",
            subtext: "Harvested from Host",
            metadata: {
              artifact: dataType,
              classification: "Sensitive User Data",
            },
          },
        });

        // Edges connect from C2 (if present) or Malware -> Data Nodes
        const sourceForData = c2NodeIds.length > 0 ? c2NodeIds[0] : malwareId;
        rawEdges.push({
          id: `e-${sourceForData}-${dataId}`,
          source: sourceForData,
          target: dataId,
          type: "smoothstep",
          label: "Exfiltrates",
          style: { stroke: "#a855f7", strokeWidth: 1.5, strokeDasharray: "4 3" },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: "#a855f7",
            width: 14,
            height: 14,
          },
          labelStyle: { fill: "#f3e8ff", fontSize: 9, fontWeight: 500 },
          labelBgStyle: { fill: "#1c1917", fillOpacity: 0.9, rx: 4, ry: 4 },
          labelBgPadding: [5, 2],
        });
      });
    }

    // 5. TIER 5: Collected Telemetry / Synthesis Node
    let parentForAssessment = malwareId;

    if (dataNodeIds.length > 0) {
      const aggId = nextId("agg");
      parentForAssessment = aggId;

      rawNodes.push({
        id: aggId,
        type: "flowNode",
        position: { x: 0, y: 0 },
        data: {
          label: "Collected Telemetry",
          fullLabel: `Aggregated Data (${uniqueDataTypes.length} types detected)`,
          category: "aggregate",
          typeLabel: "Data Pipeline",
          subtext: `${uniqueDataTypes.length} Stolen Artifacts`,
          metadata: {
            total_types: String(uniqueDataTypes.length),
            types: uniqueDataTypes.join(", "),
          },
        },
      });

      // Converging edges from all data nodes to aggregate node
      dataNodeIds.forEach((dId) => {
        rawEdges.push({
          id: `e-${dId}-${aggId}`,
          source: dId,
          target: aggId,
          type: "smoothstep",
          style: { stroke: "#06b6d4", strokeWidth: 1.25 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: "#06b6d4",
            width: 12,
            height: 12,
          },
        });
      });
    } else if (c2NodeIds.length > 0) {
      parentForAssessment = c2NodeIds[0];
    }

    // 6. TIER 6: Risk Assessment Node
    if (exfiltrationAnalysis?.risk_assessment) {
      const riskId = nextId("risk");
      const riskVal = exfiltrationAnalysis.risk_assessment;
      const severity =
        riskVal.toLowerCase().includes("critical")
          ? "critical"
          : riskVal.toLowerCase().includes("high")
          ? "high"
          : riskVal.toLowerCase().includes("medium")
          ? "medium"
          : "low";

      rawNodes.push({
        id: riskId,
        type: "flowNode",
        position: { x: 0, y: 0 },
        data: {
          label: `${riskVal} Risk`,
          fullLabel: `Overall Exfiltration Risk: ${riskVal}`,
          category: "risk",
          typeLabel: "Risk Assessment",
          subtext: "Calculated Impact",
          severity: severity,
          metadata: {
            risk_level: riskVal,
            timing_pattern: exfiltrationAnalysis.timing_patterns || "Observed",
          },
        },
      });

      rawEdges.push({
        id: `e-${parentForAssessment}-${riskId}`,
        source: parentForAssessment,
        target: riskId,
        type: "smoothstep",
        label: "Evaluates",
        style: { stroke: severity === "critical" ? "#ef4444" : "#f97316", strokeWidth: 1.5 },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: severity === "critical" ? "#ef4444" : "#f97316",
          width: 14,
          height: 14,
        },
        labelStyle: { fill: "#fed7aa", fontSize: 9, fontWeight: 500 },
        labelBgStyle: { fill: "#1c1917", fillOpacity: 0.9, rx: 4, ry: 4 },
        labelBgPadding: [5, 2],
      });

      // 7. TIER 7: Encryption Status Node
      if (exfiltrationAnalysis.encryption_status) {
        const encId = nextId("enc");
        const encVal = exfiltrationAnalysis.encryption_status;

        rawNodes.push({
          id: encId,
          type: "flowNode",
          position: { x: 0, y: 0 },
          data: {
            label: truncateText(encVal, 22),
            fullLabel: encVal,
            category: "encryption",
            typeLabel: "Transport Security",
            subtext: "Channel Cryptography",
            metadata: {
              encryption: encVal,
              transport: "Exfiltration Path Security",
            },
          },
        });

        rawEdges.push({
          id: `e-${riskId}-${encId}`,
          source: riskId,
          target: encId,
          type: "smoothstep",
          style: { stroke: "#64748b", strokeWidth: 1.5 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: "#64748b",
            width: 14,
            height: 14,
          },
        });
      }
    }

    // Compute Dagre Hierarchical Layout
    const layout = computeLayout(rawNodes, rawEdges);
    setNodes(layout.nodes);
    setEdges(layout.edges);

    // Initial smooth fit
    setTimeout(() => {
      fitView({ padding: 0.25, duration: 400 });
    }, 50);
  }, [exfiltrationAnalysis, victimImpact, malwareInfo, setNodes, setEdges, fitView]);

  // Handle Fullscreen toggle
  const toggleFullscreen = () => {
    if (!containerRef.current) return;
    if (!document.fullscreenElement) {
      containerRef.current.requestFullscreen().then(() => setIsFullscreen(true)).catch(() => {});
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false)).catch(() => {});
    }
  };

  // Node selection handler for Inspector drawer
  const onNodeClick = (_: React.MouseEvent, node: Node) => {
    setSelectedNode(node);
  };

  const handleResetLayout = () => {
    const layout = computeLayout(nodes, edges);
    setNodes(layout.nodes);
    setEdges(layout.edges);
    fitView({ padding: 0.25, duration: 400 });
  };

  if (!exfiltrationAnalysis && !victimImpact) {
    return (
      <div className="bg-[#0b111e] border border-slate-800 rounded-xl p-10 text-center flex flex-col items-center justify-center space-y-3">
        <div className="w-12 h-12 rounded-full bg-slate-800/80 flex items-center justify-center text-slate-500">
          <FileWarning className="w-6 h-6 text-slate-400" />
        </div>
        <h4 className="text-sm font-semibold text-slate-200">No Network Telemetry Available</h4>
        <p className="text-xs text-slate-400 max-w-sm">
          No external command-and-control communication or data exfiltration events were observed during analysis of this artifact.
        </p>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={`relative w-full rounded-xl border border-slate-800 bg-[#080d1a] overflow-hidden transition-all duration-300 ${
        isFullscreen ? "h-screen w-screen rounded-none" : "h-[580px]"
      }`}
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onPaneClick={() => setSelectedNode(null)}
        nodeTypes={nodeTypes}
        fitView
        colorMode="dark"
        minZoom={0.2}
        maxZoom={1.75}
        attributionPosition="bottom-left"
        defaultEdgeOptions={{
          type: "smoothstep",
        }}
      >
        {/* Subtle Background Pattern */}
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1}
          color="#1e293b"
          className="bg-[#080d1a]"
        />

        {/* Minimal Floating Controls Toolbar */}
        <Panel position="top-right" className="flex items-center gap-1.5 p-1 rounded-lg bg-[#0e1626]/90 border border-slate-700/80 shadow-xl backdrop-blur-md">
          <button
            type="button"
            onClick={() => zoomIn({ duration: 250 })}
            className="p-1.5 rounded-md hover:bg-slate-700/60 text-slate-300 hover:text-white transition-colors"
            title="Zoom In"
            aria-label="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            type="button"
            onClick={() => zoomOut({ duration: 250 })}
            className="p-1.5 rounded-md hover:bg-slate-700/60 text-slate-300 hover:text-white transition-colors"
            title="Zoom Out"
            aria-label="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            type="button"
            onClick={() => fitView({ padding: 0.25, duration: 350 })}
            className="p-1.5 rounded-md hover:bg-slate-700/60 text-slate-300 hover:text-white transition-colors"
            title="Fit to View"
            aria-label="Fit to View"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
          <div className="w-[1px] h-4 bg-slate-700 mx-0.5" />
          <button
            type="button"
            onClick={handleResetLayout}
            className="p-1.5 rounded-md hover:bg-slate-700/60 text-slate-300 hover:text-white transition-colors"
            title="Reset Hierarchical Layout"
            aria-label="Reset Layout"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
          <button
            type="button"
            onClick={toggleFullscreen}
            className="p-1.5 rounded-md hover:bg-slate-700/60 text-slate-300 hover:text-white transition-colors"
            title={isFullscreen ? "Exit Fullscreen" : "Fullscreen View"}
            aria-label="Toggle Fullscreen"
          >
            {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </Panel>

        {/* Clean Legend Panel */}
        <Panel position="top-left" className="p-2.5 rounded-lg bg-[#0e1626]/85 border border-slate-700/70 shadow-lg backdrop-blur-md hidden sm:block">
          <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1.5">
            <Info className="w-3 h-3 text-cyan-400" />
            <span>Investigation Flowchart</span>
          </div>
          <div className="flex flex-wrap gap-2 text-[10px] text-slate-300">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-sky-400" /> Victim Host
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-rose-500" /> Threat
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-amber-400" /> C2 Server
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-purple-400" /> Exfiltrated Data
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-red-400" /> Severity
            </span>
          </div>
        </Panel>

        {/* Styled Dark MiniMap */}
        <MiniMap
          nodeStrokeWidth={2}
          nodeColor={(n: Node) => {
            const cat = (n.data as unknown as FlowNodeData)?.category;
            switch (cat) {
              case "victim":
                return "#0284c7";
              case "malware":
                return "#e11d48";
              case "c2":
                return "#d97706";
              case "data":
                return "#9333ea";
              case "aggregate":
                return "#0891b2";
              case "risk":
                return "#dc2626";
              case "encryption":
                return "#059669";
              default:
                return "#475569";
            }
          }}
          maskColor="rgba(8, 13, 26, 0.75)"
          bgColor="#0c1322"
          className="!rounded-lg !border !border-slate-800 !bottom-3 !right-3 shadow-xl"
        />
      </ReactFlow>

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="absolute bottom-3 left-3 right-3 sm:right-auto sm:w-[380px] p-3.5 rounded-xl bg-[#0f192d]/95 border border-slate-700 shadow-2xl backdrop-blur-md z-40 animate-in slide-in-from-bottom-3 duration-200">
          <div className="flex items-start justify-between gap-2 pb-2 mb-2 border-b border-slate-800">
            <div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-400">
                {(selectedNode.data as unknown as FlowNodeData).typeLabel}
              </span>
              <h4 className="text-xs font-semibold text-white break-all">
                {(selectedNode.data as unknown as FlowNodeData).fullLabel || (selectedNode.data as unknown as FlowNodeData).label}
              </h4>
            </div>
            <button
              type="button"
              onClick={() => setSelectedNode(null)}
              className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              aria-label="Close Inspector"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          {(selectedNode.data as unknown as FlowNodeData).metadata && (
            <div className="space-y-1 text-[11px]">
              {Object.entries((selectedNode.data as unknown as FlowNodeData).metadata || {}).map(([key, val]) => (
                <div key={key} className="flex justify-between gap-2">
                  <span className="text-slate-400 capitalize">{key.replace(/_/g, " ")}:</span>
                  <span className="font-mono text-slate-200 truncate">{val}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Exported Component Wrapped in ReactFlowProvider
// ---------------------------------------------------------------------------
export function NetworkGraph(props: NetworkGraphProps) {
  return (
    <ReactFlowProvider>
      <NetworkGraphInner {...props} />
    </ReactFlowProvider>
  );
}
