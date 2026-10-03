import * as React from "react";
import { Globe, Network, Server, Link, AlertTriangle, MapPin, Shield } from "lucide-react";
import { ThreatCase } from "./types";

interface NetworkIntelligenceTabProps {
  activeCase: ThreatCase;
}

const GEOIP_DISCLAIMER =
  "Geo-IP is an approximate geographic estimate and not an exact physical location.";

function Badge({ label, color }: { label: string; color: "red" | "yellow" | "green" | "blue" | "gray" }) {
  const colors = {
    red: "bg-red-950/40 border-red-500/20 text-[#ff4040]",
    yellow: "bg-yellow-950/40 border-yellow-500/20 text-[#f4b400]",
    green: "bg-green-950/40 border-green-500/20 text-[#16ff4d]",
    blue: "bg-blue-950/40 border-blue-500/20 text-[#00c2ff]",
    gray: "bg-[#151515] border-[#333] text-[#A0A0A0]",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold uppercase border ${colors[color]}`}>
      {label}
    </span>
  );
}

export function NetworkIntelligenceTab({ activeCase }: NetworkIntelligenceTabProps) {
  const net = activeCase.networkIndicators;
  const geoIocs = activeCase.geoIocs ?? [];

  const hasAnyData = net && (
    net.ips.length > 0 || net.domains.length > 0 || net.urls.length > 0 || net.connections.length > 0
  );

  const c2Connections = (net?.connections ?? []).filter((c) => c.flagged_c2);

  return (
    <div className="space-y-6">

      {/* Header row */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-sans flex items-center gap-2">
            <Globe className="w-4 h-4 text-[#00c2ff]" />
            Network Intelligence
          </h3>
          <p className="text-[11px] text-[#A0A0A0] font-light mt-1">
            Real network observables extracted from static and dynamic analysis — never fabricated.
          </p>
        </div>
        {net && (
          <div className="flex gap-2">
            <Badge label={`${net.ips.length} IPs`} color="blue" />
            <Badge label={`${net.domains.length} Domains`} color="gray" />
            {c2Connections.length > 0 && (
              <Badge label={`${c2Connections.length} C2`} color="red" />
            )}
          </div>
        )}
      </div>

      {!hasAnyData ? (
        <div className="bg-[#111111] border border-[#222222] rounded-lg p-8 text-center">
          <Network className="w-10 h-10 text-[#333] mx-auto mb-3" />
          <p className="text-[#6F6F6F] font-mono text-xs uppercase tracking-widest">No network indicators extracted</p>
          <p className="text-[#444] font-sans text-[11px] mt-2">
            No IPs, domains, or URLs were identified in the static or dynamic analysis of this sample.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* IPs Panel */}
          <div className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-[#222222] flex items-center justify-between">
              <span className="text-[10px] font-mono font-bold text-white uppercase tracking-widest flex items-center gap-2">
                <Server className="w-3.5 h-3.5 text-[#00c2ff]" />
                IP Addresses
              </span>
              <span className="text-[9px] font-mono text-[#6F6F6F]">{(net?.ips ?? []).length} unique</span>
            </div>
            <div className="divide-y divide-[#1a1a1a] max-h-64 overflow-y-auto">
              {(net?.ips ?? []).length === 0 ? (
                <p className="text-[#6F6F6F] text-[10px] font-mono p-4">No IPs extracted.</p>
              ) : (
                (net?.ips ?? []).map((ip, i) => {
                  const geo = geoIocs.find((g) => g.ip === ip);
                  const isC2 = (net?.connections ?? []).some((c) => c.ip === ip && c.flagged_c2);
                  return (
                    <div key={i} className="px-4 py-2.5 hover:bg-[#161616] transition-colors">
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-mono text-[11px] text-[#00c2ff] font-bold">{ip}</span>
                        <div className="flex gap-1.5 shrink-0">
                          {isC2 && <Badge label="C2" color="red" />}
                          {geo?.is_proxy && <Badge label="Proxy" color="red" />}
                          {geo?.is_hosting && <Badge label="Hosting" color="yellow" />}
                        </div>
                      </div>
                      {geo && (
                        <p className="text-[9px] text-[#6F6F6F] font-sans mt-0.5 flex items-center gap-1">
                          <MapPin className="w-2.5 h-2.5 shrink-0" />
                          {[geo.city, geo.region, geo.country].filter(Boolean).join(", ") || "location unavailable"}
                          {geo.isp ? ` · ${geo.isp}` : ""}
                          {geo.asn ? ` · AS${geo.asn}` : ""}
                        </p>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Domains & URLs Panel */}
          <div className="space-y-4">
            <div className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden">
              <div className="px-4 py-3 border-b border-[#222222] flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <Globe className="w-3.5 h-3.5 text-[#f4b400]" />
                  Domains
                </span>
                <span className="text-[9px] font-mono text-[#6F6F6F]">{(net?.domains ?? []).length} unique</span>
              </div>
              <div className="divide-y divide-[#1a1a1a] max-h-32 overflow-y-auto">
                {(net?.domains ?? []).length === 0 ? (
                  <p className="text-[#6F6F6F] text-[10px] font-mono p-4">No domains identified.</p>
                ) : (
                  (net?.domains ?? []).map((d, i) => (
                    <div key={i} className="px-4 py-2 font-mono text-[10px] text-[#f4b400] hover:bg-[#161616] truncate">
                      {d}
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="bg-[#111111] border border-[#222222] rounded-lg overflow-hidden">
              <div className="px-4 py-3 border-b border-[#222222] flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <Link className="w-3.5 h-3.5 text-[#16ff4d]" />
                  URLs
                </span>
                <span className="text-[9px] font-mono text-[#6F6F6F]">{(net?.urls ?? []).length} unique</span>
              </div>
              <div className="divide-y divide-[#1a1a1a] max-h-32 overflow-y-auto">
                {(net?.urls ?? []).length === 0 ? (
                  <p className="text-[#6F6F6F] text-[10px] font-mono p-4">No URLs found.</p>
                ) : (
                  (net?.urls ?? []).map((u, i) => (
                    <div key={i} className="px-4 py-2 font-mono text-[10px] text-[#16ff4d] hover:bg-[#161616] truncate break-all">
                      {u}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Active Connections */}
          {(net?.connections ?? []).length > 0 && (
            <div className="lg:col-span-2 bg-[#111111] border border-[#222222] rounded-lg overflow-hidden">
              <div className="px-4 py-3 border-b border-[#222222] flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <Network className="w-3.5 h-3.5 text-[#00c2ff]" />
                  Active Network Connections (Dynamic Analysis)
                </span>
                {c2Connections.length > 0 && (
                  <span className="flex items-center gap-1.5 text-[9px] font-mono text-[#ff4040]">
                    <AlertTriangle className="w-3 h-3" />
                    {c2Connections.length} flagged C2
                  </span>
                )}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-[10px] font-mono">
                  <thead>
                    <tr className="bg-[#0d0d0d] text-[#6F6F6F] uppercase text-[8px] tracking-wider">
                      <th className="px-4 py-2 text-left">Destination IP</th>
                      <th className="px-4 py-2 text-left">Port</th>
                      <th className="px-4 py-2 text-left">Protocol</th>
                      <th className="px-4 py-2 text-left">C2 Flag</th>
                      <th className="px-4 py-2 text-left">Location</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1a1a1a]">
                    {(net?.connections ?? []).map((conn, i) => {
                      const geo = geoIocs.find((g) => g.ip === conn.ip);
                      return (
                        <tr key={i} className={`hover:bg-[#161616] transition-colors ${conn.flagged_c2 ? "bg-red-950/10" : ""}`}>
                          <td className={`px-4 py-2.5 font-bold ${conn.flagged_c2 ? "text-[#ff4040]" : "text-[#00c2ff]"}`}>{conn.ip}</td>
                          <td className="px-4 py-2.5 text-[#A0A0A0]">{conn.port ?? "—"}</td>
                          <td className="px-4 py-2.5 text-[#A0A0A0]">{conn.protocol || "—"}</td>
                          <td className="px-4 py-2.5">
                            {conn.flagged_c2
                              ? <Badge label="C2 CONFIRMED" color="red" />
                              : <Badge label="Clean" color="green" />}
                          </td>
                          <td className="px-4 py-2.5 text-[#6F6F6F]">
                            {geo
                              ? [geo.city, geo.country].filter(Boolean).join(", ") || "—"
                              : "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Geo-IP Cards */}
          {geoIocs.length > 0 && (
            <div className="lg:col-span-2 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <Shield className="w-3.5 h-3.5 text-[#00c2ff]" />
                  Geo-IP Attribution
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {geoIocs.map((g, i) => (
                  <div key={i} className="bg-[#111111] border border-[#222222] rounded-lg p-4 space-y-2 hover:border-[#00c2ff]/20 transition-colors">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[11px] text-[#00c2ff] font-bold">{g.ip}</span>
                      <div className="flex gap-1">
                        {g.is_proxy && <Badge label="Proxy" color="red" />}
                        {g.is_hosting && <Badge label="Cloud" color="yellow" />}
                        {g.threat_level && <Badge label={g.threat_level} color={g.threat_level === "HIGH" ? "red" : "yellow"} />}
                      </div>
                    </div>
                    <div className="space-y-1 text-[9px] font-mono text-[#6F6F6F]">
                      {g.country && <p><span className="text-[#A0A0A0]">Country:</span> {g.country} {g.country_iso ? `(${g.country_iso})` : ""}</p>}
                      {g.region && <p><span className="text-[#A0A0A0]">Region:</span> {g.region}</p>}
                      {g.city && <p><span className="text-[#A0A0A0]">City:</span> {g.city}</p>}
                      {g.isp && <p><span className="text-[#A0A0A0]">ISP:</span> {g.isp}</p>}
                      {g.asn && <p><span className="text-[#A0A0A0]">ASN:</span> AS{g.asn}</p>}
                      {g.timezone && <p><span className="text-[#A0A0A0]">TZ:</span> {g.timezone}</p>}
                      {g.latitude != null && g.longitude != null && (
                        <p><span className="text-[#A0A0A0]">Coords:</span> {g.latitude.toFixed(4)}, {g.longitude.toFixed(4)}</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
              {/* Mandatory disclaimer */}
              <p className="text-[9px] text-[#444] font-mono italic flex items-start gap-1.5">
                <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5 text-[#555]" />
                {geoIocs[0]?.disclaimer ?? GEOIP_DISCLAIMER}
              </p>
            </div>
          )}

        </div>
      )}
    </div>
  );
}
