import html2canvas from "html2canvas";
import { jsPDF } from "jspdf";
import type { ThreatCase } from "../components/dashboard/types";
import type { CurrentUser } from "./api";
import { LOGO_DATA_URI } from "./logoBase64";

type Language = "en" | "gu";

const gu = {
  title: "ફોરેન્સિક વિશ્લેષણ અહેવાલ",
  sample: "નમૂનાની માહિતી",
  threat: "જોખમ મૂલ્યાંકન",
  ai: "AI વિશ્લેષણ",
  static: "સ્ટેટિક વિશ્લેષણ",
  dynamic: "ડાયનેમિક વિશ્લેષણ",
  network: "નેટવર્ક ઇન્ટેલિજન્સ",
  geo: "જીઓ-IP એટ્રિબ્યુશન",
  mitre: "MITRE ATT&CK",
  capability: "ક્ષમતાઓ અને ભલામણો",
  custody: "પુરાવા શૃંખલા",
  unavailable: "ઉપલબ્ધ નથી",
  disclaimer: "જીઓ-IP અંદાજિત ભૌગોલિક માહિતી છે; તે ચોક્કસ ભૌતિક સ્થાન નથી.",
  status: "સેન્ડબોક્સ સ્થિતિ",
  available: "ઉપલબ્ધ",
  details: "વિગતો",
  location: "સ્થળ",
  ispAsn: "ISP / ASN",
  flags: "ફ્લેગ્સ",
  yes: "હા",
  no: "ના",
  classification: "વર્ગીકરણ",
  generated: "બનાવ્યાનો સમય",
  keyFindings: "મુખ્ય તારણો",
  executiveSummary: "કાર્યકારી સારાંશ",
  behaviour: "વર્તન",
  networkInterpretation: "નેટવર્ક અર્થઘટન",
  explainedStrings: "સમજાવેલ સ્ટ્રિંગ્સ",
  recommendations: "ભલામણો",
  examiner: "પરીક્ષક",
  department: "વિભાગ",
  page: "પૃષ્ઠ",
  of: "/",
};

const en = {
  title: "Forensic Analysis Report",
  sample: "Sample Information",
  threat: "Threat Assessment",
  ai: "AI Analysis",
  static: "Static Analysis",
  dynamic: "Dynamic Analysis",
  network: "Network Intelligence",
  geo: "Geo-IP Attribution",
  mitre: "MITRE ATT&CK",
  capability: "Capabilities & Recommendations",
  custody: "Chain of Custody",
  unavailable: "Not available",
  disclaimer: "Geo-IP is an approximate geographic estimate and not an exact physical location.",
  status: "Sandbox status",
  available: "Available",
  details: "Details",
  location: "Location",
  ispAsn: "ISP / ASN",
  flags: "Flags",
  yes: "Yes",
  no: "No",
  classification: "Classification",
  generated: "Generated",
  keyFindings: "Key findings",
  executiveSummary: "Executive summary",
  behaviour: "Behaviour",
  networkInterpretation: "Network interpretation",
  explainedStrings: "Explained strings",
  recommendations: "Recommendations",
  examiner: "Examiner",
  department: "Department",
  page: "Page",
  of: "/",
};

const escapeHtml = (value: unknown): string =>
  String(value ?? "").replace(/[&<>"']/g, (char) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[char]!)
  );

const value = (item: unknown, fallback: string): string =>
  item === null || item === undefined || item === "" ? fallback : String(item);

const list = (
  items: unknown[],
  fallback: string,
  render = (item: unknown) => value(item, fallback)
): string =>
  items.length
    ? `<ul style="margin:4px 0;padding-left:18px;">${items
        .map((item) => `<li style="margin-bottom:3px;font-size:11px;line-height:1.5;">${render(item)}</li>`)
        .join("")}</ul>`
    : `<p class="muted">${fallback}</p>`;

function renderInlineMd(text: string): string {
  let res = escapeHtml(text);
  res = res.replace(/\*\*(.*?)\*\*/g, "<b>$1</b>");
  res = res.replace(/__(.*?)__/g, "<b>$1</b>");
  res = res.replace(
    /`([^`]+)`/g,
    '<code style="font-family:monospace;background:#f0f4f8;padding:1px 3px;border-radius:2px;font-size:10px;">$1</code>'
  );
  return res;
}

/**
 * Formats AI-generated text cleanly:
 * - Parses Markdown tables into real HTML tables
 * - Formats bullet lists into <ul><li>
 * - Formats paragraphs with comfortable line-height and spacing
 */
function renderAiText(raw: unknown, unavailableFallback: string): string {
  if (!raw || raw === unavailableFallback || raw === "Not available" || raw === "ઉપલબ્ધ નથી") {
    return `<p class="muted">${escapeHtml(unavailableFallback)}</p>`;
  }

  let normalized = String(raw).replace(/\r\n/g, "\n");
  // If markdown table rows or headers are stuck inline on the same line, separate them with newlines:
  normalized = normalized.replace(/([^\n|]+)(\|[^\n]+\|)/g, "$1\n$2");
  normalized = normalized.replace(/\|\s*\|/g, "|\n|");
  const lines = normalized.trim().split("\n");
  const out: string[] = [];
  let inTable = false;
  let tableHeaderDone = false;
  let inList = false;

  for (let i = 0; i < lines.length; i++) {
    const s = lines[i].trim();

    // Markdown Table check
    if (s.startsWith("|") && s.endsWith("|")) {
      if (inList) {
        out.push("</ul>");
        inList = false;
      }
      const cells = s
        .slice(1, -1)
        .split("|")
        .map((c) => c.trim());

      // Divider row
      if (cells.every((c) => /^:?-+:?$/.test(c))) {
        tableHeaderDone = true;
        continue;
      }

      if (!inTable) {
        inTable = true;
        tableHeaderDone = false;

        // Setup proportional column widths: Step (~22%), What it does (~42%), Evidence basis (~36%)
        let colgroup = "";
        if (cells.length === 3) {
          colgroup = '<colgroup><col style="width:22%;"><col style="width:42%;"><col style="width:36%;"></colgroup>';
        } else if (cells.length === 2) {
          colgroup = '<colgroup><col style="width:30%;"><col style="width:70%;"></colgroup>';
        } else {
          const w = (100 / cells.length).toFixed(1);
          colgroup = `<colgroup>${cells.map(() => `<col style="width:${w}%;">`).join("")}</colgroup>`;
        }

        out.push(
          `<table class="ai-analysis-table" style="width:100%;border-collapse:collapse;font-size:9.5pt;margin:8px 0;table-layout:fixed;page-break-inside:auto;break-inside:auto;">${colgroup}`
        );
      }

      if (!tableHeaderDone) {
        out.push(
          '<thead style="display:table-header-group;"><tr style="page-break-inside:avoid;break-inside:avoid;">' +
            cells
              .map((c, idx) => {
                const w = cells.length === 3 ? (idx === 0 ? "22%" : idx === 1 ? "42%" : "36%") : "";
                const widthStyle = w ? `width:${w};` : "";
                return `<th style="border:1px solid #d6dde8;padding:7px 9px;background:#edf3fa;color:#173b68;font-weight:700;font-size:9.5pt;text-align:left;vertical-align:top;line-height:1.35;overflow-wrap:break-word;word-wrap:break-word;word-break:normal;box-sizing:border-box;${widthStyle}">${renderInlineMd(
                  c
                )}</th>`;
              })
              .join("") +
            "</tr></thead><tbody>"
        );
      } else {
        out.push(
          '<tr style="page-break-inside:avoid;break-inside:avoid;">' +
            cells
              .map((c, idx) => {
                const isStepCol = idx === 0 && cells.length === 3;
                const emphasisStyle = isStepCol
                  ? "font-weight:600;color:#173b68;"
                  : "font-weight:normal;color:#172033;";
                return `<td style="border:1px solid #d6dde8;padding:7px 9px;font-size:9.5pt;line-height:1.45;vertical-align:top;text-align:left;overflow-wrap:break-word;word-wrap:break-word;word-break:normal;box-sizing:border-box;${emphasisStyle}">${renderInlineMd(
                  c
                )}</td>`;
              })
              .join("") +
            "</tr>"
        );
      }
      continue;
    } else {
      if (inTable) {
        out.push("</tbody></table>");
        inTable = false;
        tableHeaderDone = false;
      }
    }

    // Bullet list check
    if (s.startsWith("- ") || s.startsWith("* ")) {
      if (!inList) {
        inList = true;
        out.push('<ul style="margin:4px 0;padding-left:18px;">');
      }
      out.push(
        `<li style="margin-bottom:3px;font-size:11px;line-height:1.5;">${renderInlineMd(
          s.slice(2)
        )}</li>`
      );
      continue;
    } else {
      if (inList) {
        out.push("</ul>");
        inList = false;
      }
    }

    if (!s) {
      continue;
    }

    out.push(
      `<p style="margin:5px 0;line-height:1.5;font-size:11px;color:#172033;text-align:justify;">${renderInlineMd(
        s
      )}</p>`
    );
  }

  if (inTable) {
    out.push("</tbody></table>");
  }
  if (inList) {
    out.push("</ul>");
  }

  return out.join("");
}

export async function generateForensicPDF(
  activeCase: ThreatCase,
  examiner: CurrentUser | null,
  language: Language = "en"
): Promise<void> {
  const t = language === "gu" ? gu : en;
  const unavailable = t.unavailable;
  const reportId = `ER-${activeCase.id}-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}`;
  const network = activeCase.networkIndicators;
  const threat = activeCase.threatAssessment;
  const ai = activeCase.aiAnalysis;
  const dynamic = activeCase.sandboxResult ?? (activeCase as any).dynamicAnalysis ?? null;
  const isPrivateIp = (ip: string) =>
    /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fc00:|fd)/.test(ip);
  const geoByIp = new Map((activeCase.geoIocs ?? []).map((record: any) => [record.ip, record]));
  for (const ip of network?.ips ?? []) {
    if (!geoByIp.has(ip)) geoByIp.set(ip, { ip });
  }
  const geoRecords = Array.from(geoByIp.values());

  // ---- Dynamic Analysis -------------------------------------------------
  const yesNo = (flag: unknown) => (flag === true ? t.yes : flag === false ? t.no : unavailable);
  const dynRows: string[] = [];
  const detailList = (label: string, items: unknown, render: (item: any) => string) => {
    if (Array.isArray(items) && items.length > 0) {
      dynRows.push(
        `<b>${escapeHtml(label)}:</b><ul style="margin:4px 0;padding-left:18px;">${items
          .map(render)
          .join("")}</ul>`
      );
    }
  };
  const listItemText = (item: any): string => {
    if (item && typeof item === "object") {
      const keys = Object.keys(item).filter(
        (k) =>
          item[k] != null &&
          item[k] !== "" &&
          !(Array.isArray(item[k]) && item[k].length === 0)
      );
      const text = keys
        .map(
          (k) =>
            `${k.replace(/_/g, " ")}: ${
              Array.isArray(item[k]) ? item[k].join(", ") : item[k]
            }`
        )
        .join(" · ");
      return `<li style="margin-bottom:3px;font-size:11px;line-height:1.5;">${escapeHtml(text)}</li>`;
    }
    return `<li style="margin-bottom:3px;font-size:11px;line-height:1.5;">${escapeHtml(
      item == null ? "—" : String(item)
    )}</li>`;
  };

  let dynamicHtml: string;
  if (dynamic) {
    const d = dynamic as any;
    const isSim = d.execution_mode === "simulated";
    if (isSim) {
      dynRows.push(
        `<div style="background:#fffbe6;border:1px solid #ffe58f;color:#d48806;padding:6px 10px;border-radius:4px;margin-bottom:8px;font-size:9.5px;font-weight:bold;">⚠️ DYNAMIC RESULTS ARE SIMULATED; NOT OBSERVED BEHAVIOR (HEURISTIC SIMULATION).</div>`
      );
    }
    if (d.dynamic_status === "failed") {
      dynRows.push(
        `<div style="background:#fff1f0;border:1px solid #ffa39e;color:#cf1322;padding:6px 10px;border-radius:4px;margin-bottom:8px;font-size:9.5px;font-weight:bold;">❌ Dynamic analysis failed: ${escapeHtml(d.failure_reason || d.details || d.message || "Detonation error")}</div>`
      );
    }
    dynRows.push(`<b>${t.status}:</b> ${escapeHtml(value(d.status, unavailable))}${isSim ? " (SIMULATED)" : ""}`);
    dynRows.push(`<b>Execution mode:</b> ${isSim ? "Simulated Heuristic" : "Real Detonation"}`);
    const realAvailable = d.real_sandbox_available ?? (d.execution_mode === "real");
    dynRows.push(`<b>Real sandbox available:</b> ${realAvailable ? t.yes : t.no}`);
    dynRows.push(`<b>${t.available}:</b> ${escapeHtml(yesNo(d.available))}`);
    if (d.target_architecture) dynRows.push(`<b>Architecture:</b> ${escapeHtml(d.target_architecture)}`);
    const dynMessage = value(d.message ?? d.details, "");
    if (dynMessage) dynRows.push(`<b>${t.details}:</b> ${escapeHtml(dynMessage)}`);
    if (value(d.task_id, "") !== "") dynRows.push(`<b>Task ID:</b> ${escapeHtml(d.task_id)}`);
    if (d.sandbox_url) dynRows.push(`<b>Sandbox:</b> ${escapeHtml(d.sandbox_url)}`);
    if (d.duration_seconds !== undefined && !isSim)
      dynRows.push(`<b>Duration:</b> ${escapeHtml(String(d.duration_seconds))}s`);
    detailList("Network connections", d.network_connections, (c: any) =>
      `<li style="margin-bottom:3px;font-size:11px;line-height:1.5;">${escapeHtml(
        [c.dest_ip || c.ip, c.dest_port || c.port, c.protocol, c.flagged_c2 ? "(C2)" : "", isSim ? "(simulated)" : ""]
          .filter(Boolean)
          .join(" ")
      )}</li>`
    );
    detailList("C2 endpoints", d.c2_endpoints_detected, listItemText);
    detailList("Process tree", d.process_tree, listItemText);
    detailList("API calls", d.api_calls, listItemText);
    detailList("DNS queries", d.dns_queries, listItemText);
    detailList("Files written", d.files_written, listItemText);
    detailList("Registry changes", d.registry_changes, listItemText);
    detailList("Persistence artifacts", d.persistence_artifacts, listItemText);
    dynamicHtml = dynRows.join("<br>");
  } else {
    dynamicHtml = `<b>${t.status}:</b> ${unavailable}<br><span class="muted">${
      language === "gu"
        ? "ડાયનેમિક સેન્ડબોક્સ પરિણામ આ કેસ માટે ઉપલબ્ધ નથી."
        : "No dynamic sandbox result is available for this case."
    }</span>`;
  }

  // ---- Geo-IP attribution ------------------------------------------------
  const geoHtml = geoRecords.length
    ? `<table><thead><tr><th>IP</th><th>${t.location}</th><th>${t.ispAsn}</th><th>${t.flags}</th></tr></thead><tbody>${geoRecords
        .map((g: any) => {
          const gip = escapeHtml(g.ip ?? unavailable);
          const privateIp = g.ip && isPrivateIp(g.ip);
          const locParts = [g.city, g.region, g.country].filter(Boolean);
          if (locParts.length === 0 && g.country_iso) locParts.push(g.country_iso);
          if (locParts.length === 0 && (g.latitude != null || g.longitude != null))
            locParts.push(`${g.latitude ?? "?"}, ${g.longitude ?? "?"}`);
          const loc = privateIp
            ? `<span class="muted">${
                language === "gu" ? "આંતરિક / ખાનગી નેટવર્ક" : "Internal / Private Network"
              }</span>`
            : locParts.length
            ? escapeHtml(locParts.join(", "))
            : `<span class="muted">${escapeHtml(unavailable)}</span>`;
          const ispAsn = privateIp
            ? `<span class="muted">${
                language === "gu" ? "RFC 1918 / RFC 4193" : "RFC 1918 / RFC 4193"
              }</span>`
            : [g.isp || g.asn_org, g.asn != null ? `AS${g.asn}` : ""]
                .filter(Boolean)
                .map(escapeHtml)
                .join(" · ") || `<span class="muted">${escapeHtml(unavailable)}</span>`;
          const flags = [
            g.is_proxy === true ? "Proxy" : null,
            g.is_hosting === true ? "Hosting" : null,
            g.threat_level ? g.threat_level : null,
          ]
            .filter(Boolean)
            .map(escapeHtml)
            .join(", ");
          return `<tr><td><b>${gip}</b></td><td>${loc}</td><td>${ispAsn}</td><td>${
            flags ? flags : "—"
          }</td></tr>`;
        })
        .join("")}</tbody></table>`
    : `<p class="muted">${t.unavailable}</p>`;

  const findings = threat?.key_findings ?? [];
  const recommendations = ai?.recommendations ?? [];
  const riskContributions = activeCase.riskExplanation?.contributions ?? [];
  const correlations = activeCase.evidenceCorrelation ?? [];
  const timeline = activeCase.evidenceTimeline ?? [];
  const iocs = activeCase.iocIntelligence ?? [];

  // Prepare CSS Stylesheet — natural document flow, comfortable spacing, no forced overflow
  const fontFaceCss = language === "gu"
    ? "@font-face { font-family: NotoGujarati; src: url('/fonts/NotoSansGujarati-Regular.ttf') format('truetype'); }"
    : "";
  const css = `
    ${fontFaceCss}
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    .report-container {
      font-family: ${language === "gu" ? "NotoGujarati, Arial, sans-serif" : "Arial, sans-serif"};
      font-size: 11px;
      line-height: 1.5;
      color: #172033;
      background: #ffffff;
    }

    .page {
      width: 794px;
      height: 1123px;
      min-height: 1123px;
      max-height: 1123px;
      padding: 38px 44px 50px 44px;
      position: relative;
      page-break-after: always;
      background: #ffffff;
      box-sizing: border-box;
      overflow: hidden;
    }

    .page-body {
      width: 706px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      box-sizing: border-box;
    }

    .header {
      display: flex;
      gap: 14px;
      align-items: center;
      border-bottom: 3px solid #173b68;
      padding-bottom: 10px;
      margin-bottom: 4px;
    }

    .logo {
      width: 46px;
      height: 46px;
      object-fit: contain;
    }

    h1 {
      margin: 0;
      color: #173b68;
      font-size: 21px;
      font-weight: bold;
      line-height: 1.2;
    }

    h2 {
      color: #173b68;
      font-size: 14.5px;
      font-weight: bold;
      border-left: 4px solid #d58b1a;
      padding-left: 8px;
      margin: 10px 0 4px 0;
      line-height: 1.3;
    }

    h3 {
      color: #173b68;
      font-size: 12px;
      font-weight: bold;
      margin: 8px 0 3px 0;
      line-height: 1.3;
    }

    .meta, .grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 5px 16px;
      font-size: 11px;
    }

    .card {
      border: 1px solid #d6dde8;
      border-radius: 5px;
      padding: 8px 12px;
      margin: 3px 0;
      background: #fafcff;
      font-size: 11px;
      line-height: 1.5;
    }

    .label {
      color: #52657f;
      font-weight: 700;
    }

    .critical {
      color: #a11b1b;
      font-weight: 700;
    }

    .muted {
      color: #68778c;
    }

    .hash {
      overflow-wrap: anywhere;
      word-break: break-all;
      font-family: monospace;
      font-size: 9.5px;
      line-height: 1.4;
    }

    ul {
      margin: 3px 0;
      padding-left: 18px;
    }

    li {
      margin-bottom: 2.5px;
      font-size: 11px;
      line-height: 1.45;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 10px;
      margin: 5px 0;
      table-layout: fixed;
    }

    th, td {
      border: 1px solid #d6dde8;
      padding: 5px 7px;
      vertical-align: top;
      text-align: left;
      overflow-wrap: anywhere;
      word-break: break-word;
      line-height: 1.4;
    }

    th {
      background: #edf3fa;
      color: #173b68;
      font-weight: bold;
    }

    .ai-analysis-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 9.5pt;
      margin: 8px 0;
      table-layout: fixed;
    }

    .ai-analysis-table thead {
      display: table-header-group;
    }

    .ai-analysis-table tr {
      page-break-inside: avoid;
      break-inside: avoid;
      height: auto;
    }

    .ai-analysis-table th {
      border: 1px solid #d6dde8;
      padding: 7px 9px;
      background: #edf3fa;
      color: #173b68;
      font-weight: 700;
      font-size: 9.5pt;
      text-align: left;
      vertical-align: top;
      line-height: 1.35;
      overflow-wrap: break-word;
      word-wrap: break-word;
      word-break: normal;
      box-sizing: border-box;
    }

    .ai-analysis-table td {
      border: 1px solid #d6dde8;
      padding: 7px 9px;
      font-size: 9.5pt;
      line-height: 1.45;
      vertical-align: top;
      text-align: left;
      overflow-wrap: break-word;
      word-wrap: break-word;
      word-break: normal;
      box-sizing: border-box;
      height: auto;
    }

    .footer {
      position: absolute;
      bottom: 18px;
      left: 44px;
      right: 44px;
      border-top: 1px solid #d6dde8;
      padding-top: 6px;
      color: #68778c;
      font-size: 8.5px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      height: 20px;
    }
  `;

  // Off-screen measurement host in the real DOM
  const host = document.createElement("div");
  host.setAttribute("aria-hidden", "true");
  host.lang = language;
  host.style.cssText =
    "position:absolute;left:-9999px;top:0;width:794px;background:#ffffff;pointer-events:none;z-index:-9999;";
  host.innerHTML = `<style>${css}</style><div class="report-container"></div>`;
  document.body.appendChild(host);

  const reportContainer = host.querySelector(".report-container") as HTMLElement;

  function createPageElement(): { page: HTMLElement; body: HTMLElement; footer: HTMLElement } {
    const page = document.createElement("section");
    page.className = "page";

    const body = document.createElement("div");
    body.className = "page-body";

    const footer = document.createElement("div");
    footer.className = "footer";
    footer.innerHTML = `<span>${escapeHtml(
      reportId
    )}</span><span>OFFICIAL - FORENSIC USE ONLY</span><span class="footer-page-num"></span>`;

    page.appendChild(body);
    page.appendChild(footer);
    return { page, body, footer };
  }

  // Define semantic units of content. Headings are always grouped with their immediate
  // content so they never get separated as orphan headings!
  const contentUnits: string[] = [];

  // Unit 1: Report Header & Classification
  contentUnits.push(`
    <div>
      <div class="header">
        <img class="logo" src="${LOGO_DATA_URI}" alt="E-Rakshak">
        <div>
          <h1>${t.title}</h1>
          <div style="font-size:12px;font-weight:bold;color:#173b68;margin-top:2px;">Gujarat Police Cyber Cell / E-Rakshak</div>
          <div class="muted" style="margin-top:2px;">Report ID: ${escapeHtml(reportId)} | Analysis ID: ${escapeHtml(activeCase.id)}</div>
        </div>
      </div>
      <div class="card">
        <b>${t.classification}:</b> OFFICIAL - FORENSIC USE ONLY<br>
        <b>${t.generated}:</b> ${escapeHtml(new Date().toISOString())}
      </div>
    </div>
  `);

  // Unit 2: Sample Information
  contentUnits.push(`
    <div>
      <h2>${t.sample}</h2>
      <div class="grid">
        <div><span class="label">Sample:</span> ${escapeHtml(activeCase.name)}</div>
        <div><span class="label">Platform / type:</span> ${escapeHtml(activeCase.type)}</div>
        <div><span class="label">Size:</span> ${escapeHtml(activeCase.size)}</div>
        <div><span class="label">Submitted:</span> ${escapeHtml(activeCase.date)}</div>
      </div>
      <div class="card hash" style="margin-top:5px;">
        <b>SHA-256:</b> ${escapeHtml(activeCase.sha256 || activeCase.hash)}<br>
        ${(activeCase as any).unpacked_sha256 || (activeCase.packing as any)?.unpacked_sha256 ? `<b>Unpacked SHA-256:</b> ${escapeHtml((activeCase as any).unpacked_sha256 || (activeCase.packing as any)?.unpacked_sha256)}<br>` : ""}
        <b>MD5:</b> ${escapeHtml(value(activeCase.md5, unavailable))}<br>
        <b>SHA-1:</b> ${escapeHtml(value(activeCase.sha1, unavailable))}
      </div>
    </div>
  `);

  // Unit 3: Threat Assessment
  const riskHtml = riskContributions.length
    ? `<h3>Risk score explanation</h3><ul style="margin:4px 0;padding-left:18px;">${riskContributions
        .map(
          (part) =>
            `<li style="margin-bottom:3px;font-size:11px;">${escapeHtml(part.label)}: <b>+${escapeHtml(
              part.points
            )}</b></li>`
        )
        .join("")}</ul>`
    : "";

  contentUnits.push(`
    <div>
      <h2>${t.threat}</h2>
      <div class="card">
        <div class="grid">
          <div><span class="label">Risk score:</span> <span class="critical">${activeCase.riskScore}/100</span></div>
          <div><span class="label">Threat level:</span> ${escapeHtml(threat?.threat_level ?? activeCase.status)}</div>
          <div><span class="label">Verdict:</span> ${escapeHtml(threat?.verdict ?? activeCase.status)}</div>
          <div><span class="label">Confidence:</span> ${escapeHtml(value(threat?.confidence, unavailable))}%</div>
        </div>
        ${riskHtml}
        <h3>${t.keyFindings}</h3>
        ${list(findings, unavailable, (f) => escapeHtml(f))}
      </div>
    </div>
  `);

  // Unit 4: AI Analysis — kept in single card as requested, flows naturally
  contentUnits.push(`
    <div>
      <h2>${t.ai}</h2>
      <div class="card">
        <b>${t.executiveSummary}:</b>
        ${renderAiText(ai?.executive_summary || activeCase.narrativeSummary, unavailable)}
        <div style="margin-top:8px;"><b>${t.behaviour}:</b></div>
        ${renderAiText(ai?.malware_behavior, unavailable)}
        <div style="margin-top:8px;"><b>${t.networkInterpretation}:</b></div>
        ${renderAiText(ai?.network_interpretation, unavailable)}
      </div>
    </div>
  `);

  // Unit 5: Static Analysis — Packing + YARA + Strings
  contentUnits.push(`
    <div>
      <h2>${t.static}</h2>
      <div class="card">
        <b>Packing:</b> ${
          activeCase.packing?.is_packed
            ? `Detected${
                activeCase.packing.packer_name
                  ? ` (${escapeHtml(activeCase.packing.packer_name)})`
                  : ""
              }`
            : "Not detected"
        }
      </div>
      <h3>YARA rules</h3>
      ${list(
        activeCase.yaraMatchDetails ?? [],
        unavailable,
        (m: any) =>
          `<b>${escapeHtml(m.rule_name)}</b> [${escapeHtml(m.severity)}] - ${escapeHtml(
            m.description
          )}`
      )}
      <h3>${t.explainedStrings}</h3>
      ${list(
        activeCase.explainedStrings ?? [],
        unavailable,
        (s: any) => `<span class="hash">${escapeHtml(s.value)}</span> - ${escapeHtml(s.explanation)}`
      )}
    </div>
  `);

  // Unit 6: Dynamic Analysis
  contentUnits.push(`
    <div>
      <h2>${t.dynamic}</h2>
      <div class="card">${dynamicHtml}</div>
    </div>
  `);

  // Unit 7: Network Intelligence
  contentUnits.push(`
    <div>
      <h2>${t.network}</h2>
      <table>
        <thead>
          <tr><th>IPs</th><th>Domains</th><th>URLs</th><th>DNS queries</th></tr>
        </thead>
        <tbody>
          <tr>
            <td>${(network?.ips ?? []).map(escapeHtml).join("<br>") || unavailable}</td>
            <td>${(network?.domains ?? []).map(escapeHtml).join("<br>") || unavailable}</td>
            <td>${(network?.urls ?? []).map(escapeHtml).join("<br>") || unavailable}</td>
            <td>${(network?.dns_queries ?? []).map(escapeHtml).join("<br>") || unavailable}</td>
          </tr>
        </tbody>
      </table>
    </div>
  `);

  // Unit 8: Geo-IP Attribution
  contentUnits.push(`
    <div>
      <h2>${t.geo}</h2>
      ${geoHtml}
      <p class="muted" style="margin-top:5px;font-size:9.5px;"><b>Disclaimer:</b> ${t.disclaimer}</p>
    </div>
  `);

  // Unit 9: Evidence Correlation & Timeline (if present)
  if (correlations.length || timeline.length || iocs.length) {
    contentUnits.push(`
      <div>
        <h2>Evidence Correlation &amp; Timeline</h2>
        ${
          correlations.length
            ? `<h3>Correlated findings</h3><table><thead><tr><th>Finding</th><th>Static evidence</th><th>Dynamic evidence</th><th>State</th><th>Confidence</th></tr></thead><tbody>${correlations
                .map(
                  (item: any) =>
                    `<tr><td>${escapeHtml(item.finding)}</td><td>${escapeHtml(
                      item.static_evidence || "—"
                    )}</td><td>${escapeHtml(item.dynamic_evidence || "—")}</td><td>${escapeHtml(
                      item.evidence_state || item.correlation || "UNKNOWN"
                    )}</td><td>${escapeHtml(value(item.confidence, unavailable))}</td></tr>`
                )
                .join("")}</tbody></table>`
            : ""
        }
        ${
          iocs.length
            ? `<h3>IoC intelligence</h3><table><thead><tr><th>Indicator</th><th>Type</th><th>Source</th><th>Classification</th><th>Confidence</th></tr></thead><tbody>${iocs
                .map(
                  (item: any) =>
                    `<tr><td>${escapeHtml(item.indicator)}</td><td>${escapeHtml(
                      item.type
                    )}</td><td>${escapeHtml(item.source)}</td><td>${escapeHtml(
                      item.classification
                    )}</td><td>${escapeHtml(value(item.confidence, unavailable))}</td></tr>`
                )
                .join("")}</tbody></table>`
            : ""
        }
        ${
          timeline.length
            ? `<h3>Evidence timeline</h3><table><thead><tr><th>Timestamp</th><th>Event</th><th>Source</th><th>Indicator</th></tr></thead><tbody>${timeline
                .map(
                  (item: any) =>
                    `<tr><td>${escapeHtml(item.timestamp || "—")}</td><td>${escapeHtml(
                      item.event || "—"
                    )}</td><td>${escapeHtml(item.source || "—")}</td><td>${escapeHtml(
                      item.indicator || "—"
                    )}</td></tr>`
                )
                .join("")}</tbody></table>`
            : ""
        }
      </div>
    `);
  }

  // Unit 10: MITRE ATT&CK
  contentUnits.push(`
    <div>
      <h2>${t.mitre}</h2>
      <table>
        <thead>
          <tr><th>Technique</th><th>Name</th><th>Confidence</th></tr>
        </thead>
        <tbody>
          ${
            (activeCase.mitreTechniques ?? [])
              .map(
                (m: any) =>
                  `<tr><td>${escapeHtml(m.technique_id)}</td><td>${escapeHtml(
                    m.technique_name
                  )}</td><td>${
                    typeof m.confidence === "number"
                      ? `${Math.round(m.confidence * 100)}%`
                      : unavailable
                  }</td></tr>`
              )
              .join("") || `<tr><td colspan="3">${unavailable}</td></tr>`
          }
        </tbody>
      </table>
    </div>
  `);

  // Unit 11: Capabilities & Recommendations
  contentUnits.push(`
    <div>
      <h2>${t.capability}</h2>
      ${list(
        activeCase.capabilityTags ?? [],
        unavailable,
        (c: any) =>
          `<b>${escapeHtml(c.capability)}</b>: ${escapeHtml(
            Array.isArray(c.evidence) ? c.evidence.join("; ") : c.evidence
          )}`
      )}
      <h3>${t.recommendations}</h3>
      ${list(recommendations, unavailable, (r) => escapeHtml(r))}
    </div>
  `);

  // Unit 12: Chain of Custody
  contentUnits.push(`
    <div>
      <h2>${t.custody}</h2>
      <div class="card">
        <p>${
          language === "gu"
            ? "આ અહેવાલ નીચેના SHA-256 એન્કર દ્વારા વિશ્લેષિત આર્ટિફેક્ટ સાથે જોડાયેલ છે."
            : "This report is anchored to the analysed artifact by the following SHA-256 digest."
        }</p>
        <p class="hash" style="margin:5px 0;"><b>SHA-256:</b> ${escapeHtml(
          activeCase.sha256 || activeCase.hash
        )}</p>
        <p><b>${t.examiner}:</b> ${escapeHtml(
          examiner?.full_name || examiner?.email || unavailable
        )}<br>
        <b>${t.department}:</b> ${escapeHtml(examiner?.department || unavailable)}<br>
        <b>Timestamp:</b> ${escapeHtml(new Date().toISOString())}</p>
      </div>
    </div>
  `);

  // CONTINUOUS DOCUMENT FLOW & INTELLIGENT PAGINATION
  // Usable height inside .page-body is 1010px (leaving safe clearance from footer)
  const MAX_USABLE_PAGE_HEIGHT = 1010;
  const pages: { page: HTMLElement; body: HTMLElement; footer: HTMLElement }[] = [];

  let curPage = createPageElement();
  reportContainer.appendChild(curPage.page);
  pages.push(curPage);

  function appendUnit(unitEl: HTMLElement) {
    let activeP = pages[pages.length - 1];
    const aiTable = unitEl.querySelector("table.ai-analysis-table") as HTMLTableElement | null;

    if (!aiTable) {
      // Standard non-AI-table unit: keep intact, start fresh page only on overflow
      activeP.body.appendChild(unitEl);
      if (activeP.body.offsetHeight > MAX_USABLE_PAGE_HEIGHT && activeP.body.children.length > 1) {
        activeP.body.removeChild(unitEl);
        activeP = createPageElement();
        reportContainer.appendChild(activeP.page);
        pages.push(activeP);
        activeP.body.appendChild(unitEl);
      }
      return;
    }

    // AI Analysis unit containing table:
    const tbody = aiTable.querySelector("tbody");
    const rows = tbody ? Array.from(tbody.querySelectorAll("tr")) : [];

    // First try placing the full unit
    activeP.body.appendChild(unitEl);
    if (activeP.body.offsetHeight <= MAX_USABLE_PAGE_HEIGHT) {
      // Entire unit with table fits cleanly on current page!
      return;
    }

    // If unit overflows, check how many rows can fit
    const thead = aiTable.querySelector("thead");
    const theadHtml = thead ? thead.outerHTML : "";
    const colgroupHtml = aiTable.querySelector("colgroup")?.outerHTML || "";
    const tableStyle = aiTable.getAttribute("style") || "";

    // Detach all rows temporarily to test capacity
    rows.forEach((r) => r.remove());

    if (activeP.body.offsetHeight > MAX_USABLE_PAGE_HEIGHT && activeP.body.children.length > 1) {
      // Base unit does not fit on current page; move base unit to fresh page
      activeP.body.removeChild(unitEl);
      activeP = createPageElement();
      reportContainer.appendChild(activeP.page);
      pages.push(activeP);
      activeP.body.appendChild(unitEl);
    }

    // Now re-add rows one by one to determine how many fit on activeP
    let rowsThatFit = 0;
    for (let i = 0; i < rows.length; i++) {
      tbody?.appendChild(rows[i]);
      if (activeP.body.offsetHeight > MAX_USABLE_PAGE_HEIGHT && i > 0) {
        rows[i].remove();
        rowsThatFit = i;
        break;
      }
      rowsThatFit = i + 1;
    }

    if (rowsThatFit >= rows.length) {
      // All rows fit now
      return;
    }

    if (rowsThatFit <= 0) {
      // Guarantee progress: force at least 1 row to stay on this page to prevent infinite recursive loop!
      if (rows.length > 0) {
        tbody?.appendChild(rows[0]);
        rowsThatFit = 1;
      }
    }

    // Safety guard against runaway pagination
    if (pages.length >= 10) {
      return;
    }

    // Remaining rows need to continue onto the next page
    const remainingRows = rows.slice(rowsThatFit);

    // Detach any sibling nodes inside the card AFTER the table
    const parentCard = aiTable.parentElement;
    const trailingNodes: Node[] = [];
    if (parentCard) {
      let passedTable = false;
      Array.from(parentCard.childNodes).forEach((n) => {
        if (passedTable) {
          trailingNodes.push(n);
        } else if (n === aiTable) {
          passedTable = true;
        }
      });
      trailingNodes.forEach((n) => {
        if (n.parentNode) {
          n.parentNode.removeChild(n);
        }
      });
    }

    // Start a new page for continuation
    activeP = createPageElement();
    reportContainer.appendChild(activeP.page);
    pages.push(activeP);

    // Build continuation card with repeated table header
    const contUnit = document.createElement("div");
    const contCard = document.createElement("div");
    contCard.className = "card";
    contCard.style.marginTop = "0";

    const contTable = document.createElement("table");
    contTable.className = "ai-analysis-table";
    if (tableStyle) contTable.setAttribute("style", tableStyle);
    contTable.innerHTML = `${colgroupHtml}${theadHtml}<tbody></tbody>`;
    const contTbody = contTable.querySelector("tbody")!;

    contCard.appendChild(contTable);
    trailingNodes.forEach((n) => contCard.appendChild(n));
    contUnit.appendChild(contCard);

    remainingRows.forEach((r) => contTbody.appendChild(r));

    // Recursively append in case remaining rows exceed the new page
    appendUnit(contUnit);
  }

  for (const unitHtml of contentUnits) {
    const tempDiv = document.createElement("div");
    tempDiv.innerHTML = unitHtml;
    const unitEl = tempDiv.firstElementChild as HTMLElement;
    if (!unitEl) continue;
    appendUnit(unitEl);
  }

  // Update Page Numbering across all footers (Page X / Y)
  const totalPages = pages.length;
  pages.forEach((p, idx) => {
    const numEl = p.footer.querySelector(".footer-page-num");
    if (numEl) {
      numEl.textContent = `${t.page} ${idx + 1} ${t.of} ${totalPages}`;
    }
  });

  // Render to Canvas and PDF using jsPDF
  try {
    await Promise.race([
      document.fonts.ready,
      new Promise((resolve) => setTimeout(resolve, 800)),
    ]);
    const pdf = new jsPDF({
      orientation: "portrait",
      unit: "mm",
      format: "a4",
      compress: true,
    });

    const maxExportPages = Math.min(pages.length, 10);
    for (let i = 0; i < maxExportPages; i++) {
      const pageEl = pages[i].page;
      const canvas = await Promise.race([
        html2canvas(pageEl, {
          scale: 1.25,
          useCORS: true,
          allowTaint: true,
          backgroundColor: "#ffffff",
          logging: false,
          imageTimeout: 1000,
          scrollX: 0,
          scrollY: 0,
        }),
        new Promise<HTMLCanvasElement>((_, reject) =>
          setTimeout(() => reject(new Error(`Page ${i + 1} render timed out`)), 4500)
        ),
      ]);

      if (i > 0) {
        pdf.addPage("a4", "portrait");
      }
      pdf.addImage(canvas.toDataURL("image/jpeg", 0.85), "JPEG", 0, 0, 210, 297, undefined, "FAST");
    }

    const safeName = (activeCase.name || "forensic_report").replace(/[^\w.-]+/g, "_");
    pdf.save(`${safeName}_Forensic_Report_${language}.pdf`);
  } catch (renderError) {
    console.warn("Direct canvas render failed, falling back to formatted print dialog:", renderError);
    const safeName = (activeCase.name || "forensic_report").replace(/[^\w.-]+/g, "_");
    const printWin = window.open("", "_blank");
    if (printWin) {
      printWin.document.write(`
        <!DOCTYPE html>
        <html>
          <head>
            <title>${safeName}_Forensic_Report_${language}</title>
            <style>
              ${css}
              @media print {
                body { margin: 0; padding: 0; background: #fff; }
                .page { page-break-after: always; break-after: page; }
              }
            </style>
          </head>
          <body>
            ${reportContainer.innerHTML}
            <script>
              window.onload = function() {
                window.print();
              };
            <\/script>
          </body>
        </html>
      `);
      printWin.document.close();
    } else {
      throw renderError;
    }
  } finally {
    if (host.parentNode) {
      host.parentNode.removeChild(host);
    }
  }
}

// Alias export for compatibility
export const generateForensicPdfReport = generateForensicPDF;
