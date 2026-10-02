import * as React from "react";
import { Download, Check, ShieldCheck, ScrollText, ListChecks, Fingerprint, Cpu } from "lucide-react";
import { ThreatCase } from "./types";
import { CurrentUser } from "../../lib/api";
import { AgencyLogo } from "../AgencyLogo";
import { generateForensicPDF } from "../../lib/reportPdf";

interface AiReportsTabProps {
  activeCase: ThreatCase;
  examiner: CurrentUser | null;
}

const RECOMMENDATION_TEXT: Record<string, { en: string; gu: string }> = {
  sms_otp_theft: {
    en: "Check the victim's banking and payment apps for unauthorized transactions — this sample can intercept SMS/OTP codes.",
    gu: "પીડિતના બેંકિંગ અને પેમેન્ટ એપ્સમાં અનધિકૃત વ્યવહારો તપાસો — આ સેમ્પલ SMS/OTP કોડ ઇન્ટરસેપ્ટ કરી શકે છે.",
  },
  gps_tracking: {
    en: "Confirm whether the device owner's real-time location may have been exposed to a third party.",
    gu: "ખાતરી કરો કે ડિવાઇસ માલિકનું રીયલ-ટાઇમ સ્થાન કોઈ તૃતીય પક્ષને ખુલ્લું પડ્યું હોઈ શકે છે કે નહીં.",
  },
  overlay_phishing: {
    en: "Look for fake login screens the victim may have entered credentials into — this sample can draw UI over legitimate apps.",
    gu: "નકલી લોગિન સ્ક્રીન શોધો જ્યાં પીડિતે ઓળખપત્રો દાખલ કર્યા હોઈ શકે — આ સેમ્પલ કાયદેસર એપ્સ પર UI દોરી શકે છે.",
  },
  data_exfiltration: {
    en: "Pull network logs / router records for connections to the flagged endpoints below to identify what data left the device and when.",
    gu: "નીચે ફ્લેગ કરેલા એન્ડપોઇન્ટ્સ સાથેના જોડાણો માટે નેટવર્ક લોગ / રાઉટર રેકોર્ડ્સ મેળવો જેથી ખબર પડે કે કયો ડેટા ક્યારે ડિવાઇસમાંથી ગયો.",
  },
  keylogging: {
    en: "Treat all passwords typed on this device as compromised and recommend the owner change them from a clean device.",
    gu: "આ ડિવાઇસ પર ટાઇપ કરેલા તમામ પાસવર્ડ સાથે ચેડાં થયા હોવાનું માનો અને માલિકને સ્વચ્છ ડિવાઇસથી તે બદલવાની ભલામણ કરો.",
  },
  uninstall_resistance: {
    en: "Removal likely requires revoking device administrator privileges before the app can be uninstalled normally.",
    gu: "એપને સામાન્ય રીતે અનઇન્સ્ટોલ કરી શકાય તે પહેલાં ડિવાઇસ એડમિનિસ્ટ્રેટર વિશેષાધિકારો રદ કરવા જરૂરી છે.",
  },
  packed: {
    en: "The sample is packed/obfuscated — treat static findings as a lower bound; dynamic detonation is recommended once available.",
    gu: "સેમ્પલ પેક/ઓબ્ફસ્કેટેડ છે — સ્ટેટિક તારણોને નીચલી મર્યાદા ગણો; ડાયનેમિક ડિટોનેશન ઉપલબ્ધ થાય ત્યારે ભલામણ કરવામાં આવે છે.",
  },
  none: {
    en: "No high-confidence malicious capability was confirmed from static analysis alone — consider dynamic/behavioral analysis before closing this case.",
    gu: "ફક્ત સ્ટેટિક વિશ્લેષણથી કોઈ ઉચ્ચ-વિશ્વાસ દુર્ભાવનાપૂર્ણ ક્ષમતાની પુષ્ટિ થઈ નથી — આ કેસ બંધ કરતાં પહેલાં ડાયનેમિક/વર્તન વિશ્લેષણ ધ્યાનમાં લો.",
  },
};

function recommendationsFor(activeCase: ThreatCase, language: "en" | "gu"): string[] {
  const caps = new Set((activeCase.capabilityTags ?? []).map((c: any) => c.capability));
  const keys: string[] = [];
  if (caps.has("sms_otp_theft")) keys.push("sms_otp_theft");
  if (caps.has("gps_tracking")) keys.push("gps_tracking");
  if (caps.has("overlay_phishing")) keys.push("overlay_phishing");
  if (caps.has("data_exfiltration")) keys.push("data_exfiltration");
  if (caps.has("keylogging")) keys.push("keylogging");
  if (caps.has("uninstall_resistance")) keys.push("uninstall_resistance");
  if (activeCase.packing?.is_packed) keys.push("packed");
  if (keys.length === 0) keys.push("none");
  return keys.map((k) => RECOMMENDATION_TEXT[k][language]);
}

// Closed-vocabulary translations used to render backend case data in Gujarati
// (capability names, MITRE technique names, severities, statuses, file types
// and category slugs are all produced by this platform's rule engines, so a
// finite map covers the whole vocabulary — no free-text guessing).
const CAPABILITY_GU: Record<string, string> = {
  sms_otp_theft: "SMS/OTP ચોરી",
  gps_tracking: "GPS લોકેશન ટ્રેકિંગ",
  overlay_phishing: "ઓવરલે ફિશિંગ",
  uninstall_resistance: "અનઇન્સ્ટોલ અવરોધ",
  data_exfiltration: "ડેટા ચોરી/બહાર મોકલવો",
  keylogging: "કીલોગિંગ",
  persistence_registry: "રજિસ્ટ્રી પર્સિસ્ટન્સ",
  persistence_cron: "ક્રોન પર્સિસ્ટન્સ",
  persistence_launchd: "લોંચડેમન પર્સિસ્ટન્સ",
  privilege_escalation: "વિશેષાધિકાર વૃદ્ધિ",
  remote_shell_access: "રિમોટ શેલ એક્સેસ",
  library_hijacking: "લાઇબ્રેરી હાઇજેકિંગ",
};

const MITRE_GU: Record<string, string> = {
  "T1517": "સૂચનાઓ ઍક્સેસ",
  "T1071": "એપ્લિકેશન લેયર પ્રોટોકોલ (C2)",
  "T1417": "ઇનપુટ કેપ્ચર (ઓવરલે)",
  "T1626": "ઉપકરણ એડમિન દુરુપયોગ",
  "T1430": "લોકેશન ટ્રેકિંગ",
  "T1005": "લોકલ સિસ્ટમમાંથી ડેટા",
  "T1547.001": "રજિસ્ટ્રી રન કી ઓટોસ્ટાર્ટ",
  "T1056.001": "ઇનપુટ કેપ્ચર: કીલોગિંગ",
  "T1053.003": "શેડ્યૂલ્ડ ટાસ્ક/ક્રોન",
  "T1543.001": "લોંચ એજન્ટ સિસ્ટમ પ્રોસેસ",
  "T1574.006": "ડાયનેમિક લિંકર હાઇજેકિંગ (LD_PRELOAD)",
  "T1548.001": "સેટયુઇડ/સેટજીઆઇડી દુરુપયોગ",
  "T1059": "કમાન્ડ અને સ્ક્રિપ્ટિંગ ઇન્ટરપ્રિટર",
};

const SEVERITY_GU: Record<string, string> = {
  low: "નીચું",
  medium: "મધ્યમ",
  high: "ઉચ્ચ",
  critical: "ગંભીર",
};

const STATUS_GU: Record<string, string> = {
  malicious: "દુર્ભાવનાપૂર્ણ",
  suspicious: "શંકાસ્પદ",
  clean: "સ્વચ્છ",
  QUARANTINED: "ક્વોરેન્ટાઇન",
  ACTIVE_TRACE: "સક્રિય ટ્રેસ",
  CLEARED: "ક્લિયર",
  ANALYZING: "વિશ્લેષણ થઈ રહ્યું છે",
};

const FILETYPE_GU: Record<string, string> = {
  apk: "Android પેકેજ (APK)",
  pe: "Windows PE",
  exe: "Windows એક્ઝિક્યુટેબલ",
  dll: "Windows DLL",
  elf: "Linux ELF",
  macho: "macOS Mach-O",
  APK: "Android પેકેજ (APK)",
  PE: "Windows PE",
  EXE: "Windows એક્ઝિક્યુટેબલ",
  DLL: "Windows DLL",
  ELF: "Linux ELF",
  MACH_O: "macOS Mach-O",
  SYS: "સિસ્ટમ ફાઇલ",
};

const CATEGORY_GU: Record<string, string> = {
  shell_execution: "શેલ એક્ઝેક્યુશન",
  living_off_the_land: "લિવિંગ-ઓફ-ધ-લેન્ડ ટૂલ્સ",
  download_primitive: "ડાઉનલોડ પ્રિમિટિવ",
  obfuscation: "ઓબ્ફસ્કેશન",
  execution_prep: "એક્ઝેક્યુશન તૈયારી",
  anti_analysis: "એન્ટિ-એનાલિસિસ",
  process_injection: "પ્રોસેસ ઇન્જેક્શન",
  remote_access: "રિમોટ એક્સેસ",
  network_indicator: "નેટવર્ક ઇન્ડિકેટર",
  persistence: "પર્સિસ્ટન્સ",
  filesystem_indicator: "ફાઇલસિસ્ટમ ઇન્ડિકેટર",
  india_scam_rules: "ભારત-વિશિષ્ટ સ્કેમ નિયમો",
  suspicious_strings: "શંકાસ્પદ સ્ટ્રિંગ્સ",
  packed: "પેક્ડ",
  signature: "સિગ્નેચર",
  anomaly: "વિસંગતતા",
  entropy: "એન્ટ્રોપી",
  permission: "પરવાનગીઓ",
  pe_anomaly: "PE વિસંગતતા",
  w_x: "લેખન-એક્ઝેક્યુટેબલ સેક્શન",
};

// Backend free-text is mostly closed vocabulary produced by this platform's
// rule engines (see static-analysis strings/explain.py, rules/builtin.py and
// agents/capability_classifier/capability_rules.py). Mapping the exact strings
// lets the Gujarati report render those fields in Gujarati too instead of
// leaking English sentence fragments into an otherwise-Gujarati document.
const EXPLANATION_GU: Record<string, string> = {
  "Spawns the Windows command interpreter — often used to run attacker-supplied commands.": "Windows કમાન્ડ ઇન્ટરપ્રિટર શરૂ કરે છે — ઘણીવાર હુમલાખોર દ્વારા પૂરા પાડવામાં આવેલા કમાન્ડ ચલાવવા માટે વપરાય છે.",
  "Invokes PowerShell, commonly used for fileless execution or to download a second-stage payload.": "પાવરશેલ શરૂ કરે છે, સામાન્ય રીતે ફાઇલલેસ એક્ઝેક્યુશન અથવા બીજા-તબક્કાનો પેલોડ ડાઉનલોડ કરવા માટે વપરાય છે.",
  "PowerShell 'Invoke-Expression' — executes a string as code, a common way to run obfuscated commands.": "પાવરશેલ 'ઇનવોક-એક્સપ્રેશન' — સ્ટ્રિંગને કોડ તરીકે ચલાવે છે, ઓબ્ફસ્કેટેડ કમાન્ડ ચલાવવાની સામાન્ય રીત.",
  "Downloads and often immediately executes remote content — a classic dropper pattern.": "રિમોટ સામગ્રી ડાઉનલોડ કરીને ઘણીવાર તરત ચલાવે છે — ઉત્તમ ડ્રોપર પેટર્ન.",
  "Spawns a Unix shell — indicates the sample can execute arbitrary commands.": "Unix શેલ શરૂ કરે છે — દર્શાવે છે કે નમૂનો કોઈપણ કમાન્ડ ચલાવી શકે છે.",
  "Uses 'wget' to fetch a remote file — a common way to pull down a second-stage payload.": "રિમોટ ફાઇલ લાવવા 'wget' વાપરે છે — બીજા-તબક્કાનો પેલોડ લાવવાની સામાન્ય રીત.",
  "Uses 'curl' to fetch or transmit data over the network — may be used for download or exfiltration.": "નેટવર્ક પર ડેટા લાવવા કે મોકલવા 'curl' વાપરે છે — ડાઉનલોડ કે ચોરી માટે વપરાય શકે છે.",
  "Decodes Base64 data — often used to deobfuscate a hidden payload at runtime.": "Base64 ડેટા ડીકોડ કરે છે — ઘણીવાર છુપાયેલા પેલોડને રનટાઇમમાં ડિઓબ્ફસ્કેટ કરવા વપરાય છે.",
  "Marks a file executable — typically a step just before running a dropped payload.": "ફાઇલને એક્ઝિક્યુટેબલ બનાવે છે — સામાન્ય રીતે ડ્રોપ કરેલા પેલોડ ચલાવતા પહેલાંનું પગલું.",
  "Uses the trusted Windows 'rundll32' utility to execute code — a common defense-evasion technique.": "વિશ્વસનીય Windows 'rundll32' યુટિલિટી દ્વારા કોડ ચલાવે છે — સામાન્ય ડિફેન્સ-એવેઝન તકનીક.",
  "Uses 'regsvr32' to run code via a registered COM/script handler — a known AppLocker/defense bypass.": "'regsvr32' દ્વારા નોંધાયેલા COM/સ્ક્રિપ્ટ હેન્ડલરથી કોડ ચલાવે છે — જાણીતો AppLocker/ડિફેન્સ બાયપાસ.",
  "Uses 'mshta' to execute HTML Application (.hta) code — commonly abused to run scripts while evading detection.": "'mshta' દ્વારા HTML એપ્લિકેશન (.hta) કોડ ચલાવે છે — શોધ ટાળતી વખતે સ્ક્રિપ્ટ ચલાવવા દુરુપયોગ થાય છે.",
  "Uses 'certutil', a trusted Windows tool, to decode or download files — a well-known evasion trick.": "'certutil', વિશ્વસનીય Windows સાધન, ફાઇલો ડીકોડ કે ડાઉનલોડ કરવા વાપરે છે — જાણીતી એવેઝન યુક્તિ.",
  "PowerShell 'IEX' (Invoke-Expression) shorthand — executes a string as code, often obfuscated.": "પાવરશેલ 'IEX' (ઇનવોક-એક્સપ્રેશન) શોર્ટકટ — સ્ટ્રિંગને કોડ તરીકે ચલાવે છે, ઘણીવાર ઓબ્ફસ્કેટેડ.",
  "Evaluates a string as code at runtime — a common way to hide the sample's real logic from static scanning.": "રનટાઇમમાં સ્ટ્રિંગને કોડ તરીકે ચકાસે છે — સ્ટેટિક સ્કેનિંગથી નમૂનાનું વાસ્તવિક લોજિક છુપાવવાની સામાન્ય રીત.",
  "Calls the C library 'system()' function to run an arbitrary shell command.": "કોઈપણ શેલ કમાન્ડ ચલાવવા C લાઇબ્રેરીનું 'system()' કાર્ય બોલાવે છે.",
  "Uses 'ptrace' — commonly used for anti-debugging checks or to inject into another process.": "'ptrace' વાપરે છે — સામાન્ય રીતે એન્ટિ-ડીબગિંગ ચકાસણી અથવા બીજી પ્રક્રિયામાં ઇન્જેક્ટ કરવા માટે.",
  "Reads its own process information — often used to detect debuggers or sandboxing.": "પોતાની પ્રક્રિયાની માહિતી વાંચે છે — ડીબગર કે સેન્ડબોક્સિંગ શોધવા ઘણીવાર વપરાય છે.",
  "Creates a child process without fully copying the parent — sometimes paired with code injection.": "પેરેન્ટની નકલ કર્યા વગર ચાઇલ્ડ પ્રક્રિયા બનાવે છે — ક્યારેક કોડ ઇન્જેક્શન સાથે વપરાય છે.",
  "Indicates a reverse-shell pattern, granting an attacker interactive remote control of the device.": "રિવર્સ-શેલ પેટર્ન દર્શાવે છે, હુમલાખોરને ઉપકરણનો ઇન્ટરેક્ટિવ રિમોટ નિયંત્રણ આપે છે.",
  "Uses netcat with command execution ('-e') — a classic way to open a reverse shell to an attacker.": "કમાન્ડ એક્ઝેક્યુશન ('-e') સાથે netcat વાપરે છે — હુમલાખોર સામે રિવર્સ શેલ ખોલવાની ઉત્તમ રીત.",
  "Embedded URL — a potential command-and-control (C2) or data-exfiltration destination.": "એમ્બેડેડ URL — સંભવિત કમાન્ડ-એન્ડ-કંટ્રોલ (C2) અથવા ડેટા-ચોરી ગંતવ્ય.",
  "Embedded IP address — a potential C2 server or exfiltration destination hardcoded into the sample.": "એમ્બેડેડ IP સરનામું — નમૂનામાં હાર્ડકોડેડ સંભવિત C2 સર્વર અથવા ચોરી ગંતવ્ય.",
  "Embedded IPv6 address — a potential C2 server or exfiltration destination hardcoded into the sample.": "એમ્બેડેડ IPv6 સરનામું — નમૂનામાં હાર્ડકોડેડ સંભવિત C2 સર્વર અથવા ચોરી ગંતવ્ય.",
  "Embedded domain name — a potential C2 or exfiltration destination; worth a threat-intel lookup.": "એમ્બેડેડ ડોમેન નામ — સંભવિત C2 કે ચોરી ગંતવ્ય; ભય-માહિતી તપાસ યોગ્ય.",
  "Embedded email address — may be used for exfiltration, C2 registration, or attacker attribution.": "એમ્બેડેડ ઇમેઇલ સરનામું — ચોરી, C2 નોંધણી, અથવા હુમલાખોર ઓળખ માટે વપરાય શકે છે.",
  "Windows registry path — may indicate persistence via a Run key or other autostart location.": "Windows રજિસ્ટ્રી પાથ — Run કી અથવા અન્ય ઓટોસ્ટાર્ટ સ્થાન દ્વારા પર્સિસ્ટન્સ દર્શાવી શકે છે.",
  "Windows filesystem path — shows where the sample reads, writes, or installs itself.": "Windows ફાઇલસિસ્ટમ પાથ — નમૂનો ક્યાં વાંચે, લખે કે સ્થાપિત થાય તે દર્શાવે છે.",
  "Unix filesystem path — shows where the sample reads, writes, or installs itself.": "Unix ફાઇલસિસ્ટમ પાથ — નમૂનો ક્યાં વાંચે, લખે કે સ્થાપિત થાય તે દર્શાવે છે.",
};

const YARA_DESC_GU: Record<string, string> = {
  "The binary references APIs commonly associated with process injection, evasion, or remote execution.": "બાઇનરી પ્રોસેસ ઇન્જેક્શન, એવેઝન, અથવા રિમોટ એક્ઝેક્યુશન સાથે સંકળાયેલા APIs દર્શાવે છે.",
  "The target requests permissions capable of sensitive data access or device control.": "લક્ષ્ય સંવેદનશીલ ડેટા ઍક્સેસ અથવા ઉપકરણ નિયંત્રણ સક્ષમ પરવાનગીઓ માંગે છે.",
  "One or more sections have entropy consistent with compressed, encrypted, or packed content.": "એક અથવા વધુ વિભાગોમાં કમ્પ્રેસ્ડ, એન્ક્રિપ્ટેડ, અથવા પેક્ડ સામગ્રી સાથે સુસંગત એન્ટ્રોપી છે.",
  "Structural characteristics suggest the binary may be packed or obfuscated.": "માળખાકીય લક્ષણો દર્શાવે છે કે બાઇનરી પેક્ડ અથવા ઓબ્ફસ્કેટેડ હોઈ શકે છે.",
  "Extracted strings reference shell execution, living-off-the-land tools, or download primitives.": "એક્સ્ટ્રેક્ટેડ સ્ટ્રિંગ્સ શેલ એક્ઝેક્યુશન, લિવિંગ-ઓફ-ધ-લેન્ડ સાધનો, અથવા ડાઉનલોડ પ્રિમિટિવ્સ દર્શાવે છે.",
  "The target embeds URLs, IP addresses, or domain names that may indicate C2 or exfiltration endpoints.": "લક્ષ્ય C2 અથવા ચોરી એન્ડપોઇન્ટ્સ દર્શાવી શકે તેવા URLs, IP સરનામાં, અથવા ડોમેન નામો ધરાવે છે.",
  "Sections mapped as both writable and executable are commonly used for self-modifying or shellcode-staging code.": "લખી શકાય અને એક્ઝિક્યુટ કરી શકાય તેવા વિભાગો સામાન્ય રીતે સ્વ-સંશોધિત અથવા શેલકોડ-સ્ટેજિંગ કોડ માટે વપરાય છે.",
  "The binary does not carry a recognized digital signature or code signing block.": "બાઇનરીમાં ઓળખી શકાય તેવી ડિજિટલ સહી અથવા કોડ સાઇનિંગ બ્લોક નથી.",
  "The target exhibits structural or metadata anomalies commonly seen in tampered or hand-crafted binaries.": "લક્ષ્ય છેડછાડ કરેલી અથવા હાથે બનાવેલી બાઇનરીઓમાં સામાન્ય રીતે જોવા મળતી માળખાકીય અથવા મેટાડેટા વિસંગતતાઓ દર્શાવે છે.",
  "READ_SMS permission declared": "READ_SMS પરવાનગી જાહેર કરી",
  "matches India-specific scam YARA rule": "ભારત-વિશિષ્ટ સ્કેમ YARA નિયમ સાથે મેળ ખાય છે",
  "observed live SMS content access during detonation": "ડિટોનેશન દરમિયાન લાઇવ SMS સામગ્રી ઍક્સેસ જોવા મળી",
  "ACCESS_FINE_LOCATION permission declared": "ACCESS_FINE_LOCATION પરવાનગી જાહેર કરી",
  "observed live location API calls during detonation": "ડિટોનેશન દરમિયાન લાઇવ લોકેશન API કોલ જોવા મળ્યા",
  "SYSTEM_ALERT_WINDOW permission — can draw fake UI over legitimate apps": "SYSTEM_ALERT_WINDOW પરવાનગી — કાયદેસર એપ્સ પર નકલી UI દોરી શકે છે",
  "requested device admin privileges during detonation — resists uninstall": "ડિટોનેશન દરમિયાન ઉપકરણ એડમિન વિશેષાધિકાર માંગ્યા — અનઇન્સ્ટોલનો અવરોધ કરે છે",
  "hardcoded network endpoint(s) found in static strings": "સ્ટેટિક સ્ટ્રિંગ્સમાં હાર્ડકોડેડ નેટવર્ક એન્ડપોઇન્ટ(ઓ) મળ્યા",
  "confirmed live connection to flagged C2 endpoint": "ફ્લેગ કરેલા C2 એન્ડપોઇન્ટ સાથે લાઇવ જોડાણ પુષ્ટિ થયું",
  "observed keyboard-hooking API calls during detonation": "ડિટોનેશન દરમિયાન કીલોગિંગ API કોલ જોવા મળ્યા",
  "'keylog' string found in static analysis": "સ્ટેટિક વિશ્લેષણમાં 'keylog' સ્ટ્રિંગ મળી",
  "writes to registry Run key — survives reboot": "રજિસ્ટ્રી Run કીમાં લખે છે — રીબૂટ પછી પણ ટકી રહે છે",
  "installs a cron job — survives reboot on Linux": "ક્રોન જોબ સ્થાપિત કરે છે — Linux પર રીબૂટ પછી પણ ટકી રહે છે",
  "installs a LaunchAgent/LaunchDaemon — survives reboot on macOS": "LaunchAgent/LaunchDaemon સ્થાપિત કરે છે — macOS પર રીબૂટ પછી પણ ટકી રહે છે",
  "setuid/setgid import found in binary": "બાઇનરીમાં setuid/setgid ઇમ્પોર્ટ મળ્યો",
  "observed setuid/setgid call during detonation — privilege escalation": "ડિટોનેશન દરમિયાન setuid/setgid કોલ — વિશેષાધિકાર વૃદ્ધિ",
  "spawned a command shell with an active network connection — remote control capability": "સક્રિય નેટવર્ક જોડાણ સાથે કમાન્ડ શેલ શરૂ કર્યું — રિમોટ નિયંત્રણ ક્ષમતા",
  "uses LD_PRELOAD to hijack library loading — stealth/persistence technique": "લાઇબ્રેરી લોડિંગ હાઇજેક કરવા LD_PRELOAD વાપરે છે — સ્ટીલ્થ/પર્સિસ્ટન્સ તકનીક",
};

// Only the PDF export's fixed scaffolding (headings/labels/boilerplate) is
// translated — case data itself (narrative summary, YARA descriptions,
// evidence strings) comes from the backend/engine as-is and stays in
// whatever language it was generated in.
export function AiReportsTab({ activeCase, examiner }: AiReportsTabProps) {
  const [activeBookmark, setActiveBookmark] = React.useState("summary");
  const [language, setLanguage] = React.useState<"en" | "gu">("en");
  const [isExporting, setIsExporting] = React.useState(false);
  const [exportDone, setExportDone] = React.useState(false);
  const [exportError, setExportError] = React.useState<string>("");

  const examinerName = examiner?.full_name || examiner?.email || "Unassigned examiner";
  const examinerDept = examiner?.department || "Department not on file";
  const recommendations = recommendationsFor(activeCase, language);
  const yaraDetails = activeCase.yaraMatchDetails ?? [];
  const explainedStrings = activeCase.explainedStrings ?? [];
  const packing = activeCase.packing;
  const geoIocs = activeCase.geoIocs ?? [];

  // Value-level translators: backend emits fixed slugs/IDs, the report maps
  // them into the active report language (English passthrough, Gujarati map).
  const tx = (guMap: Record<string, string>, value: string | null | undefined): string => {
    if (value == null || value === "") return "—";
    if (language !== "gu") return value;
    return guMap[value] ?? value;
  };
  const txCapability = (value: string) => tx(CAPABILITY_GU, value);
  const txMitre = (id: string, name: string) => (language === "gu" ? MITRE_GU[id] ?? name : name);
  const txSeverity = (value: string) => tx(SEVERITY_GU, value);
  const txStatus = (value: string) => tx(STATUS_GU, value);
  const txFileType = (value: string) => tx(FILETYPE_GU, value);
  const txCategory = (value: string) => tx(CATEGORY_GU, value);
  const txYesNo = (value: boolean | null) => {
    if (value == null) return language === "gu" ? "અજ્ઞાત" : "Unknown";
    return value ? (language === "gu" ? "હા" : "Yes") : language === "gu" ? "ના" : "No";
  };
  // Free-text sent from the backend is mostly this platform's own closed
  // vocabulary — translate exact strings when a match exists, else passthrough.
  const txText = (maps: Record<string, string>[], text: string | null | undefined): string => {
    if (!text) return "—";
    if (language !== "gu") return text;
    for (const map of maps) {
      const hit = map[text];
      if (hit) return hit;
    }
    // Evidence strings occasionally embed dynamic values (e.g. "every 30s") —
    // fall back to the original when no exact match is available.
    return text;
  };
  const txExplanation = (text: string | null | undefined) => txText([EXPLANATION_GU], text);
  const txEvidence = (text: string | null | undefined) => txText([YARA_DESC_GU], text);

  const handleExport = async () => {
    setIsExporting(true);
    setExportDone(false);
    setExportError("");
    try {
      const exportTask = generateForensicPDF(activeCase, examiner, language);
      const timeoutTask = new Promise((_, reject) =>
        setTimeout(() => reject(new Error("PDF compilation timed out. Please try again.")), 30000)
      );
      await Promise.race([exportTask, timeoutTask]);
      setExportDone(true);
      setTimeout(() => setExportDone(false), 2500);
    } catch (err: any) {
      console.error("PDF export error:", err);
      setExportError(err?.message || "Failed to generate PDF report. Please try again.");
    } finally {
      setIsExporting(false);
    }
  };
  const bookmarks = [
    { id: "summary", label: "1. Case Summary" },
    { id: "timeline", label: "2. Evidence Timeline" },
    { id: "ai_analysis", label: "3. AI Analysis" },
    { id: "static", label: "4-5. Identification & Findings" },
    { id: "mitre", label: "6-7. MITRE & Capabilities" },
    { id: "examiner", label: "8-9. Recommendations & Examiner" },
  ];

  return (
    <div className="space-y-6">

      {/* Tab controls */}
      <div className="flex justify-between items-center border-b border-[#222222]/80 pb-4">
        <div>
          <h3 className="text-base font-bold text-white uppercase tracking-wider font-sans">
            Forensic Analysis Report
          </h3>
          <p className="text-[11px] text-[#A0A0A0] font-light font-sans">
            Automated static-analysis findings, intended to assist an investigator's assessment — not a substitute for a qualified forensic examiner's review.
          </p>
        </div>

        <div className="flex flex-col items-end gap-2 shrink-0">
          <div className="flex items-center gap-2">
            <div className="flex rounded border border-[#222222] overflow-hidden text-[10px] font-mono font-bold uppercase">
              <button
                onClick={() => setLanguage("en")}
                className={`px-3 py-1.5 transition-colors ${language === "en" ? "bg-[#16ff4d] text-[#090909]" : "bg-[#111111] text-[#A0A0A0] hover:text-white"}`}
              >
                EN
              </button>
              <button
                onClick={() => setLanguage("gu")}
                className={`px-3 py-1.5 transition-colors ${language === "gu" ? "bg-[#16ff4d] text-[#090909]" : "bg-[#111111] text-[#A0A0A0] hover:text-white"}`}
              >
                ગુ
              </button>
            </div>
            <button
              onClick={handleExport}
              disabled={isExporting}
              className={`px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider rounded border transition-all flex items-center gap-2 select-none ${
                isExporting
                  ? "bg-[#111111] border-[#222222] text-[#A0A0A0] cursor-not-allowed animate-pulse"
                  : exportDone
                    ? "bg-[#16ff4d]/10 border-[#16ff4d]/40 text-[#16ff4d]"
                    : "bg-[#16ff4d] hover:bg-[#16ff4d]/95 border-[#16ff4d] text-[#090909]"
              }`}
            >
              {isExporting ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-[#A0A0A0] border-t-transparent rounded-full animate-spin" />
                  Compiling PDF...
                </>
              ) : exportDone ? (
                <>
                  <Check className="w-4 h-4 text-[#16ff4d]" />
                  Report Downloaded
                </>
              ) : (
                <>
                  <Download className="w-4 h-4" />
                  Export PDF Report
                </>
              )}
            </button>
          </div>
          {exportError ? (
            <span className="text-[10px] font-mono text-[#ff4040]">{exportError}</span>
          ) : null}
          {language === "gu" && (
            <span className="text-[9px] font-mono text-[#f4b400] max-w-xs text-right">
              Gujarati labels are machine-translated — have a native speaker review before formal use.
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">

        {/* Section navigation */}
        <div className="lg:col-span-3 space-y-4">
          <span className="text-[10px] font-mono text-[#6F6F6F] uppercase tracking-widest block font-bold">
            REPORT SECTIONS
          </span>
          <div className="bg-[#111111] border border-[#222222] rounded-lg p-2.5 space-y-1">
            {bookmarks.map((bm) => (
              <button
                key={bm.id}
                onClick={() => setActiveBookmark(bm.id)}
                className={`w-full text-left font-sans text-xs px-3 py-2 rounded transition-colors block ${
                  activeBookmark === bm.id
                    ? "bg-[#16ff4d]/10 text-[#16ff4d] font-bold border border-[#16ff4d]/20"
                    : "text-[#A0A0A0] hover:bg-[#171717] hover:text-white"
                }`}
              >
                {bm.label}
              </button>
            ))}
          </div>
        </div>

        {/* Document preview */}
        <div className="lg:col-span-9 bg-[#111111] border border-[#222222] rounded-lg shadow-2xl p-8 max-w-3xl mx-auto space-y-6 relative overflow-hidden text-[#A0A0A0] select-text">

          {/* Letterhead */}
          <div className="flex justify-between items-start border-b border-[#222222] pb-6 font-mono text-[10px]">
            <div className="flex items-center gap-3">
              <AgencyLogo className="w-10 h-10 object-contain shrink-0" />
              <div className="space-y-1">
                <span className="text-sm font-bold text-white font-sans tracking-wide block">SentinelScan Forensic Analysis Report</span>
                <p className="text-[#6F6F6F]">E-RAKSHAK CYBER CRIME INVESTIGATION PLATFORM · GUJARAT POLICE (CYBER CELL)</p>
                <p className="text-[#6F6F6F]">CASE ID: <span className="text-white font-bold">{activeCase.id}</span></p>
              </div>
            </div>
            <div className="text-right space-y-1">
              <span className={`px-2 py-0.5 rounded font-bold uppercase text-[8px] tracking-wider border ${
                activeCase.status === "QUARANTINED" ? "bg-red-950/40 border-red-500/20 text-[#ff4040]" :
                activeCase.status === "ACTIVE_TRACE" ? "bg-yellow-950/40 border-yellow-500/20 text-[#f4b400]" :
                "bg-green-950/40 border-green-500/20 text-[#16ff4d]"
              }`}>
                {activeCase.status.replace("_", " ")}
              </span>
              <p className="text-[#6F6F6F]">{activeCase.date} UTC</p>
            </div>
          </div>

          {activeBookmark === "summary" && (
            <div className="space-y-4">
              <h4 className="text-white text-xs font-bold uppercase tracking-wider border-l-2 border-[#16ff4d] pl-2 font-mono flex items-center gap-2">
                <ScrollText className="w-3.5 h-3.5" /> 1. Case Summary
              </h4>

              {/* Threat Assessment Badges */}
              {activeCase.threatAssessment && (
                <div className="flex flex-wrap gap-2 items-center">
                  <span className={`px-2.5 py-1 rounded text-[9px] font-mono font-bold uppercase border ${
                    activeCase.threatAssessment.threat_level === "SEVERE" ? "bg-red-950/50 border-red-400/30 text-red-300" :
                    activeCase.threatAssessment.threat_level === "CRITICAL" ? "bg-red-950/40 border-red-500/20 text-[#ff4040]" :
                    activeCase.threatAssessment.threat_level === "HIGH" ? "bg-yellow-950/40 border-yellow-500/20 text-[#f4b400]" :
                    activeCase.threatAssessment.threat_level === "MEDIUM" ? "bg-yellow-950/20 border-yellow-500/10 text-yellow-400" :
                    "bg-green-950/40 border-green-500/20 text-[#16ff4d]"
                  }`}>{activeCase.threatAssessment.threat_level}</span>
                  <span className={`px-2.5 py-1 rounded text-[9px] font-mono font-bold uppercase border ${
                    activeCase.threatAssessment.verdict === "MALICIOUS" ? "bg-red-950/40 border-red-500/20 text-[#ff4040]" :
                    activeCase.threatAssessment.verdict === "SUSPICIOUS" ? "bg-yellow-950/40 border-yellow-500/20 text-[#f4b400]" :
                    "bg-green-950/40 border-green-500/20 text-[#16ff4d]"
                  }`}>{activeCase.threatAssessment.verdict}</span>
                  <span className="px-2.5 py-1 rounded text-[9px] font-mono border border-[#222222] text-[#A0A0A0]">
                    Confidence: <span className="text-white font-bold">{activeCase.threatAssessment.confidence}%</span>
                  </span>
                  {activeCase.aiAnalysis && (
                    <span className={`px-2 py-1 rounded text-[8px] font-mono border ${
                      activeCase.aiAnalysis.ai_available
                        ? "border-[#16ff4d]/30 text-[#16ff4d] bg-[#16ff4d]/5"
                        : "border-[#f4b400]/30 text-[#f4b400] bg-[#f4b400]/5"
                    }`}>
                      {activeCase.aiAnalysis.ai_available ? "AI: ACTIVE" : "AI: FALLBACK"}
                    </span>
                  )}
                </div>
              )}

              {activeCase.narrativeSummary ? (
                <p className="text-xs leading-relaxed font-sans font-light">{activeCase.narrativeSummary}</p>
              ) : (
                <p className="text-xs leading-relaxed font-sans font-light">
                  Automated static analysis was performed on <span className="text-white font-bold font-mono">{activeCase.name}</span>. No AI-generated plain-language summary is available for this case.
                </p>
              )}
              <div className="bg-[#090909] p-4 rounded border border-[#222222] space-y-2 font-mono text-[11px]">
                <p><span className="text-white font-bold">Sample:</span> {activeCase.name}</p>
                <p><span className="text-white font-bold">File type:</span> {activeCase.type}</p>
                <p><span className="text-white font-bold">Risk score:</span> <span className="text-[#ff4040] font-bold">{activeCase.riskScore}/100</span></p>
                <p><span className="text-white font-bold">Verdict:</span> <span className="text-[#ff4040] font-bold">{activeCase.threatAssessment?.verdict || activeCase.status.replace('_', ' ')}</span></p>
                <p><span className="text-white font-bold">MITRE techniques:</span> {activeCase.mitreCount}</p>
                <p><span className="text-white font-bold">Rule engine matches:</span> {yaraDetails.length}</p>
              </div>

              {(activeCase.riskExplanation?.contributions ?? []).length > 0 && (
                <div className="space-y-1.5">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">RISK SCORE EXPLANATION</span>
                  {activeCase.riskExplanation!.contributions.map((part, index) => (
                    <p key={`${part.label}-${index}`} className="text-[11px] font-mono flex justify-between gap-3 border-b border-[#222222] pb-1">
                      <span>{part.label}</span><span className="text-[#f4b400] font-bold">+{part.points}</span>
                    </p>
                  ))}
                </div>
              )}

              {/* Key Findings */}
              {(activeCase.threatAssessment?.key_findings ?? []).length > 0 && (
                <div className="space-y-1.5">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">KEY FINDINGS</span>
                  {activeCase.threatAssessment!.key_findings.map((f, i) => (
                    <p key={i} className="text-[11px] font-sans font-light flex gap-2">
                      <span className="text-[#ff4040] shrink-0">▸</span> {f}
                    </p>
                  ))}
                </div>
              )}

              {(activeCase.evidenceCorrelation ?? []).length > 0 && (
                <div className="space-y-1.5">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">CORRELATED EVIDENCE</span>
                  {activeCase.evidenceCorrelation!.slice(0, 4).map((item: any, index) => (
                    <div key={`${item.finding}-${index}`} className="bg-[#090909] border border-[#222222] rounded p-2 text-[10px] font-mono">
                      <span className="text-white">{item.finding}</span><br />
                      <span className="text-[#6F6F6F]">{item.evidence_state || item.correlation} · {item.confidence}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeBookmark === "timeline" && (
            <div className="space-y-4">
              <h4 className="text-white text-xs font-bold uppercase tracking-wider border-l-2 border-[#00c2ff] pl-2 font-mono flex items-center gap-2">
                <ListChecks className="w-3.5 h-3.5" /> 2. Analysis Evidence Timeline
              </h4>
              {(activeCase.evidenceTimeline ?? []).length > 0 ? (
                <div className="space-y-2">
                  {activeCase.evidenceTimeline!.map((event: any, index) => (
                    <div key={`${event.timestamp}-${event.event}-${index}`} className="grid grid-cols-[110px_1fr] gap-3 rounded border border-[#222222] bg-[#090909] p-3 text-[10px] font-mono">
                      <span className="text-[#00c2ff] break-all">{event.timestamp || "NOT AVAILABLE"}</span>
                      <div><p className="text-white font-bold">{event.event || "Evidence event"}</p><p className="text-[#A0A0A0] mt-1">{event.source || "Unknown source"} · {event.indicator || "No indicator"} · {event.severity || "INFO"}</p></div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs leading-relaxed font-sans font-light">No timestamped evidence is available for this case. Timeline entries are generated only from actual analysis and sandbox events.</p>
              )}
            </div>
          )}

          {activeBookmark === "ai_analysis" && (
            <div className="space-y-5">
              <h4 className="text-white text-xs font-bold uppercase tracking-wider border-l-2 border-[#00c2ff] pl-2 font-mono flex items-center gap-2">
                <Cpu className="w-3.5 h-3.5" /> 2. AI Analysis — Real Evidence Correlation
              </h4>

              {activeCase.aiAnalysis ? (
                <>
                  {activeCase.aiAnalysis.fallback_used && (
                    <div className="p-3 rounded border border-[#f4b400]/30 bg-[#f4b400]/5 text-[10px] font-mono text-[#f4b400]">
                      ⚠ AI model unavailable or GROQ_API_KEY not configured — showing template fallback. Set GROQ_API_KEY in .env for full AI analysis.
                    </div>
                  )}

                  {/* Executive Summary */}
                  <div className="space-y-2">
                    <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest font-bold block">EXECUTIVE SUMMARY</span>
                    <p className="text-xs leading-relaxed font-sans font-light">{activeCase.aiAnalysis.executive_summary}</p>
                  </div>

                  {/* Malware Behavior */}
                  {activeCase.aiAnalysis.malware_behavior && (
                    <div className="space-y-2">
                      <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest font-bold block">MALWARE BEHAVIOR</span>
                      <p className="text-xs leading-relaxed font-sans font-light">{activeCase.aiAnalysis.malware_behavior}</p>
                    </div>
                  )}

                  {/* Evidence Correlation */}
                  {activeCase.aiAnalysis.evidence_correlation && (
                    <div className="space-y-2">
                      <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest font-bold block">EVIDENCE CORRELATION</span>
                      <p className="text-xs leading-relaxed font-sans font-light">{activeCase.aiAnalysis.evidence_correlation}</p>
                    </div>
                  )}

                  {/* Network Intelligence Interpretation */}
                  {activeCase.aiAnalysis.network_interpretation && (
                    <div className="space-y-2">
                      <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest font-bold block">NETWORK INTELLIGENCE</span>
                      <p className="text-xs leading-relaxed font-sans font-light">{activeCase.aiAnalysis.network_interpretation}</p>
                      {activeCase.networkIndicators && (
                        <div className="grid grid-cols-3 gap-2 font-mono text-[9px] mt-1">
                          <div className="bg-[#090909] p-2 rounded border border-[#222222] text-center">
                            <span className="text-[#00c2ff] font-bold block text-base">{activeCase.networkIndicators.ips.length}</span>
                            <span className="text-[#6F6F6F]">IPs</span>
                          </div>
                          <div className="bg-[#090909] p-2 rounded border border-[#222222] text-center">
                            <span className="text-[#00c2ff] font-bold block text-base">{activeCase.networkIndicators.domains.length}</span>
                            <span className="text-[#6F6F6F]">Domains</span>
                          </div>
                          <div className="bg-[#090909] p-2 rounded border border-[#222222] text-center">
                            <span className="text-[#00c2ff] font-bold block text-base">{activeCase.networkIndicators.urls.length}</span>
                            <span className="text-[#6F6F6F]">URLs</span>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Geo-IP Interpretation */}
                  {activeCase.aiAnalysis.geoip_interpretation && (
                    <div className="space-y-2">
                      <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest font-bold block">GEO-IP INTELLIGENCE</span>
                      <p className="text-xs leading-relaxed font-sans font-light">{activeCase.aiAnalysis.geoip_interpretation}</p>
                      {(activeCase.geoIocs ?? []).length > 0 && (
                        <div className="space-y-1">
                          {(activeCase.geoIocs ?? []).map((g, i) => (
                            <div key={i} className="bg-[#090909] p-2.5 rounded border border-[#222222] font-mono text-[10px] flex justify-between items-center gap-4">
                              <span className="text-[#00c2ff] font-bold">{g.ip}</span>
                              <span className="text-[#A0A0A0] font-sans">
                                {[g.city, g.region, g.country].filter(Boolean).join(", ") || "location unavailable"}
                                {g.isp ? ` · ${g.isp}` : ""}
                                {g.is_proxy ? " · 🔴 Proxy" : ""}
                                {g.is_hosting ? " · ☁ Hosting" : ""}
                              </span>
                            </div>
                          ))}
                          <p className="text-[8px] text-[#6F6F6F] font-mono italic pt-1">
                            ⚠ {(activeCase.geoIocs ?? [])[0]?.disclaimer ?? "Geo-IP is an approximate geographic estimate and not an exact physical location."}
                          </p>
                        </div>
                      )}
                    </div>
                  )}

                  {/* MITRE Techniques Explained */}
                  {(activeCase.aiAnalysis.mitre_techniques_explained ?? []).length > 0 && (
                    <div className="space-y-2">
                      <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest font-bold block">MITRE ATT&CK TECHNIQUES (EVIDENCE-BASED)</span>
                      <div className="space-y-1 font-mono text-[10px]">
                        {activeCase.aiAnalysis.mitre_techniques_explained.map((t, i) => (
                          <p key={i} className="flex gap-2">
                            <span className="text-[#f4b400] shrink-0">▸</span>
                            <span className="text-[#A0A0A0]">{t}</span>
                          </p>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recommendations */}
                  {(activeCase.aiAnalysis.recommendations ?? []).length > 0 && (
                    <div className="space-y-2">
                      <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest font-bold block">INVESTIGATION RECOMMENDATIONS (AI-DERIVED)</span>
                      <div className="space-y-1.5">
                        {activeCase.aiAnalysis.recommendations.map((r, i) => (
                          <p key={i} className="text-[11px] font-sans font-light flex gap-2">
                            <span className="text-[#16ff4d] shrink-0">•</span> {r}
                          </p>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Confidence */}
                  <div className="pt-3 border-t border-[#222222] flex items-center justify-between font-mono text-[10px]">
                    <span className="text-[#6F6F6F]">AI Analysis Confidence</span>
                    <div className="flex items-center gap-2">
                      <div className="w-32 h-1.5 bg-[#222222] rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            activeCase.aiAnalysis.confidence >= 70 ? "bg-[#16ff4d]" :
                            activeCase.aiAnalysis.confidence >= 40 ? "bg-[#f4b400]" : "bg-[#ff4040]"
                          }`}
                          style={{ width: `${activeCase.aiAnalysis.confidence}%` }}
                        />
                      </div>
                      <span className="text-white font-bold">{activeCase.aiAnalysis.confidence}%</span>
                    </div>
                  </div>
                </>
              ) : (
                <div className="p-4 rounded border border-[#222222] text-[11px] font-mono text-[#6F6F6F]">
                  AI analysis data not yet available for this case. Run a fresh analysis to generate it.
                </div>
              )}
            </div>
          )}

          {activeBookmark === "static" && (
            <div className="space-y-4">
              <h4 className="text-white text-xs font-bold uppercase tracking-wider border-l-2 border-[#16ff4d] pl-2 font-mono flex items-center gap-2">
                <Fingerprint className="w-3.5 h-3.5" /> 2-3. File Identification & Static Findings
              </h4>
              <div className="p-4 bg-[#090909] border border-[#222222] rounded-lg font-mono text-[10px] space-y-2 leading-relaxed break-all">
                <p><span className="text-white font-bold">SHA-256:</span> {activeCase.sha256 || activeCase.hash}</p>
                <p><span className="text-white font-bold">MD5:</span> {activeCase.md5 || "not computed"}</p>
                <p><span className="text-white font-bold">SHA-1:</span> {activeCase.sha1 || "not computed"}</p>
              </div>

              {packing && (
                <p className="text-xs leading-relaxed font-sans font-light">
                  {packing.is_packed
                    ? <>This sample appears to be <span className="text-white font-bold">packed/compressed</span>{packing.packer_name ? <> (likely <span className="text-white font-bold">{packing.packer_name}</span>)</> : null}. {packing.unpack_succeeded ? "It was automatically unpacked for deeper analysis." : `Automatic unpacking was ${packing.unpack_attempted ? "attempted but not successful" : "not attempted"}.`}</>
                    : "This sample does not show signs of being packed or compressed — static findings reflect the original binary directly."}
                </p>
              )}

              {yaraDetails.length === 0 ? (
                <p className="text-xs text-[#6F6F6F] font-mono">No rule engine matches were triggered.</p>
              ) : (
                <div className="space-y-2">
                  {yaraDetails.map((m, i) => (
                    <div key={i} className="bg-[#090909] p-3 rounded border border-[#222222] font-mono text-[10px]">
                      <span className={`font-bold ${m.severity === "critical" || m.severity === "high" ? "text-[#ff4040]" : "text-[#f4b400]"}`}>[{m.severity.toUpperCase()}] {m.rule_name}</span>
                      <p className="text-[#A0A0A0] font-sans mt-1">{m.description}</p>
                    </div>
                  ))}
                </div>
              )}

              {explainedStrings.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">NOTABLE EXTRACTED INDICATORS</span>
                  {explainedStrings.slice(0, 10).map((s, i) => (
                    <div key={i} className="bg-[#090909] p-2.5 rounded border border-[#222222] font-mono text-[10px]">
                      <span className="text-[#16ff4d] font-bold break-all">{s.value}</span>
                      <p className="text-[#A0A0A0] font-sans mt-1">{s.explanation}</p>
                    </div>
                  ))}
                </div>
              )}

              {geoIocs.length > 0 && (
                <div className="space-y-2">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">NETWORK INDICATOR GEOLOCATION</span>
                  {geoIocs.map((g, i) => (
                    <div key={i} className="bg-[#090909] p-2.5 rounded border border-[#222222] font-mono text-[10px] flex justify-between items-center gap-4">
                      <span className="text-[#00c2ff] font-bold">{g.ip}</span>
                      <span className="text-[#A0A0A0] font-sans">{[g.city, g.country].filter(Boolean).join(", ") || "location unavailable"}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeBookmark === "mitre" && (
            <div className="space-y-4">
              <h4 className="text-white text-xs font-bold uppercase tracking-wider border-l-2 border-[#16ff4d] pl-2 font-mono flex items-center gap-2">
                <ListChecks className="w-3.5 h-3.5" /> 4-5. MITRE ATT&CK & Capability Assessment
              </h4>

              {(activeCase.mitreTechniques ?? []).length === 0 ? (
                <p className="text-xs text-[#6F6F6F] font-mono">No MITRE techniques detected for this case.</p>
              ) : (
                <div className="space-y-2 font-mono text-[10px]">
                  {(activeCase.mitreTechniques ?? []).map((t: any) => {
                    const conf = typeof t.confidence === "number" ? t.confidence : 0.5;
                    return (
                      <div key={t.technique_id} className="bg-[#090909] p-3 rounded border border-[#222222] flex justify-between items-center gap-4">
                        <span className="text-white font-bold">{t.technique_id} — {t.technique_name}</span>
                        <span className={`font-bold shrink-0 ${conf >= 0.8 ? "text-[#ff4040]" : conf >= 0.6 ? "text-[#f4b400]" : "text-[#16ff4d]"}`}>[{(conf * 100).toFixed(0)}%]</span>
                      </div>
                    );
                  })}
                </div>
              )}

              {(activeCase.capabilityTags ?? []).length > 0 && (
                <div className="space-y-2 pt-2">
                  <span className="text-[10px] text-[#6F6F6F] uppercase tracking-widest block font-bold">CAPABILITY EVIDENCE</span>
                  {(activeCase.capabilityTags ?? []).map((c: any, i: number) => (
                    <div key={i} className="bg-[#090909] p-3 rounded border border-[#222222] font-mono text-[10px]">
                      <span className="text-[#00c2ff] font-bold">{c.capability.replace(/_/g, " ")}</span>
                      <p className="text-[#A0A0A0] font-sans mt-1">{Array.isArray(c.evidence) ? c.evidence.join("; ") : c.evidence}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeBookmark === "examiner" && (
            <div className="space-y-4">
              <h4 className="text-white text-xs font-bold uppercase tracking-wider border-l-2 border-[#16ff4d] pl-2 font-mono flex items-center gap-2">
                <ShieldCheck className="w-3.5 h-3.5" /> 6-7. Recommendations & Examiner Record
              </h4>

              <div className="space-y-2">
                {recommendations.map((rec, i) => (
                  <p key={i} className="text-xs leading-relaxed font-sans font-light flex gap-2">
                    <span className="text-[#16ff4d] shrink-0">•</span> {rec}
                  </p>
                ))}
              </div>

              <div className="pt-6 border-t border-[#222222] space-y-3">
                <div className="p-4 bg-[#090909]/40 border border-[#222222] rounded flex items-center gap-3 font-mono text-[9px]">
                  <div className="w-10 h-10 rounded-full border border-[#16ff4d]/40 flex items-center justify-center text-[#16ff4d] bg-[#16ff4d]/5 shrink-0">
                    <ShieldCheck className="w-5 h-5" />
                  </div>
                  <div className="space-y-1">
                    <span className="text-white font-bold uppercase block text-[10px]">Examining Officer</span>
                    <p className="text-[#A0A0A0] font-sans normal-case">{examinerName}</p>
                    <p className="text-[#6F6F6F] font-sans normal-case">{examinerDept}</p>
                  </div>
                </div>
                <p className="text-[10px] leading-relaxed font-sans font-light text-[#6F6F6F]">
                  This report was produced by automated static analysis. It is intended to assist an investigator's
                  assessment and should be corroborated by a qualified forensic examiner — and, where required,
                  dynamic (sandboxed) analysis — before being relied upon as standalone evidence.
                </p>
              </div>
            </div>
          )}

          <div className="pt-8 border-t border-[#222222] text-center font-mono text-[9px] text-[#6F6F6F] uppercase tracking-wider">
            SentinelScan · Case {activeCase.id}
          </div>

        </div>

      </div>

    </div>
  );
}
