// Payload sensitivity scanner. Detects PII, credentials, internal-only
// markers, and source code patterns flowing through LLM API requests.
// Used to compute the "what's actually leaving" half of shadow-AI risk
// (the other half is "where is it going").

export type SensitivitySeverity = 'critical' | 'high' | 'medium' | 'low';

export interface SensitivityPattern {
  name: string;
  category: 'credential' | 'pii' | 'pci' | 'internal-marker' | 'source-code' | 'health';
  severity: SensitivitySeverity;
  regex: RegExp;
  description: string;
}

const PATTERNS: SensitivityPattern[] = [
  // Credentials
  { name: 'private-key-block', category: 'credential', severity: 'critical', regex: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/i, description: 'Private key block in payload.' },
  { name: 'aws-access-key', category: 'credential', severity: 'critical', regex: /\bAKIA[0-9A-Z]{16}\b/, description: 'AWS access key ID.' },
  { name: 'api-key-prefix', category: 'credential', severity: 'critical', regex: /\b(?:sk|pk|api|sk-proj|sk-live|sk-test)[-_][A-Za-z0-9]{20,}/i, description: 'API/secret key with conventional prefix.' },
  { name: 'jwt-token', category: 'credential', severity: 'high', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, description: 'JWT token.' },
  { name: 'github-pat', category: 'credential', severity: 'critical', regex: /\bghp_[A-Za-z0-9]{36,}\b/, description: 'GitHub personal access token.' },
  { name: 'slack-token', category: 'credential', severity: 'critical', regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, description: 'Slack token.' },
  { name: 'password-in-text', category: 'credential', severity: 'high', regex: /\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{6,}/i, description: 'Inline password assignment.' },

  // PII
  { name: 'ssn-us', category: 'pii', severity: 'high', regex: /\b\d{3}-\d{2}-\d{4}\b/, description: 'US SSN-like pattern.' },
  { name: 'iban', category: 'pii', severity: 'high', regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{12,28}\b/, description: 'IBAN.' },
  { name: 'us-phone', category: 'pii', severity: 'low', regex: /\b\(\d{3}\)\s*\d{3}-\d{4}\b/, description: 'US phone number.' },
  { name: 'email', category: 'pii', severity: 'low', regex: /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/, description: 'Email address.' },
  { name: 'date-of-birth', category: 'pii', severity: 'medium', regex: /\b(?:DOB|date of birth|d\.o\.b\.)[:\s]+\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/i, description: 'Date of birth marker.' },

  // Payment / financial
  { name: 'credit-card', category: 'pci', severity: 'critical', regex: /\b(?:\d{4}[- ]?){3}\d{4}\b/, description: 'Credit card number.' },
  { name: 'cvv', category: 'pci', severity: 'high', regex: /\b(?:CVV|CVC|CVV2)[:\s]+\d{3,4}\b/i, description: 'CVV/CVC marker.' },

  // Health
  { name: 'mrn', category: 'health', severity: 'high', regex: /\b(?:MRN|medical record (?:number|no\.?))[:\s]+[A-Z0-9-]{6,}/i, description: 'Medical record number.' },
  { name: 'icd-code', category: 'health', severity: 'medium', regex: /\b(?:ICD[- ]?(?:9|10)[:\s]+)?[A-TV-Z]\d{2}(?:\.\d{1,4})?\b/, description: 'ICD diagnosis code.' },

  // Internal markers
  { name: 'classified-marker', category: 'internal-marker', severity: 'critical', regex: /\b(?:CONFIDENTIAL|SECRET|TOP[- ]SECRET|INTERNAL ONLY|RESTRICTED|FOUO|PROPRIETARY)\b/, description: 'Document classification marker.' },
  { name: 'merger-marker', category: 'internal-marker', severity: 'high', regex: /\b(?:project (?:codename|cobalt|titan|orion|atlas)|deal (?:codename|alpha|bravo))\b/i, description: 'Common deal/M&A codename pattern.' },

  // Source code
  { name: 'aws-sdk-creds', category: 'source-code', severity: 'critical', regex: /aws_secret_access_key\s*=\s*["']?[A-Za-z0-9\/+]{30,}/i, description: 'AWS SDK credentials in code.' },
  { name: 'connection-string', category: 'source-code', severity: 'high', regex: /\b(?:postgres|mysql|mongodb|redis):\/\/[^:\/\s]+:[^@\/\s]+@/i, description: 'Database connection string with credentials.' },
];

export interface SensitivityHit {
  patternName: string;
  category: SensitivityPattern['category'];
  severity: SensitivitySeverity;
  description: string;
  matchedSnippet: string;
}

export interface PayloadScanResult {
  payloadId: string | null;
  hits: SensitivityHit[];
  highestSeverity: SensitivitySeverity | null;
  shouldBlock: boolean;
  byCategory: Record<SensitivityPattern['category'], number>;
}

const SEV_RANK: Record<SensitivitySeverity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const SNIPPET_LEN = 24;

function redact(s: string): string {
  if (s.length <= 6) return '****';
  return s.slice(0, 4) + '****' + s.slice(-2);
}

export function scanPayload(payload: string, payloadId: string | null = null): PayloadScanResult {
  const hits: SensitivityHit[] = [];
  let highestSeverity: SensitivitySeverity | null = null;
  const byCategory: Record<SensitivityPattern['category'], number> = {
    credential: 0, pii: 0, pci: 0, 'internal-marker': 0, 'source-code': 0, health: 0,
  };

  for (const p of PATTERNS) {
    const m = payload.match(p.regex);
    if (m) {
      hits.push({
        patternName: p.name,
        category: p.category,
        severity: p.severity,
        description: p.description,
        matchedSnippet: redact(m[0].slice(0, SNIPPET_LEN)),
      });
      byCategory[p.category]++;
      if (highestSeverity === null || SEV_RANK[p.severity] > SEV_RANK[highestSeverity]) {
        highestSeverity = p.severity;
      }
    }
  }

  const shouldBlock = highestSeverity === 'critical' || highestSeverity === 'high';

  return { payloadId, hits, highestSeverity, shouldBlock, byCategory };
}
