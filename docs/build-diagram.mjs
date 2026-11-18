// Generates docs/architecture.svg with an explicit, hand-tuned layout and the
// official AWS Architecture Icons in docs/icons/ (embedded as data URIs, so the
// output is self-contained).
// Run from the cdk directory: npm run diagram
// PNG: rsvg-convert -z 2 docs/architecture.svg -o docs/architecture.png
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DOCS = dirname(fileURLToPath(import.meta.url));
const OUT = join(DOCS, 'architecture.svg');
const W = 1600;
const H = 900;
const FONT = 'Helvetica, Arial, sans-serif';

// AWS architecture icon category colors, used for connectors and labels.
const C = {
  ink: '#16191F', muted: '#545B64', line: '#232F3E',
  network: '#8C4FFF', security: '#DD344C', compute: '#ED7100', ml: '#01A88D',
  database: '#C925D1', storage: '#7AA116', integration: '#E7157B',
};

const ICON_FILES = {
  user: 'User.svg',
  waf: 'AWSWAF.svg',
  cloudfront: 'AmazonCloudFront.svg',
  lambda: 'AWSLambda.svg',
  s3: 'AmazonSimpleStorageService.svg',
  cognito: 'AmazonCognito.svg',
  secrets: 'AWSSecretsManager.svg',
  rekognition: 'AmazonRekognition.svg',
  dynamodb: 'AmazonDynamoDB.svg',
  cloudwatch: 'AmazonCloudWatch.svg',
  eventbridge: 'AmazonEventBridge.svg',
  sqs: 'AmazonSimpleQueueService.svg',
};
const ICONS = Object.fromEntries(Object.entries(ICON_FILES).map(([name, file]) => [
  name,
  `data:image/svg+xml;base64,${readFileSync(join(DOCS, 'icons', file)).toString('base64')}`,
]));

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const out = [];

// ---------- primitives ----------
function lane(y, h, label) {
  out.push(`<rect x="12" y="${y}" width="${W - 24}" height="${h}" rx="10" fill="#F7F8F8" stroke="#E9EBED"/>`);
  // Top-right, clear of the connectors on the left side of each lane.
  out.push(`<text x="${W - 60}" y="${y + 18}" text-anchor="end" font-size="10.5" font-weight="bold" letter-spacing="1" fill="#687078">${esc(label)}</text>`);
}

function node({ x, y, w, h = 64, icon, title, lines = [], edge = false }) {
  const border = edge ? `stroke="${C.network}" stroke-width="1.6" stroke-dasharray="6 3"` : 'stroke="#AAB7B8" stroke-width="1.2"';
  out.push('<g>');
  out.push(`<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="6" fill="#FFFFFF" ${border}/>`);
  out.push(`<image x="${x + 8}" y="${y + 8}" width="48" height="48" href="${ICONS[icon]}" xlink:href="${ICONS[icon]}"/>`);
  out.push(`<text x="${x + 66}" y="${y + 21}" font-size="12" font-weight="bold" fill="${C.ink}">${esc(title)}</text>`);
  lines.forEach((t, i) => out.push(`<text x="${x + 66}" y="${y + 36 + i * 12.5}" font-size="10" fill="${C.muted}">${esc(t)}</text>`));
  out.push('</g>');
}

const markers = new Set();
function marker(color) {
  const id = `arrow-${color.slice(1)}`;
  markers.add(id);
  return id;
}

function badgeAt(x, y, n) {
  out.push(`<circle cx="${x}" cy="${y}" r="9" fill="${C.line}"/>`);
  out.push(`<text x="${x}" y="${y + 3.5}" text-anchor="middle" font-size="10" font-weight="bold" fill="#FFFFFF">${esc(n)}</text>`);
}

function edgeLine({ points, color = C.line, width = 1.6, dash, label, badge }) {
  const d = points.map(([px, py], i) => `${i ? 'L' : 'M'}${px},${py}`).join(' ');
  out.push(`<path d="${d}" fill="none" stroke="${color}" stroke-width="${width}"${dash ? ` stroke-dasharray="${dash}"` : ''} marker-end="url(#${marker(color)})"/>`);
  if (label) {
    const { x, y, text, anchor = 'start', lines, muted = false } = label;
    (lines || [text]).forEach((t, i) => out.push(
      `<text x="${x}" y="${y + i * 12}" text-anchor="${anchor}" font-size="10" fill="${muted ? C.muted : color}"${muted ? '' : ' font-weight="bold"'}>${esc(t)}</text>`,
    ));
  }
  if (badge) badgeAt(badge.x, badge.y, badge.n);
}

// ---------- title ----------
out.push(`<text x="${W / 2}" y="34" text-anchor="middle" font-size="18" font-weight="bold" fill="${C.ink}">Step-up human verification for agent-driven browsers</text>`);
out.push(`<text x="${W / 2}" y="56" text-anchor="middle" font-size="12" fill="${C.muted}">AWS WAF Bot Control decides when · Lambda@Edge decides how · Amazon Rekognition Face Liveness checks for a live person</text>`);

// ---------- lanes ----------
lane(78, 162, 'DETECT AND GATE · EVERY REQUEST');
lane(250, 360, 'CHECK FOR A LIVE PERSON · FLAGGED SESSIONS ONLY');
lane(620, 190, 'RETENTION AND OPERATIONS');

// ---------- nodes ----------
// Lane 1: AWS WAF inspects each request as CloudFront receives it, before the
// cache and before any Lambda@Edge function runs.
node({ x: 30, y: 133, w: 210, icon: 'user', title: 'Browser', lines: ['human, or an AI agent', 'driving a real browser'] });
node({ x: 300, y: 133, w: 250, icon: 'waf', edge: true, title: 'AWS WAF web ACL', lines: ['Bot Control 7.0: targeted + ML', 'inserts bot-suspect, token-id'] });
node({ x: 610, y: 133, w: 250, icon: 'cloudfront', edge: true, title: 'Amazon CloudFront', lines: ['3 cache behaviors, OAC', 'security headers policies'] });
node({ x: 920, y: 133, w: 250, icon: 'lambda', edge: true, title: 'Gate (Lambda@Edge)', lines: ['viewer request · flagged needs', 'session bound to this token'] });
node({ x: 1230, y: 133, w: 250, icon: 's3', title: 'Site bucket (S3)', lines: ['protected demo storefront', 'private, read through OAC'] });

// Lane 2
node({ x: 30, y: 290, w: 210, icon: 'cognito', title: 'Cognito identity pool', lines: ['guest role allows only', 'StartFaceLivenessSession'] });
node({ x: 300, y: 330, w: 260, icon: 'rekognition', title: 'Rekognition Face Liveness', lines: ['movement + colored-light check', 'returns score + reference image'] });
node({ x: 300, y: 430, w: 260, icon: 'rekognition', title: 'Rekognition collection', lines: ['face vectors only, no images', 'SearchFacesByImage, IndexFaces'] });
node({ x: 300, y: 530, w: 260, icon: 'dynamodb', title: 'DynamoDB table', lines: ['single use, per-face daily limit', 'FACE# registry (TTL retention)'] });
node({ x: 610, y: 410, w: 250, icon: 'lambda', edge: true, title: 'Liveness API', lines: ['Lambda@Edge, origin request', 'POST /liveness/session, /verify'] });
node({ x: 610, y: 530, w: 250, icon: 'secrets', title: 'Secrets Manager', lines: ['HMAC cookie-signing key', 'read by both edge functions'] });
node({ x: 920, y: 290, w: 250, icon: 's3', title: 'Challenge page (S3)', lines: ['React + FaceLivenessDetector', 'served at /challenge/*'] });
node({ x: 1230, y: 290, w: 250, icon: 'cloudwatch', title: 'CloudWatch Logs', lines: ['AWS WAF logs', 'Cookie header redacted'] });

// Lane 3
node({ x: 30, y: 660, w: 210, icon: 'eventbridge', title: 'EventBridge rule', lines: ['daily sweep schedule'] });
node({ x: 300, y: 660, w: 260, icon: 'lambda', title: 'Face cleanup function', lines: ['deletes expired face vectors', 'stream + daily sweep'] });
node({ x: 610, y: 660, w: 250, icon: 'sqs', title: 'Dead-letter queue', lines: ['failed cleanup batches'] });

// ---------- edges ----------
// Request path
edgeLine({ points: [[240, 165], [298, 165]], badge: { x: 269, y: 150, n: '1' } });
edgeLine({ points: [[550, 165], [608, 165]], badge: { x: 579, y: 150, n: '2' }, label: { x: 579, y: 190, text: 'allowed', anchor: 'middle', muted: true } });
edgeLine({ points: [[860, 165], [918, 165]], badge: { x: 889, y: 150, n: '3' }, label: { x: 889, y: 190, text: 'flag + token ID', anchor: 'middle', muted: true } });
edgeLine({ points: [[1170, 165], [1228, 165]], color: C.storage, badge: { x: 1199, y: 150, n: '4a' } });
edgeLine({ points: [[1045, 197], [1045, 288]], color: C.security, badge: { x: 1060, y: 222, n: '4b' },
  label: { x: 1035, y: 238, anchor: 'end', lines: ['flagged, no bound session:', '302 to /challenge/'] } });

// Challenge path
edgeLine({ points: [[90, 197], [90, 288]], color: C.security, dash: '5 3', badge: { x: 75, y: 225, n: '5' },
  label: { x: 100, y: 266, lines: ['guest', 'credentials'] } });
edgeLine({ points: [[200, 197], [200, 270], [430, 270], [430, 328]], color: C.ml, dash: '5 3', badge: { x: 315, y: 270, n: '7' },
  label: { x: 440, y: 294, lines: ['video stream', '(WebSocket)'] } });
edgeLine({ points: [[735, 197], [735, 408]], color: C.compute, badge: { x: 750, y: 300, n: '6' },
  label: { x: 765, y: 304, text: 'POST /liveness/session' } });
badgeAt(750, 338, '8');
out.push(`<text x="765" y="342" font-size="10" font-weight="bold" fill="${C.compute}">POST /liveness/verify</text>`);
// Liveness API fan-out
edgeLine({ points: [[610, 442], [585, 442], [585, 362], [562, 362]], color: C.ml });
edgeLine({ points: [[585, 442], [585, 462], [562, 462]], color: C.ml });
edgeLine({ points: [[585, 462], [585, 562], [562, 562]], color: C.database });
edgeLine({ points: [[735, 474], [735, 528]], color: C.security, dash: '2 3', label: { x: 743, y: 505, text: 'signing key' } });
// Logging
edgeLine({ points: [[425, 133], [425, 112], [1572, 112], [1572, 322], [1482, 322]], color: C.integration, dash: '2 3',
  label: { x: 433, y: 106, text: 'WAF logs' } });

// Retention
edgeLine({ points: [[430, 594], [430, 658]], color: C.integration, label: { x: 438, y: 632, text: 'stream: FACE# removed' } });
edgeLine({ points: [[240, 692], [298, 692]], color: C.integration, label: { x: 252, y: 684, text: 'daily' } });
edgeLine({ points: [[560, 700], [608, 700]], color: C.integration, dash: '5 3', label: { x: 566, y: 720, text: 'on failure' } });
edgeLine({ points: [[300, 670], [275, 670], [275, 462], [298, 462]], color: C.integration, label: { x: 268, y: 580, text: 'DeleteFaces', anchor: 'end' } });

// ---------- cookie contract panel ----------
{
  const px = 920;
  const py = 405;
  const rows = [
    ['__Secure-hv_challenge', 'set by Gate · Path=/liveness · 10 min', 'proves the browser was flagged; carries return path'],
    ['__Secure-hv_liveness', 'set by /session · Path=/liveness · 4 min', 'binds the Face Liveness session ID to this browser'],
    ['__Host-hv_session', 'set by /verify · Path=/ · 15 min', 'a live person passed; works only with the same WAF token'],
  ];
  out.push(`<rect x="${px}" y="${py}" width="560" height="190" rx="6" fill="#FFFFFF" stroke="#AAB7B8" stroke-dasharray="3 3"/>`);
  out.push(`<text x="${px + 14}" y="${py + 22}" font-size="11.5" font-weight="bold" fill="${C.ink}">Signed cookies (HMAC-SHA256, typed, expiring)</text>`);
  out.push(`<text x="${px + 14}" y="${py + 37}" font-size="10" fill="${C.muted}">Each is bound to the AWS WAF token ID that minted it. Secure + HttpOnly.</text>`);
  rows.forEach(([name, scope, purpose], i) => {
    const ry = py + 62 + i * 42;
    out.push(`<text x="${px + 14}" y="${ry}" font-size="10.5" font-weight="bold" font-family="Menlo, Consolas, monospace" fill="${C.security}">${esc(name)}</text>`);
    out.push(`<text x="${px + 220}" y="${ry}" font-size="10" fill="${C.ink}">${esc(scope)}</text>`);
    out.push(`<text x="${px + 14}" y="${ry + 15}" font-size="10" fill="${C.muted}">${esc(purpose)}</text>`);
  });
}

// ---------- legend ----------
const lx = 1230;
const ly = 650;
out.push(`<rect x="${lx}" y="${ly}" width="285" height="146" rx="6" fill="#FFFFFF" stroke="#E9EBED"/>`);
out.push(`<text x="${lx + 12}" y="${ly + 20}" font-size="11" font-weight="bold" fill="${C.ink}">Legend</text>`);
out.push(`<rect x="${lx + 12}" y="${ly + 32}" width="26" height="14" rx="3" fill="#FFFFFF" stroke="${C.network}" stroke-width="1.6" stroke-dasharray="6 3"/>`);
out.push(`<text x="${lx + 46}" y="${ly + 43}" font-size="10" fill="${C.muted}">Runs at the CloudFront edge</text>`);
out.push(`<rect x="${lx + 12}" y="${ly + 54}" width="26" height="14" rx="3" fill="#FFFFFF" stroke="#AAB7B8" stroke-width="1.2"/>`);
out.push(`<text x="${lx + 46}" y="${ly + 65}" font-size="10" fill="${C.muted}">Regional resource in us-east-1</text>`);
out.push(`<line x1="${lx + 12}" y1="${ly + 84}" x2="${lx + 38}" y2="${ly + 84}" stroke="${C.line}" stroke-width="1.6"/>`);
out.push(`<text x="${lx + 46}" y="${ly + 87}" font-size="10" fill="${C.muted}">Request or API call</text>`);
out.push(`<line x1="${lx + 12}" y1="${ly + 104}" x2="${lx + 38}" y2="${ly + 104}" stroke="${C.line}" stroke-width="1.6" stroke-dasharray="5 3"/>`);
out.push(`<text x="${lx + 46}" y="${ly + 107}" font-size="10" fill="${C.muted}">Direct from the browser / on failure</text>`);
badgeAt(lx + 25, ly + 124, 'n');
out.push(`<text x="${lx + 46}" y="${ly + 128}" font-size="10" fill="${C.muted}">Step in the request flow (see README)</text>`);

// ---------- footer ----------
out.push(`<text x="26" y="${H - 64}" font-size="10" fill="${C.muted}">AWS WAF evaluates each request when CloudFront receives it, before the cache and before any Lambda@Edge function runs.</text>`);
out.push(`<text x="26" y="${H - 50}" font-size="10" fill="${C.muted}">Lambda@Edge functions are created in us-east-1, run at CloudFront Regional Edge Caches, and call the us-east-1 services shown.</text>`);
out.push(`<text x="26" y="${H - 36}" font-size="10" fill="${C.muted}">Also in the stack: IAM roles and policies, response headers policies, origin access controls, and CDK-managed custom resources. Icons: AWS Architecture Icons.</text>`);

// ---------- assemble ----------
const defs = [...markers].map((id) => {
  const color = `#${id.slice('arrow-'.length)}`;
  return `<marker id="${id}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="${color}"/></marker>`;
}).join('');

const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" font-family="${FONT}">
<title>Step-up human verification for agent-driven browsers: AWS WAF Bot Control, Amazon CloudFront, Lambda@Edge, and Amazon Rekognition Face Liveness</title>
<defs>${defs}</defs>
<rect width="${W}" height="${H}" fill="#FFFFFF"/>
${out.join('\n')}
</svg>
`;
writeFileSync(OUT, svg);
console.log(`wrote ${OUT}`);
