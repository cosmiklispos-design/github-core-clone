// github-core-clone: a standalone GitHub-compatible forge in one process.
//
// Surfaces, all served from this one server:
//   - git smart HTTP  at /{owner}/{repo}.git  (upload-pack v2/v0, receive-pack v0)
//   - REST v3         under /api/v3
//   - GraphQL v4      at /api/graphql
//   - MCP             at /mcp (Streamable HTTP)
//
// Node 22 standard library only. No git binary, no network beyond the suite,
// no wall clock and no unseeded randomness in anything a request can observe:
// timestamps come from MAKEFUN_TRIAL_NOW plus a logical counter, and every
// identifier the server mints is content-addressed or counter-derived.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// -------------------------------------------------------------------------------------------
// Configuration: token, deterministic clock, the suite's viewer.
// -------------------------------------------------------------------------------------------

/** The suite's bearer token, from the trial environment. Empty locally: any token then passes. */
const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

/** Parse MAKEFUN_TRIAL_NOW (epoch seconds, epoch milliseconds, or an ISO string). */
function trialNowMs(): number {
  const raw = (process.env.MAKEFUN_TRIAL_NOW ?? '').trim();
  if (raw === '') return Date.parse('2026-11-14T06:30:00Z');
  if (/^\d+$/.test(raw)) {
    const n = Number(raw);
    return n > 1e12 ? n : n * 1000;
  }
  const parsed = Date.parse(raw);
  return Number.isFinite(parsed) ? parsed : Date.parse('2026-11-14T06:30:00Z');
}

const TRIAL_NOW_MS = trialNowMs();
/** Logical clock: the trial's now, one second per stamp handed out. Deterministic across replays. */
let clockSeq = 0;
function nowMs(): number {
  return TRIAL_NOW_MS + clockSeq++ * 1000;
}
function nowIso(): string {
  return new Date(nowMs()).toISOString();
}
function nowEpochSec(): number {
  return Math.floor(nowMs() / 1000);
}

// The suite's scenario is built from one constant seed, so its viewer is the same
// in every trial. The entry re-derives that first user from the seed (the same
// xorshift stream the kit's wire.ts uses) instead of hard-coding a login.
const U64_MASK = 0xffffffffffffffffn;
const SCENARIO_SEED = 0x6a09e667f3bcc909n;
function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}
function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}
class ScenarioRng {
  #state: bigint;
  constructor(seed: bigint) {
    const masked = seed & U64_MASK;
    this.#state = masked === 0n ? SCENARIO_SEED : masked;
  }
  nextU64(): bigint {
    let x = this.#state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.#state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }
  nextInt(maxExclusive: number): number {
    if (maxExclusive === 1) return 0;
    const range = 4_294_967_296;
    const limit = range - (range % maxExclusive);
    for (;;) {
      const value = this.nextU32();
      if (value < limit) return value % maxExclusive;
    }
  }
  pick<T>(list: readonly T[]): T {
    return list[this.nextInt(list.length)] as T;
  }
}
const FIRST_NAMES = [
  'ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas',
  'kira', 'lars', 'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess',
  'ulla', 'vito', 'wren', 'yara', 'zane',
] as const;
const LAST_NAMES = [
  'anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen',
  'jansen', 'keller', 'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi',
  'sato', 'turi', 'ulrich', 'vega', 'weber', 'xu', 'yilmaz', 'zimmer',
] as const;
/** The token owner's login, name and email, as the suite's seeded scenario names them. */
function deriveViewer(): { id: number; login: string; name: string; email: string } {
  const rng = new ScenarioRng(mix64(SCENARIO_SEED ^ fnv1a64('users')));
  const first = rng.pick(FIRST_NAMES);
  const last = rng.pick(LAST_NAMES);
  const login = `${first}${last}`.replace(/[^a-z0-9-]/g, '');
  return { id: 1000, login, name: `${first} ${last}`, email: `${login}@example.invalid` };
}
const VIEWER = deriveViewer();
const VIEWER_IDENTITY = `${VIEWER.name} <${VIEWER.email}>`;

// -------------------------------------------------------------------------------------------
// Small helpers: ids, hashing, base64, HTTP plumbing, pkt-lines.
// -------------------------------------------------------------------------------------------

export const ZERO_OID = '0'.repeat(40);
const HEX40 = /^[0-9a-f]{40}$/i;
function isOid(value: unknown): value is string {
  return typeof value === 'string' && HEX40.test(value);
}

/** Deterministic per-request id (the suite's request sequence is fixed per trial). */
let requestSeq = 0;
function nextRequestId(): string {
  requestSeq += 1;
  return `req-${requestSeq.toString(16).padStart(8, '0')}`;
}

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}
function b64encode(data: Buffer | string): string {
  return Buffer.isBuffer(data) ? data.toString('base64') : Buffer.from(data, 'utf8').toString('base64');
}
function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

const JSON_TYPE = 'application/json; charset=utf-8';

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': nextRequestId(),
    ...headers,
  });
  res.end(text);
}
function sendJsonError(res: ServerResponse, status: number, message: string, headers: Record<string, string> = {}): void {
  sendJson(res, status, { message }, headers);
}
function sendNoContent(res: ServerResponse, status: number, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': JSON_TYPE, 'x-github-request-id': nextRequestId(), ...headers });
  res.end();
}
function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': nextRequestId(),
  });
  res.end(body);
}

const MAX_BODY_BYTES = 64 * 1024 * 1024;
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Parse a request body as JSON; throws { status, message } on malformed input. */
function parseJsonBody(buffer: Buffer): unknown {
  const text = buffer.toString('utf8');
  if (text.trim() === '') return {};
  try {
    return JSON.parse(text) as unknown;
  } catch {
    const err = new Error('Invalid JSON body') as Error & { status?: number };
    err.status = 400;
    throw err;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Whether the request carries the suite's token. A missing or wrong token is refused. */
function isAuthed(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  if (!header.startsWith('Bearer ')) return false;
  const token = header.slice('Bearer '.length);
  if (token === '') return false;
  if (SHOP_TOKEN === '') return true;
  return token === SHOP_TOKEN;
}

function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}
function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}
function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

// -------------------------------------------------------------------------------------------
// pkt-lines (git's framing): 4 hex digits of length including the digits, "0000" flush,
// "0001" delim, "0002" response-end. Payloads are raw bytes, usually LF-terminated text.
// -------------------------------------------------------------------------------------------

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = data.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
function pktLines(items: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(PKT_FLUSH);
    else if (item === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

interface DecodedPacket {
  kind: 'data' | 'flush' | 'delim' | 'response-end';
  payload: Buffer;
}
/** Decode a whole pkt-line stream; throws on a malformed length, truncation or bad framing. */
function decodePktLines(buffer: Buffer): DecodedPacket[] {
  const packets: DecodedPacket[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + 4 > buffer.length) throw new Error('malformed pkt-line: truncated length');
    const head = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error('malformed pkt-line: bad length prefix');
    const len = parseInt(head, 16);
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'response-end', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (len < 4 || offset + len > buffer.length) throw new Error('malformed pkt-line: bad length');
    packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + len) });
    offset += len;
  }
  return packets;
}
function packetLines(packets: readonly DecodedPacket[]): string[] {
  const lines: string[] = [];
  for (const packet of packets) {
    if (packet.kind !== 'data') continue;
    lines.push(packet.payload.toString('utf8'));
  }
  return lines;
}

// -------------------------------------------------------------------------------------------
// Git object store: loose objects, content-addressed, shared across the forge's repos
// (reachability is always computed from one repo's own refs, so sharing is safe).
// -------------------------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject {
  type: ObjType;
  data: Buffer;
}
const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

const objects = new Map<string, GitObject>();

function hashObject(type: ObjType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'ascii');
  return sha1Hex(Buffer.concat([head, data]));
}
function putObject(type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!objects.has(oid)) objects.set(oid, { type, data });
  return oid;
}
function getObject(oid: string): GitObject | undefined {
  return objects.get(oid);
}

// Parsed-commit and parsed-tree caches: a walk parses each object once per process.
interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}
interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}
interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}
const commitCache = new Map<string, CommitView>();
const treeCache = new Map<string, TreeEntry[]>();
const tagCache = new Map<string, TagView>();

function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split === -1 ? text : text.slice(0, split);
  const message = split === -1 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}
function commitOf(oid: string): CommitView | undefined {
  const cached = commitCache.get(oid);
  if (cached !== undefined) return cached;
  const object = objects.get(oid);
  if (object === undefined || object.type !== 'commit') return undefined;
  const view = parseCommit(object.data);
  commitCache.set(oid, view);
  return view;
}
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space === -1) break;
    const mode = data.subarray(offset, space).toString('ascii');
    const nul = data.indexOf(0, space + 1);
    if (nul === -1 || nul + 21 > data.length) break;
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}
function treeOf(oid: string): TreeEntry[] | undefined {
  const cached = treeCache.get(oid);
  if (cached !== undefined) return cached;
  const object = objects.get(oid);
  if (object === undefined || object.type !== 'tree') return undefined;
  const entries = parseTree(object.data);
  treeCache.set(oid, entries);
  return entries;
}
function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split === -1 ? text : text.slice(0, split);
  const message = split === -1 ? '' : text.slice(split + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}
function tagOf(oid: string): TagView | undefined {
  const cached = tagCache.get(oid);
  if (cached !== undefined) return cached;
  const object = objects.get(oid);
  if (object === undefined || object.type !== 'tag') return undefined;
  const view = parseTag(object.data);
  tagCache.set(oid, view);
  return view;
}

/** git's tree sort: entries by name, directories as if the name ended with '/'. */
function compareTreeEntries(a: TreeEntry, b: TreeEntry): number {
  const an = a.mode === '40000' ? `${a.name}/` : a.name;
  const bn = b.mode === '40000' ? `${b.name}/` : b.name;
  return an < bn ? -1 : an > bn ? 1 : 0;
}
function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeEntries);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}
function buildCommit(fields: { tree: string; parents: readonly string[]; message: string; author: string; committer: string; timestamp: number }): Buffer {
  const lines: string[] = [`tree ${fields.tree}`];
  for (const parent of fields.parents) lines.push(`parent ${parent}`);
  lines.push(`author ${fields.author} ${fields.timestamp} +0000`);
  lines.push(`committer ${fields.committer} ${fields.timestamp} +0000`);
  const message = fields.message.endsWith('\n') ? fields.message : `${fields.message}\n`;
  return Buffer.from(`${lines.join('\n')}\n\n${message}`, 'utf8');
}

/** Every object reachable from the tips: commits (parents, peeled tags), their trees, blobs. */
function collectReachable(tips: Iterable<string>): Set<string> {
  const seen = new Set<string>();
  const stack = [...tips];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const object = objects.get(oid);
    if (object === undefined) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const view = commitOf(oid);
      if (view === undefined) continue;
      if (view.tree !== '') stack.push(view.tree);
      for (const parent of view.parents) stack.push(parent);
    } else if (object.type === 'tree') {
      const entries = treeOf(oid);
      if (entries !== undefined) for (const entry of entries) stack.push(entry.oid);
    } else if (object.type === 'tag') {
      const view = tagOf(oid);
      if (view !== undefined && view.object !== '') stack.push(view.object);
    }
  }
  return seen;
}

/** The commit a ref target resolves to (peeling an annotated tag). */
function peelToCommit(oid: string): string | undefined {
  const object = objects.get(oid);
  if (object === undefined) return undefined;
  if (object.type === 'commit') return oid;
  if (object.type === 'tag') {
    const view = tagOf(oid);
    return view === undefined ? undefined : peelToCommit(view.object);
  }
  return undefined;
}

/** True when `ancestor` is reachable from `oid` (or equal to it), following parents. */
function isAncestor(ancestor: string, oid: string): boolean {
  if (ancestor === oid) return true;
  const seen = new Set<string>();
  const stack = [oid];
  while (stack.length > 0) {
    const current = stack.pop() as string;
    if (seen.has(current)) continue;
    seen.add(current);
    const view = commitOf(current);
    if (view === undefined) continue;
    for (const parent of view.parents) {
      if (parent === ancestor) return true;
      stack.push(parent);
    }
  }
  return false;
}

/** A path -> blob map for a tree, recursively. */
function flattenTree(treeOid: string, prefix = '', out = new Map<string, { oid: string; mode: string }>()): Map<string, { oid: string; mode: string }> {
  const entries = treeOf(treeOid);
  if (entries === undefined) return out;
  for (const entry of entries) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(entry.oid, path, out);
    else out.set(path, { oid: entry.oid, mode: entry.mode });
  }
  return out;
}

/** Set (or delete, with blobOid null) one path in a tree, rebuilding the changed trees. */
function setPathInTree(treeOid: string | null, segments: readonly string[], blobOid: string | null): string {
  if (segments.length === 0) return treeOid ?? putObject('tree', Buffer.alloc(0));
  const entries = treeOid === null ? [] : (treeOf(treeOid) ?? []);
  const [head, ...rest] = segments as [string, ...string[]];
  const next: TreeEntry[] = [];
  let found = false;
  for (const entry of entries) {
    if (entry.name !== head) {
      next.push(entry);
      continue;
    }
    found = true;
    if (rest.length === 0) {
      if (blobOid !== null) next.push({ mode: '100644', name: head, oid: blobOid });
      // else: delete the entry
    } else if (entry.mode === '40000') {
      const child = setPathInTree(entry.oid, rest, blobOid);
      const childEntries = treeOf(child) ?? [];
      if (childEntries.length > 0) next.push({ mode: '40000', name: head, oid: child });
      // else: the directory emptied, drop it
    } else if (blobOid !== null) {
      // A file sits where a directory must go: replace it with the new subtree.
      const child = setPathInTree(null, rest, blobOid);
      next.push({ mode: '40000', name: head, oid: child });
    }
  }
  if (!found && blobOid !== null) {
    if (rest.length === 0) next.push({ mode: '100644', name: head, oid: blobOid });
    else {
      const child = setPathInTree(null, rest, blobOid);
      next.push({ mode: '40000', name: head, oid: child });
    }
  }
  return putObject('tree', buildTree(next));
}

// -------------------------------------------------------------------------------------------
// Packs: write plain packs (no deltas); read plain, OFS_DELTA and REF_DELTA packs.
// -------------------------------------------------------------------------------------------

function writePackObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}
function writePack(list: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const object of list) {
    parts.push(writePackObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

/** Read a pack header's size varint: { size, next offset }. */
function readPackSize(buffer: Buffer, start: number): { size: number; next: number } {
  let byte = buffer[start] as number;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while ((byte & 0x80) !== 0) {
    byte = buffer[offset] as number;
    offset += 1;
    size |= (byte & 0x7f) << shift;
    shift += 7;
  }
  return { size, next: offset };
}
function readOfsDeltaBase(buffer: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buffer[start] as number;
  let offset = start + 1;
  let value = byte & 0x7f;
  while ((byte & 0x80) !== 0) {
    byte = buffer[offset] as number;
    offset += 1;
    value = ((value + 1) << 7) | (byte & 0x7f);
  }
  return { baseOffset: value, next: offset };
}
/** Inflate one zlib stream starting at `start`, stopping at the stream's end. */
function inflateOne(pack: Buffer, start: number, end: number, expectedSize: number): { bytes: Buffer; next: number } {
  // The stream's end is the smallest slice end that inflates without throwing and
  // yields the expected size: shorter slices throw "unexpected end of file", and
  // longer slices succeed too (trailing bytes are ignored), so lower-bound search.
  let low = start + 1;
  let high = end;
  let best = -1;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    try {
      const bytes = inflateSync(pack.subarray(start, mid));
      if (bytes.length === expectedSize) {
        best = mid;
        high = mid - 1;
      } else {
        low = mid + 1;
      }
    } catch {
      low = mid + 1;
    }
  }
  if (best === -1) throw new Error('pack object inflate failed');
  return { bytes: inflateSync(pack.subarray(start, best)), next: best };
}

/** Apply a git delta to its base bytes. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[offset] as number;
      offset += 1;
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const baseSize = readVarint();
  const resultSize = readVarint();
  if (baseSize !== base.length) throw new Error('delta base size mismatch');
  const parts: Buffer[] = [];
  let size = 0;
  while (offset < delta.length) {
    const op = delta[offset] as number;
    offset += 1;
    if ((op & 0x80) !== 0) {
      let copyOffset = 0;
      let copySize = 0;
      for (let i = 0; i < 4; i += 1) {
        if ((op & (1 << i)) !== 0) {
          copyOffset |= (delta[offset] as number) << (i * 8);
          offset += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if ((op & (0x10 << i)) !== 0) {
          copySize |= (delta[offset] as number) << (i * 8);
          offset += 1;
        }
      }
      if (copySize === 0) copySize = 0x10000;
      parts.push(base.subarray(copyOffset, copyOffset + copySize));
      size += copySize;
    } else if (op !== 0) {
      parts.push(delta.subarray(offset, offset + op));
      size += op;
      offset += op;
    } else {
      throw new Error('delta op 0 is reserved');
    }
  }
  const result = Buffer.concat(parts);
  if (size !== resultSize || result.length !== resultSize) throw new Error('delta result size mismatch');
  return result;
}

interface PackReadResult {
  objects: Map<string, GitObject>;
  deltaCount: number;
}
/**
 * Parse a packfile. Plain objects resolve directly; OFS/REF deltas resolve against
 * objects earlier in the same pack or already in the store. Uses zlib's streaming
 * inflate through a bounded window so each entry's end is found exactly.
 */
function readPack(pack: Buffer): PackReadResult {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('not a packfile');
  }
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const expectedTrailer = sha1Hex(pack.subarray(0, pack.length - 20));
  if (pack.subarray(pack.length - 20).toString('hex') !== expectedTrailer) {
    throw new Error('pack trailer checksum mismatch');
  }
  const found = new Map<string, GitObject>();
  const byOffset = new Map<number, GitObject>();
  let deltaCount = 0;
  let offset = 12;
  const end = pack.length - 20;
  for (let index = 0; index < count; index += 1) {
    const entryOffset = offset;
    const first = pack[offset] as number;
    offset += 1;
    const typeCode = (first >> 4) & 0x07;
    let size = first & 0x0f;
    let shift = 4;
    let byte = first;
    while ((byte & 0x80) !== 0) {
      byte = pack[offset] as number;
      offset += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    let baseOid: string | undefined;
    let baseOffset: number | undefined;
    if (typeCode === 6) {
      const parsed = readOfsDeltaBase(pack, offset);
      baseOffset = entryOffset - parsed.baseOffset;
      offset = parsed.next;
    } else if (typeCode === 7) {
      baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    } else if (CODE_TYPE[typeCode] === undefined) {
      throw new Error(`unknown pack object type ${typeCode}`);
    }
    // Inflate exactly one object: Node's inflateSync returns the first stream in
    // a slice and ignores trailing bytes, so the smallest slice end that inflates
    // to the expected size is the stream's exact end (binary search below).
    const data = inflateOne(pack, offset, end, size);
    offset = data.next;
    if (typeCode === 6 || typeCode === 7) {
      deltaCount += 1;
      const base = baseOffset !== undefined ? byOffset.get(baseOffset) : baseOid !== undefined ? (found.get(baseOid) ?? getObject(baseOid)) : undefined;
      if (base === undefined) throw new Error('delta base not found');
      const resolved = applyDelta(base.data, data.bytes);
      const type = base.type;
      const oid = hashObject(type, resolved);
      const object: GitObject = { type, data: resolved };
      found.set(oid, object);
      byOffset.set(entryOffset, object);
    } else {
      const type = CODE_TYPE[typeCode] as ObjType;
      if (data.bytes.length !== size) throw new Error('pack object size mismatch');
      const oid = hashObject(type, data.bytes);
      const object: GitObject = { type, data: data.bytes };
      found.set(oid, object);
      byOffset.set(entryOffset, object);
    }
  }
  if (offset !== end) throw new Error('pack has trailing bytes');
  return { objects: found, deltaCount };
}

// -------------------------------------------------------------------------------------------
// Repository store: repos, issues, pull requests, labels, comments. All in memory.
// Repos are keyed by the exact owner/name the calls name; a name under another
// owner is simply a different (absent) key, so it reads 404, never 403.
// -------------------------------------------------------------------------------------------

interface Label {
  name: string;
  color: string;
  description: string;
}
interface IssueComment {
  id: number;
  body: string;
  createdAt: string;
  updatedAt: string;
}
interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  comments: IssueComment[];
  createdAt: string;
  updatedAt: string;
}
interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  createdAt: string;
  updatedAt: string;
}
interface Repo {
  id: number;
  name: string;
  owner: string;
  private: boolean;
  description: string;
  defaultBranch: string;
  createdAt: string;
  updatedAt: string;
  refs: Map<string, string>;
  issues: Issue[];
  nextIssueNumber: number;
  pulls: Pull[];
  nextPullNumber: number;
  labels: Map<string, Label>;
  order: number;
}

const repos = new Map<string, Repo>();
let nextRepoId = 1;
let nextObjectId = 1;
let nextCommentId = 1;
let repoOrderSeq = 0;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}
function findRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}
function ownerId(owner: string): number {
  return owner === VIEWER.login ? VIEWER.id : 9000 + Number(fnv1a64(owner) % 999n);
}
function userView(login: string): Record<string, unknown> {
  return { login, id: ownerId(login), type: 'User', site_admin: false };
}
function repoView(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    owner: userView(repo.owner),
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    pushed_at: repo.updatedAt,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    has_pages: false,
    has_downloads: true,
    archived: false,
    disabled: false,
    fork: false,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    open_issues_count: repo.issues.filter((issue) => issue.state === 'open').length,
    license: { key: 'mit', name: 'MIT License', spdx_id: 'MIT' },
  };
}
function labelView(label: Label): Record<string, unknown> {
  return { name: label.name, color: label.color, description: label.description };
}
function issueView(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map(labelView),
    user: userView(VIEWER.login),
    assignees: [],
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.state === 'closed' ? issue.updatedAt : null,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    comments: issue.comments.length,
    comments_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/comments`,
  };
}
function pullView(repo: Repo, pull: Pull): Record<string, unknown> {
  const head = {
    ref: pull.headRef,
    sha: pull.headSha,
    label: `${repo.owner}:${pull.headRef}`,
    user: userView(repo.owner),
    repo: repoView(repo),
  };
  const base = {
    ref: pull.baseRef,
    sha: pull.baseSha,
    label: `${repo.owner}:${pull.baseRef}`,
    user: userView(repo.owner),
    repo: repoView(repo),
  };
  return {
    id: pull.id,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable: pull.merged ? false : undefined,
    head,
    base,
    user: userView(VIEWER.login),
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    closed_at: pull.state === 'closed' ? pull.updatedAt : null,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}
function commentView(repo: Repo, issue: Issue, comment: IssueComment): Record<string, unknown> {
  return {
    id: comment.id,
    body: comment.body,
    user: userView(VIEWER.login),
    created_at: comment.createdAt,
    updated_at: comment.updatedAt,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}/comments/${comment.id}`,
  };
}

/** The global id a GraphQL node carries: opaque (base64) and stable across reads. */
function globalId(kind: string, ...parts: (string | number)[]): string {
  return Buffer.from(`${kind}:${parts.join(':')}`, 'utf8').toString('base64');
}
function parseGlobalId(id: string): { kind: string; parts: string[] } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const [kind, ...parts] = text.split(':');
    if (kind === undefined || parts.length === 0) return null;
    return { kind, parts };
  } catch {
    return null;
  }
}

// -------------------------------------------------------------------------------------------
// Contents: resolve a ref, read a file or a directory, commit a file.
// -------------------------------------------------------------------------------------------

/** The tip commit of a ref: a branch name, a full ref, or a 40-hex commit id. */
function resolveRefTip(repo: Repo, ref?: string): string | undefined {
  if (ref === undefined || ref === '') {
    return repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  }
  if (ref.startsWith('refs/')) return repo.refs.get(ref);
  const branchTip = repo.refs.get(`refs/heads/${ref}`);
  if (branchTip !== undefined) return branchTip;
  if (isOid(ref) && getObject(ref)?.type === 'commit') return ref;
  return undefined;
}

/** Immediate children of a directory inside a tree. */
function listDirEntries(treeOid: string, dirPath: string): { type: 'file' | 'dir'; name: string; path: string; sha: string; size?: number }[] | null {
  let current = treeOid;
  if (dirPath !== '') {
    for (const segment of dirPath.split('/')) {
      const entries = treeOf(current);
      const found = entries?.find((entry) => entry.name === segment && entry.mode === '40000');
      if (found === undefined) return null;
      current = found.oid;
    }
  }
  const entries = treeOf(current);
  if (entries === undefined) return null;
  const out: { type: 'file' | 'dir'; name: string; path: string; sha: string; size?: number }[] = [];
  for (const entry of entries) {
    const path = dirPath === '' ? entry.name : `${dirPath}/${entry.name}`;
    if (entry.mode === '40000') {
      out.push({ type: 'dir', name: entry.name, path, sha: entry.oid });
    } else {
      const blob = getObject(entry.oid);
      out.push({ type: 'file', name: entry.name, path, sha: entry.oid, size: blob?.data.length ?? 0 });
    }
  }
  return out;
}

/** Commit one file's bytes on a branch (creating the branch from the default tip when needed). */
function commitFile(repo: Repo, branch: string, filePath: string, content: Buffer, message: string): { commitSha: string; contentSha: string } {
  const refName = `refs/heads/${branch}`;
  let tip = repo.refs.get(refName);
  if (tip === undefined) {
    tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  }
  const blobOid = putObject('blob', content);
  const baseTree = tip === undefined ? null : (commitOf(tip)?.tree ?? null);
  const treeOid = setPathInTree(baseTree, filePath.split('/'), blobOid);
  const commitData = buildCommit({
    tree: treeOid,
    parents: tip === undefined ? [] : [tip],
    message,
    author: VIEWER_IDENTITY,
    committer: VIEWER_IDENTITY,
    timestamp: nowEpochSec(),
  });
  const commitSha = putObject('commit', commitData);
  repo.refs.set(refName, commitSha);
  repo.updatedAt = nowIso();
  return { commitSha, contentSha: blobOid };
}

/** Line counts for a file diff, by multiset difference of lines. */
function lineDiff(oldData: Buffer | null, newData: Buffer | null): { additions: number; deletions: number; changes: number } {
  const splitLines = (data: Buffer | null): string[] => {
    if (data === null) return [];
    const text = data.toString('utf8');
    const lines = text.split('\n');
    if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
    return lines;
  };
  const count = (lines: string[]): Map<string, number> => {
    const map = new Map<string, number>();
    for (const line of lines) map.set(line, (map.get(line) ?? 0) + 1);
    return map;
  };
  const oldLines = count(splitLines(oldData));
  const newLines = count(splitLines(newData));
  let additions = 0;
  let deletions = 0;
  for (const [line, n] of newLines) additions += Math.max(0, n - (oldLines.get(line) ?? 0));
  for (const [line, n] of oldLines) deletions += Math.max(0, n - (newLines.get(line) ?? 0));
  return { additions, deletions, changes: additions + deletions };
}

interface FileChange {
  filename: string;
  status: 'added' | 'removed' | 'modified';
  additions: number;
  deletions: number;
  changes: number;
}
/** The file diff between two commits' trees. */
function diffCommits(baseCommitOid: string, headCommitOid: string): FileChange[] {
  const baseTree = commitOf(baseCommitOid)?.tree;
  const headTree = commitOf(headCommitOid)?.tree;
  const baseFiles = baseTree === undefined ? new Map() : flattenTree(baseTree);
  const headFiles = headTree === undefined ? new Map() : flattenTree(headTree);
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
  const changes: FileChange[] = [];
  for (const path of [...paths].sort()) {
    const oldEntry = baseFiles.get(path);
    const newEntry = headFiles.get(path);
    if (oldEntry === undefined && newEntry !== undefined) {
      const data = getObject(newEntry.oid)?.data ?? null;
      const { additions } = lineDiff(null, data);
      changes.push({ filename: path, status: 'added', additions, deletions: 0, changes: additions });
    } else if (oldEntry !== undefined && newEntry === undefined) {
      const data = getObject(oldEntry.oid)?.data ?? null;
      const { deletions } = lineDiff(data, null);
      changes.push({ filename: path, status: 'removed', additions: 0, deletions, changes: deletions });
    } else if (oldEntry !== undefined && newEntry !== undefined && oldEntry.oid !== newEntry.oid) {
      const oldData = getObject(oldEntry.oid)?.data ?? null;
      const newData = getObject(newEntry.oid)?.data ?? null;
      const { additions, deletions, changes } = lineDiff(oldData, newData);
      changes.push({ filename: path, status: 'modified', additions, deletions, changes });
    }
  }
  return changes;
}

/** The merge-base of two commits: the first common ancestor walking from the second. */
function mergeBase(a: string, b: string): string | undefined {
  const ancestors = new Set<string>();
  const stackA = [a];
  while (stackA.length > 0) {
    const current = stackA.pop() as string;
    if (ancestors.has(current)) continue;
    ancestors.add(current);
    const view = commitOf(current);
    if (view !== undefined) for (const parent of view.parents) stackA.push(parent);
  }
  const queue = [b];
  const seen = new Set<string>();
  while (queue.length > 0) {
    const current = queue.shift() as string;
    if (seen.has(current)) continue;
    seen.add(current);
    if (ancestors.has(current)) return current;
    const view = commitOf(current);
    if (view !== undefined) for (const parent of view.parents) queue.push(parent);
  }
  return undefined;
}

/** Whether a pull request would merge cleanly (squash): no path changed on both sides differently. */
function mergeConflict(repo: Repo, pull: Pull): boolean {
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  if (baseTip === undefined || headTip === undefined) return true;
  const base = mergeBase(baseTip, headTip);
  if (base === undefined) return true;
  const baseTree = commitOf(base)?.tree;
  const baseTipTree = commitOf(baseTip)?.tree;
  const headTipTree = commitOf(headTip)?.tree;
  if (baseTree === undefined || baseTipTree === undefined || headTipTree === undefined) return true;
  const baseFiles = flattenTree(baseTree);
  const baseTipFiles = flattenTree(baseTipTree);
  const headTipFiles = flattenTree(headTipTree);
  const paths = new Set([...baseTipFiles.keys(), ...headTipFiles.keys(), ...baseFiles.keys()]);
  for (const path of paths) {
    const baseOid = baseFiles.get(path)?.oid;
    const onBaseOid = baseTipFiles.get(path)?.oid;
    const onHeadOid = headTipFiles.get(path)?.oid;
    const changedOnBase = onBaseOid !== baseOid;
    const changedOnHead = onHeadOid !== baseOid;
    if (changedOnBase && changedOnHead && onBaseOid !== onHeadOid) return true;
  }
  return false;
}

/** Squash-merge a pull request onto its base branch; returns the merge commit or null on conflict. */
function squashMerge(repo: Repo, pull: Pull): string | null {
  if (mergeConflict(repo, pull)) return null;
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`) as string;
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`) as string;
  const base = mergeBase(baseTip, headTip) as string;
  const baseTree = commitOf(base)?.tree as string;
  const headTipTree = commitOf(headTip)?.tree as string;
  const baseTipTree = commitOf(baseTip)?.tree as string;
  const baseFiles = flattenTree(baseTree);
  const headTipFiles = flattenTree(headTipTree);
  let treeOid = baseTipTree;
  const paths = new Set([...baseFiles.keys(), ...headTipFiles.keys()]);
  for (const path of paths) {
    const baseOid = baseFiles.get(path)?.oid;
    const headOid = headTipFiles.get(path)?.oid;
    if (headOid !== baseOid) {
      treeOid = setPathInTree(treeOid, path.split('/'), headOid ?? null);
    }
  }
  const message = `Merge pull request #${pull.number} from ${pull.headRef}\n\n${pull.title}`;
  const commitData = buildCommit({
    tree: treeOid,
    parents: [baseTip],
    message,
    author: VIEWER_IDENTITY,
    committer: VIEWER_IDENTITY,
    timestamp: nowEpochSec(),
  });
  const mergeSha = putObject('commit', commitData);
  repo.refs.set(`refs/heads/${pull.baseRef}`, mergeSha);
  pull.merged = true;
  pull.state = 'closed';
  pull.mergedAt = nowIso();
  pull.mergeCommitSha = mergeSha;
  pull.updatedAt = nowIso();
  repo.updatedAt = nowIso();
  return mergeSha;
}

// -------------------------------------------------------------------------------------------
// REST v3 under /api/v3.
// -------------------------------------------------------------------------------------------

function paginate<T>(items: readonly T[], query: URLSearchParams, req: IncomingMessage): { page: T[]; link: string | null } {
  const perPage = Math.max(1, Math.min(100, Number(query.get('per_page') ?? 30) || 30));
  const pageNum = Math.max(1, Number(query.get('page') ?? 1) || 1);
  const start = (pageNum - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  let link: string | null = null;
  if (start + perPage < items.length) {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'entry'}`);
    url.searchParams.set('page', String(pageNum + 1));
    url.searchParams.set('per_page', String(perPage));
    link = `<${url.toString()}>; rel="next"`;
  }
  return { page: slice, link };
}

async function handleRest(req: IncomingMessage, res: ServerResponse, segments: string[], query: URLSearchParams): Promise<void> {
  const method = req.method ?? 'GET';
  if (!isAuthed(req)) {
    sendJsonError(res, 401, 'Requires authentication');
    return;
  }
  let body: unknown = {};
  if (method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE') {
    const raw = await readBody(req);
    if (raw.length > 0) {
      try {
        body = parseJsonBody(raw);
      } catch (err) {
        const status = (err as Error & { status?: number }).status ?? 400;
        sendJsonError(res, status, 'Invalid JSON body');
        return;
      }
    }
  }
  const obj = isRecord(body) ? body : {};

  // API root and meta.
  if (segments.length === 0) {
    if (method !== 'GET') {
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    sendJson(
      res,
      200,
      {
        current_user_url: '/api/v3/user',
        current_user_authorizations_html_url: 'https://example.invalid/settings/applications',
        authorizations_url: '/api/v3/authorizations',
        code_search_url: '/api/v3/search/code?q={query}',
        commit_search_url: '/api/v3/search/commits?q={query}',
        emails_url: '/api/v3/user/emails',
        emojis_url: '/api/v3/emojis',
        events_url: '/api/v3/events',
        feeds_url: '/api/v3/feeds',
        followers_url: '/api/v3/user/followers',
        following_url: '/api/v3/user/following{/other_user}',
        gists_url: '/api/v3/gists{/gist_id}',
        hub_url: '/api/v3/hub',
        issue_search_url: '/api/v3/search/issues?q={query}',
        issues_url: '/api/v3/issues',
        keys_url: '/api/v3/user/keys',
        label_search_url: '/api/v3/search/labels?q={query}',
        notifications_url: '/api/v3/notifications',
        organization_url: '/api/v3/orgs/{org}',
        public_gists_url: '/api/v3/gists/public',
        rate_limit_url: '/api/v3/rate_limit',
        repository_url: '/api/v3/repos/{owner}/{repo}',
        repository_search_url: '/api/v3/search/repositories?q={query}',
        current_user_repositories_url: '/api/v3/user/repos{?type,page,per_page,sort}',
        starred_url: '/api/v3/user/starred{/owner}{/repo}',
        starred_gists_url: '/api/v3/gists/starred',
        user_url: '/api/v3/users/{user}',
        user_organizations_url: '/api/v3/user/orgs',
        user_repositories_url: '/api/v3/users/{user}/repos{?type,page,per_page,sort}',
        user_search_url: '/api/v3/search/users?q={query}',
      },
      { 'x-oauth-scopes': 'repo, read:org' },
    );
    return;
  }
  if (segments.length === 1 && segments[0] === 'meta') {
    if (method !== 'GET') {
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, { verifiable_password_authentication: true, installed_version: '1.0.0' });
    return;
  }

  // The token's own user.
  if (segments.length === 1 && segments[0] === 'user') {
    if (method !== 'GET') {
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, {
      login: VIEWER.login,
      id: VIEWER.id,
      name: VIEWER.name,
      email: VIEWER.email,
      type: 'User',
      site_admin: false,
      html_url: `https://example.invalid/${VIEWER.login}`,
      url: '/api/v3/user',
      created_at: '2025-01-01T00:00:00Z',
      updated_at: nowIso(),
    });
    return;
  }

  // The token owner's repositories.
  if (segments.length === 2 && segments[0] === 'user' && segments[1] === 'repos') {
    if (method === 'GET') {
      const mine = [...repos.values()]
        .filter((repo) => repo.owner === VIEWER.login)
        .sort((a, b) => a.order - b.order);
      const { page, link } = paginate(mine, query, req);
      sendJson(res, 200, page.map(repoView), link === null ? {} : { link });
      return;
    }
    if (method === 'POST') {
      const name = typeof obj.name === 'string' ? obj.name : '';
      if (name === '' || /[^\w.-]/.test(name) || name.length > 100) {
        sendJsonError(res, 422, 'name is required and must be a valid repository name');
        return;
      }
      if (repos.has(repoKey(VIEWER.login, name))) {
        sendJsonError(res, 422, `A repository named ${VIEWER.login}/${name} already exists`);
        return;
      }
      const stamp = nowIso();
      const repo: Repo = {
        id: nextRepoId++,
        name,
        owner: VIEWER.login,
        private: obj.private === true,
        description: typeof obj.description === 'string' ? obj.description : '',
        defaultBranch: 'main',
        createdAt: stamp,
        updatedAt: stamp,
        refs: new Map(),
        issues: [],
        nextIssueNumber: 1,
        pulls: [],
        nextPullNumber: 1,
        labels: new Map(),
        order: repoOrderSeq++,
      };
      repos.set(repoKey(VIEWER.login, name), repo);
      sendJson(res, 201, repoView(repo));
      return;
    }
    sendJsonError(res, 404, 'Not Found');
    return;
  }

  // Repository-scoped routes: /repos/{owner}/{name}/...
  if (segments.length >= 3 && segments[0] === 'repos') {
    const owner = decodeSegment(segments[1] as string);
    const name = decodeSegment(segments[2] as string);
    const repo = findRepo(owner, name);
    if (repo === undefined) {
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    const rest = segments.slice(3);
    await handleRepoRoute(req, res, repo, rest, query, obj, method);
    return;
  }

  sendJsonError(res, 404, 'Not Found');
}

async function handleRepoRoute(
  req: IncomingMessage,
  res: ServerResponse,
  repo: Repo,
  rest: string[],
  query: URLSearchParams,
  obj: Record<string, unknown>,
  method: string,
): Promise<void> {
  // /repos/{o}/{r}
  if (rest.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, repoView(repo));
      return;
    }
    if (method === 'PATCH') {
      if (typeof obj.description === 'string') repo.description = obj.description;
      if (typeof obj.private === 'boolean') repo.private = obj.private;
      repo.updatedAt = nowIso();
      sendJson(res, 200, repoView(repo));
      return;
    }
    if (method === 'DELETE') {
      repos.delete(repoKey(repo.owner, repo.name));
      sendNoContent(res, 204);
      return;
    }
    sendJsonError(res, 404, 'Not Found');
    return;
  }

  // /repos/{o}/{r}/branches
  if (rest[0] === 'branches') {
    if (rest.length === 1 && method === 'GET') {
      const branches = [...repo.refs.entries()]
        .filter(([ref]) => ref.startsWith('refs/heads/'))
        .map(([ref, sha]) => ({ name: ref.slice('refs/heads/'.length), commit: { sha, url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${sha}` }, protected: false }));
      sendJson(res, 200, branches);
      return;
    }
    if (rest.length === 2 && method === 'GET') {
      const branch = decodeSegment(rest[1] as string);
      const sha = repo.refs.get(`refs/heads/${branch}`);
      if (sha === undefined) {
        sendJsonError(res, 404, 'Not Found');
        return;
      }
      sendJson(res, 200, { name: branch, commit: { sha, url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${sha}` }, protected: false });
      return;
    }
    sendJsonError(res, 404, 'Not Found');
    return;
  }

  // /repos/{o}/{r}/commits
  if (rest[0] === 'commits') {
    if (rest.length === 1 && method === 'GET') {
      const tip = resolveRefTip(repo, query.get('sha') ?? undefined);
      if (tip === undefined) {
        sendJson(res, 200, []);
        return;
      }
      const out: Record<string, unknown>[] = [];
      const seen = new Set<string>();
      const stack = [tip];
      while (stack.length > 0) {
        const oid = stack.pop() as string;
        if (seen.has(oid)) continue;
        seen.add(oid);
        const view = commitOf(oid);
        if (view === undefined) continue;
        const authorBits = view.author.split(' <');
        out.push({
          sha: oid,
          commit: {
            message: view.message.replace(/\n$/, ''),
            author: { name: authorBits[0] ?? '', email: (authorBits[1] ?? '').replace('>', ''), date: nowIso() },
            committer: { name: authorBits[0] ?? '', email: (authorBits[1] ?? '').replace('>', ''), date: nowIso() },
          },
          author: userView(VIEWER.login),
          committer: userView(VIEWER.login),
          parents: view.parents.map((parent) => ({ sha: parent })),
        });
        for (let i = view.parents.length - 1; i >= 0; i -= 1) stack.push(view.parents[i] as string);
      }
      sendJson(res, 200, out);
      return;
    }
    sendJsonError(res, 404, 'Not Found');
    return;
  }

  // /repos/{o}/{r}/contents/...
  if (rest[0] === 'contents') {
    const filePath = rest.slice(1).map(decodeSegment).join('/');
    if (method === 'GET') {
      const tip = resolveRefTip(repo, query.get('ref') ?? undefined);
      if (tip === undefined) {
        sendJsonError(res, 404, 'Not Found');
        return;
      }
      const tree = commitOf(tip)?.tree;
      if (tree === undefined) {
        sendJsonError(res, 404, 'Not Found');
        return;
      }
      if (filePath === '') {
        const entries = listDirEntries(tree, '');
        sendJson(res, 200, entries ?? []);
        return;
      }
      const flat = flattenTree(tree);
      const file = flat.get(filePath);
      if (file !== undefined) {
        const blob = getObject(file.oid);
        sendJson(res, 200, {
          type: 'file',
          encoding: 'base64',
          size: blob?.data.length ?? 0,
          name: filePath.split('/').pop() ?? filePath,
          path: filePath,
          content: blob === undefined ? '' : b64encode(blob.data),
          sha: file.oid,
          url: `/api/v3/repos/${repo.owner}/${repo.name}/contents/${filePath}`,
          html_url: `https://example.invalid/${repo.owner}/${repo.name}/blob/HEAD/${filePath}`,
          git_url: `/api/v3/repos/${repo.owner}/${repo.name}/git/blobs/${file.oid}`,
          download_url: `https://example.invalid/${repo.owner}/${repo.name}/raw/HEAD/${filePath}`,
        });
        return;
      }
      const dir = listDirEntries(tree, filePath);
      if (dir !== null) {
        sendJson(res, 200, dir);
        return;
      }
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    if (method === 'PUT') {
      const message = typeof obj.message === 'string' ? obj.message : 'Update file';
      const contentB64 = typeof obj.content === 'string' ? obj.content : '';
      const branch = typeof obj.branch === 'string' && obj.branch !== '' ? obj.branch : repo.defaultBranch;
      const content = b64decode(contentB64);
      const tip = repo.refs.get(`refs/heads/${branch}`);
      let currentSha: string | undefined;
      if (tip !== undefined) {
        const tree = commitOf(tip)?.tree;
        if (tree !== undefined) currentSha = flattenTree(tree).get(filePath)?.oid;
      }
      if (currentSha !== undefined && typeof obj.sha === 'string' && obj.sha !== '' && obj.sha !== currentSha) {
        sendJsonError(res, 409, 'The file has changed since it was read (stale sha)');
        return;
      }
      const { commitSha, contentSha } = commitFile(repo, branch, filePath, content, message);
      sendJson(res, currentSha === undefined ? 201 : 200, {
        content: {
          name: filePath.split('/').pop() ?? filePath,
          path: filePath,
          sha: contentSha,
          size: content.length,
          encoding: 'base64',
          content: contentB64,
        },
        commit: { sha: commitSha, message },
      });
      return;
    }
    if (method === 'DELETE') {
      const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      if (tip === undefined) {
        sendJsonError(res, 404, 'Not Found');
        return;
      }
      const tree = commitOf(tip)?.tree;
      const currentSha = tree === undefined ? undefined : flattenTree(tree).get(filePath)?.oid;
      if (currentSha === undefined) {
        sendJsonError(res, 404, 'Not Found');
        return;
      }
      if (typeof obj.sha === 'string' && obj.sha !== '' && obj.sha !== currentSha) {
        sendJsonError(res, 409, 'The file has changed since it was read (stale sha)');
        return;
      }
      const message = typeof obj.message === 'string' ? obj.message : 'Delete file';
      const newTree = setPathInTree(tree, filePath.split('/'), null);
      const commitData = buildCommit({
        tree: newTree,
        parents: [tip],
        message,
        author: VIEWER_IDENTITY,
        committer: VIEWER_IDENTITY,
        timestamp: nowEpochSec(),
      });
      const commitSha = putObject('commit', commitData);
      repo.refs.set(`refs/heads/${repo.defaultBranch}`, commitSha);
      repo.updatedAt = nowIso();
      sendJson(res, 200, { commit: { sha: commitSha, message } });
      return;
    }
    sendJsonError(res, 404, 'Not Found');
    return;
  }

  // /repos/{o}/{r}/labels
  if (rest[0] === 'labels') {
    if (rest.length === 1 && method === 'GET') {
      sendJson(res, 200, [...repo.labels.values()].map(labelView));
      return;
    }
    if (rest.length === 1 && method === 'POST') {
      const name = typeof obj.name === 'string' ? obj.name : '';
      if (name === '') {
        sendJsonError(res, 422, 'name is required');
        return;
      }
      const existing = repo.labels.get(name);
      if (existing !== undefined) {
        sendJson(res, 201, labelView(existing));
        return;
      }
      const label: Label = {
        name,
        color: typeof obj.color === 'string' ? obj.color : 'ededed',
        description: typeof obj.description === 'string' ? obj.description : '',
      };
      repo.labels.set(name, label);
      sendJson(res, 201, labelView(label));
      return;
    }
    sendJsonError(res, 404, 'Not Found');
    return;
  }

  // /repos/{o}/{r}/issues...
  if (rest[0] === 'issues') {
    if (rest.length === 1) {
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        const sort = query.get('sort') ?? 'created';
        const direction = query.get('direction') ?? 'desc';
        let list = repo.issues.filter((issue) => state === 'all' || issue.state === state);
        if (sort === 'created') {
          list = [...list].sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
        }
        const { page, link } = paginate(list, query, req);
        sendJson(res, 200, page.map((issue) => issueView(repo, issue)), link === null ? {} : { link });
        return;
      }
      if (method === 'POST') {
        const title = typeof obj.title === 'string' ? obj.title : '';
        if (title === '') {
          sendJsonError(res, 422, 'title is required');
          return;
        }
        const labelNames: string[] = Array.isArray(obj.labels)
          ? obj.labels.map((entry) => (typeof entry === 'string' ? entry : isRecord(entry) && typeof entry.name === 'string' ? entry.name : ''))
          : [];
        const labels: Label[] = [];
        for (const labelName of labelNames) {
          const label = repo.labels.get(labelName);
          if (label === undefined) {
            sendJsonError(res, 422, `Label '${labelName}' does not exist`);
            return;
          }
          labels.push(label);
        }
        const stamp = nowIso();
        const issue: Issue = {
          id: nextObjectId++,
          number: repo.nextIssueNumber++,
          title,
          body: typeof obj.body === 'string' ? obj.body : '',
          state: 'open',
          labels,
          comments: [],
          createdAt: stamp,
          updatedAt: stamp,
        };
        repo.issues.push(issue);
        repo.updatedAt = stamp;
        sendJson(res, 201, issueView(repo, issue));
        return;
      }
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    const number = Number(rest[1]);
    const issue = repo.issues.find((entry) => entry.number === number);
    if (issue === undefined) {
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    if (rest.length === 2) {
      if (method === 'GET') {
        sendJson(res, 200, issueView(repo, issue));
        return;
      }
      if (method === 'PATCH') {
        if (typeof obj.title === 'string') issue.title = obj.title;
        if (typeof obj.body === 'string') issue.body = obj.body;
        if (obj.state === 'open' || obj.state === 'closed') issue.state = obj.state;
        issue.updatedAt = nowIso();
        sendJson(res, 200, issueView(repo, issue));
        return;
      }
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    if (rest.length === 3 && rest[2] === 'comments') {
      if (method === 'GET') {
        sendJson(res, 200, issue.comments.map((comment) => commentView(repo, issue, comment)));
        return;
      }
      if (method === 'POST') {
        const text = typeof obj.body === 'string' ? obj.body : '';
        if (text === '') {
          sendJsonError(res, 422, 'body is required');
          return;
        }
        const stamp = nowIso();
        const comment: IssueComment = { id: nextCommentId++, body: text, createdAt: stamp, updatedAt: stamp };
        issue.comments.push(comment);
        issue.updatedAt = stamp;
        sendJson(res, 201, commentView(repo, issue, comment));
        return;
      }
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    sendJsonError(res, 404, 'Not Found');
    return;
  }

  // /repos/{o}/{r}/pulls...
  if (rest[0] === 'pulls') {
    if (rest.length === 1) {
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        const list = repo.pulls.filter((pull) => state === 'all' || pull.state === state);
        const { page, link } = paginate(list, query, req);
        sendJson(res, 200, page.map((pull) => pullView(repo, pull)), link === null ? {} : { link });
        return;
      }
      if (method === 'POST') {
        const title = typeof obj.title === 'string' ? obj.title : '';
        const head = typeof obj.head === 'string' ? obj.head : '';
        const base = typeof obj.base === 'string' ? obj.base : repo.defaultBranch;
        if (title === '' || head === '') {
          sendJsonError(res, 422, 'title and head are required');
          return;
        }
        const headTip = repo.refs.get(`refs/heads/${head}`);
        const baseTip = repo.refs.get(`refs/heads/${base}`);
        if (headTip === undefined || baseTip === undefined) {
          sendJsonError(res, 422, 'head or base branch does not exist');
          return;
        }
        const duplicate = repo.pulls.find((pull) => pull.state === 'open' && pull.headRef === head && pull.baseRef === base);
        if (duplicate !== undefined) {
          sendJsonError(res, 422, 'A pull request already exists for this head and base');
          return;
        }
        const stamp = nowIso();
        const pull: Pull = {
          id: nextObjectId++,
          number: repo.nextPullNumber++,
          title,
          body: typeof obj.body === 'string' ? obj.body : '',
          state: 'open',
          merged: false,
          mergedAt: null,
          mergeCommitSha: null,
          headRef: head,
          baseRef: base,
          headSha: headTip,
          baseSha: baseTip,
          createdAt: stamp,
          updatedAt: stamp,
        };
        repo.pulls.push(pull);
        repo.updatedAt = stamp;
        sendJson(res, 201, pullView(repo, pull));
        return;
      }
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    const number = Number(rest[1]);
    const pull = repo.pulls.find((entry) => entry.number === number);
    if (pull === undefined) {
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    if (rest.length === 2 && method === 'GET') {
      sendJson(res, 200, pullView(repo, pull));
      return;
    }
    if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
      const headTip = repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headSha;
      sendJson(res, 200, diffCommits(pull.baseSha, headTip));
      return;
    }
    if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
      if (pull.merged) {
        sendJsonError(res, 405, 'Pull request is already merged');
        return;
      }
      if (pull.state !== 'open') {
        sendJsonError(res, 405, 'Pull request is closed');
        return;
      }
      const mergeSha = squashMerge(repo, pull);
      if (mergeSha === null) {
        sendJsonError(res, 405, 'Merge conflict');
        return;
      }
      sendJson(res, 200, { merged: true, sha: mergeSha, message: 'Pull request successfully merged' });
      return;
    }
    sendJsonError(res, 404, 'Not Found');
    return;
  }

  // /repos/{o}/{r}/git/refs...
  if (rest[0] === 'git' && rest[1] === 'refs') {
    if (rest.length === 2 && method === 'POST') {
      const ref = typeof obj.ref === 'string' ? obj.ref : '';
      const sha = typeof obj.sha === 'string' ? obj.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha)) {
        sendJsonError(res, 422, 'ref and sha are required');
        return;
      }
      if (getObject(sha) === undefined) {
        sendJsonError(res, 422, 'sha does not name an object in this repository');
        return;
      }
      if (repo.refs.has(ref)) {
        sendJsonError(res, 422, 'Reference already exists');
        return;
      }
      repo.refs.set(ref, sha);
      const type = getObject(sha)?.type ?? 'commit';
      sendJson(res, 201, { ref, object: { sha, type, url: `/api/v3/repos/${repo.owner}/${repo.name}/git/${type}s/${sha}` }, url: `/api/v3/repos/${repo.owner}/${repo.name}/git/refs/${ref}` });
      return;
    }
    if (rest.length >= 3 && method === 'GET') {
      const ref = `refs/${rest.slice(2).map(decodeSegment).join('/')}`;
      const sha = repo.refs.get(ref);
      if (sha === undefined) {
        sendJsonError(res, 404, 'Not Found');
        return;
      }
      const type = getObject(sha)?.type ?? 'commit';
      sendJson(res, 200, { ref, object: { sha, type, url: `/api/v3/repos/${repo.owner}/${repo.name}/git/${type}s/${sha}` }, url: `/api/v3/repos/${repo.owner}/${repo.name}/git/refs/${ref}` });
      return;
    }
    sendJsonError(res, 404, 'Not Found');
    return;
  }

  sendJsonError(res, 404, 'Not Found');
}

// -------------------------------------------------------------------------------------------
// Git smart HTTP: /{owner}/{repo}.git/info/refs, git-upload-pack, git-receive-pack.
// Upload-pack speaks v2 when the client asks (Git-Protocol: version=2) and v0 otherwise;
// receive-pack is v0 only. Every object the suite already holds is excluded from a
// fetch pack (the suite fails a check that re-sends a held object).
// -------------------------------------------------------------------------------------------

const UPLOAD_PACK_V0_CAPS =
  'multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not no-progress';
const RECEIVE_PACK_CAPS = 'report-status side-band-64k delete-refs ofs-delta';

/** All refs the advertisement shows: HEAD first, then the rest sorted. */
function advertisedRefs(repo: Repo): { name: string; oid: string }[] {
  const refs: { name: string; oid: string }[] = [];
  const defaultTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (defaultTip !== undefined) refs.push({ name: 'HEAD', oid: defaultTip });
  for (const [name, oid] of [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
    refs.push({ name, oid });
  }
  return refs;
}

function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps =
    service === 'git-upload-pack' ? UPLOAD_PACK_V0_CAPS : RECEIVE_PACK_CAPS;
  const fullCaps = `${caps} symref=HEAD:refs/heads/${repo.defaultBranch} agent=forge/1.0`;
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const refs = advertisedRefs(repo);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${fullCaps}\n`));
  } else {
    refs.forEach((ref, index) => {
      const suffix = index === 0 ? `\0${fullCaps}` : '';
      parts.push(pktLine(`${ref.oid} ${ref.name}${suffix}\n`));
      const peeled = peelToCommit(ref.oid);
      if (peeled !== undefined && peeled !== ref.oid && getObject(ref.oid)?.type === 'tag') {
        parts.push(pktLine(`${peeled} ${ref.name}^{}\n`));
      }
    });
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

function v2Advertisement(): Buffer {
  return Buffer.concat([
    pktLine('version 2\n'),
    pktLine('agent=forge/1.0\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow filter\n'),
    pktLine('object-format=sha1\n'),
    PKT_FLUSH,
  ]);
}

/** The v2 ls-refs answer: one line per matching ref, HEAD carrying its symref target. */
function v2LsRefs(repo: Repo, args: string[]): Buffer {
  const prefixes = args.filter((line) => line.startsWith('ref-prefix ')).map((line) => line.slice('ref-prefix '.length));
  const wantPeel = args.includes('peel');
  const wantSymrefs = args.includes('symrefs');
  const wantUnborn = args.includes('unborn');
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  const parts: Buffer[] = [];
  const defaultTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (defaultTip === undefined) {
    if (wantUnborn && keep('HEAD')) {
      parts.push(pktLine(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
    }
  } else if (keep('HEAD')) {
    const symref = wantSymrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : '';
    parts.push(pktLine(`${defaultTip} HEAD${symref}\n`));
  }
  for (const [name, oid] of [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
    if (!keep(name)) continue;
    let suffix = '';
    if (wantPeel) {
      const peeled = peelToCommit(oid);
      if (peeled !== undefined && peeled !== oid && getObject(oid)?.type === 'tag') suffix = ` peeled:${peeled}`;
    }
    parts.push(pktLine(`${oid} ${name}${suffix}\n`));
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/** Walk the fetch: which commits to send, and where the shallow boundary moves. */
function walkFetch(
  repo: Repo,
  wants: string[],
  haves: string[],
  heldShallow: string[],
  depth: number | undefined,
  deepenSince: number | undefined,
  deepenNotRefs: string[],
): { sendCommits: Set<string>; heldCommits: Set<string>; shallowOut: string[]; unshallowOut: string[] } {
  // Held commits: the closure of the haves, stopping descent at held shallow boundaries.
  const heldBoundary = new Set(heldShallow);
  const heldCommits = new Set<string>();
  const heldStack = [...haves];
  while (heldStack.length > 0) {
    const oid = heldStack.pop() as string;
    if (heldCommits.has(oid)) continue;
    const view = commitOf(oid);
    if (view === undefined) continue;
    heldCommits.add(oid);
    if (heldBoundary.has(oid)) continue;
    for (const parent of view.parents) heldStack.push(parent);
  }
  // deepen-not: the closure of the named refs is never sent and never descended into.
  const excluded = new Set<string>();
  for (const refName of deepenNotRefs) {
    const tip = repo.refs.get(refName) ?? repo.refs.get(`refs/heads/${refName}`);
    if (tip === undefined) continue;
    const stack = [tip];
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (excluded.has(oid)) continue;
      const view = commitOf(oid);
      if (view === undefined) continue;
      excluded.add(oid);
      for (const parent of view.parents) stack.push(parent);
    }
  }
  // Breadth-first walk from the wants (want = distance 1).
  const candidates = new Set<string>();
  const queue: { oid: string; dist: number }[] = [];
  for (const want of wants) {
    const peeled = peelToCommit(want);
    if (peeled !== undefined) queue.push({ oid: peeled, dist: 1 });
  }
  const visited = new Set<string>();
  while (queue.length > 0) {
    const { oid, dist } = queue.shift() as { oid: string; dist: number };
    if (visited.has(oid)) continue;
    visited.add(oid);
    const view = commitOf(oid);
    if (view === undefined || excluded.has(oid)) continue;
    if (depth !== undefined && dist > depth) continue;
    if (deepenSince !== undefined && view.timestamp < deepenSince) continue;
    candidates.add(oid);
    const descend = depth === undefined ? !heldCommits.has(oid) && !heldBoundary.has(oid) : dist < depth;
    if (!descend) continue;
    for (const parent of view.parents) queue.push({ oid: parent, dist: dist + 1 });
  }
  const sendCommits = new Set([...candidates].filter((oid) => !heldCommits.has(oid)));
  const shallowOut: string[] = [];
  for (const oid of sendCommits) {
    const view = commitOf(oid);
    if (view !== undefined && view.parents.some((parent) => !sendCommits.has(parent) && !heldCommits.has(parent))) {
      shallowOut.push(oid);
    }
  }
  const unshallowOut: string[] = [];
  for (const oid of heldBoundary) {
    const view = commitOf(oid);
    if (view !== undefined && view.parents.some((parent) => sendCommits.has(parent))) unshallowOut.push(oid);
  }
  return { sendCommits, heldCommits, shallowOut, unshallowOut };
}

/** The objects a fetch sends: the sent commits with their trees and blobs (never descending
 * into unsent parents), plus any non-commit wanted object (an annotated tag) as itself,
 * minus everything the client already holds. */
function collectSendObjects(sendCommits: Set<string>): Map<string, GitObject> {
  const out = new Map<string, GitObject>();
  const seenCommits = new Set<string>();
  const stack = [...sendCommits];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seenCommits.has(oid)) continue;
    const object = getObject(oid);
    if (object === undefined || object.type !== 'commit') continue;
    seenCommits.add(oid);
    out.set(oid, object);
    const view = commitOf(oid);
    if (view === undefined) continue;
    const treeStack = [view.tree];
    while (treeStack.length > 0) {
      const treeOid = treeStack.pop() as string;
      const treeObject = getObject(treeOid);
      if (treeObject === undefined) continue;
      out.set(treeOid, treeObject);
      const entries = treeOf(treeOid);
      if (entries === undefined) continue;
      for (const entry of entries) {
        if (entry.mode === '40000') {
          treeStack.push(entry.oid);
        } else {
          const blob = getObject(entry.oid);
          if (blob !== undefined) out.set(entry.oid, blob);
        }
      }
    }
  }
  return out;
}

function fetchPackBytes(sendCommits: Set<string>, heldCommits: Set<string>, wants: string[]): Buffer | null {
  const sendObjects = collectSendObjects(sendCommits);
  for (const want of wants) {
    const object = getObject(want);
    if (object !== undefined && object.type !== 'commit' && !sendObjects.has(want)) {
      sendObjects.set(want, object);
    }
  }
  const heldOids = new Set(collectSendObjects(heldCommits).keys());
  for (const oid of heldOids) sendObjects.delete(oid);
  if (sendObjects.size === 0) return null;
  return writePack([...sendObjects.values()]);
}

/** Split pack bytes into sideband band-1 packets (chunks stay well under the pkt-line limit). */
function sidebandPackets(pack: Buffer): Buffer[] {
  const packets: Buffer[] = [];
  const CHUNK = 32768;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    const slice = pack.subarray(offset, Math.min(offset + CHUNK, pack.length));
    packets.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  return packets;
}

interface FetchParams {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth?: number;
  deepenSince?: number;
  deepenNot: string[];
}

function parseFetchArgs(args: string[]): FetchParams {
  const params: FetchParams = { wants: [], haves: [], shallow: [], deepenNot: [] };
  for (const line of args) {
    if (line.startsWith('want ')) params.wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) params.haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) params.shallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) {
      const n = Number(line.slice(7).trim());
      if (Number.isFinite(n)) params.depth = n;
    } else if (line.startsWith('deepen-since ')) {
      const n = Number(line.slice('deepen-since '.length).trim());
      if (Number.isFinite(n)) params.deepenSince = n;
    } else if (line.startsWith('deepen-not ')) params.deepenNot.push(line.slice('deepen-not '.length).trim());
  }
  return params;
}

async function handleGit(req: IncomingMessage, res: ServerResponse, segments: string[], query: URLSearchParams): Promise<void> {
  const method = req.method ?? 'GET';
  if (!isAuthed(req)) {
    sendJsonError(res, 401, 'Requires authentication');
    return;
  }
  if (segments.length < 2 || !segments[1]?.endsWith('.git')) {
    sendJsonError(res, 404, 'Not Found');
    return;
  }
  const owner = decodeSegment(segments[0] as string);
  const name = decodeSegment((segments[1] as string).slice(0, -4));
  const repo = findRepo(owner, name);
  if (repo === undefined) {
    sendJsonError(res, 404, 'Not Found');
    return;
  }
  const tail = segments.slice(2);

  // GET /{o}/{r}.git/info/refs?service=git-upload-pack|git-receive-pack
  if (method === 'GET' && tail.length === 2 && tail[0] === 'info' && tail[1] === 'refs') {
    const service = query.get('service');
    if (service === 'git-upload-pack') {
      const wantsV2 = (req.headers['git-protocol'] ?? '').includes('version=2');
      if (wantsV2) {
        sendRaw(res, 200, v2Advertisement(), 'application/x-git-upload-pack-advertisement');
      } else {
        sendRaw(res, 200, v0Advertisement(repo, 'git-upload-pack'), 'application/x-git-upload-pack-advertisement');
      }
      return;
    }
    if (service === 'git-receive-pack') {
      sendRaw(res, 200, v0Advertisement(repo, 'git-receive-pack'), 'application/x-git-receive-pack-advertisement');
      return;
    }
    sendJsonError(res, 400, 'service parameter is required');
    return;
  }

  // POST /{o}/{r}.git/git-upload-pack
  if (method === 'POST' && tail.length === 1 && tail[0] === 'git-upload-pack') {
    const body = await readBody(req);
    let packets: Packet[];
    try {
      packets = decodePktLines(body);
    } catch {
      sendJsonError(res, 400, 'malformed pkt-line stream');
      return;
    }
    const wantsV2 = (req.headers['git-protocol'] ?? '').includes('version=2');
    if (wantsV2) {
      // Split the request at the delim: header lines (command, agent, object-format)
      // then the argument lines.
      const headerLines: string[] = [];
      const argLines: string[] = [];
      let afterDelim = false;
      for (const packet of packets) {
        if (packet.kind === 'delim') {
          afterDelim = true;
          continue;
        }
        if (packet.kind !== 'data') continue;
        const text = packet.payload.toString('utf8');
        if (afterDelim) argLines.push(text);
        else headerLines.push(text);
      }
      const command = headerLines.find((line) => line.startsWith('command='))?.slice('command='.length).trim();
      if (command === 'ls-refs') {
        sendRaw(res, 200, v2LsRefs(repo, argLines.map((line) => line.replace(/\n$/, ''))), 'application/x-git-upload-pack-result');
        return;
      }
      if (command === 'fetch') {
        const params = parseFetchArgs(argLines.map((line) => line.replace(/\n$/, '')));
        const { sendCommits, heldCommits, shallowOut, unshallowOut } = walkFetch(
          repo,
          params.wants,
          params.haves,
          params.shallow,
          params.depth,
          params.deepenSince,
          params.deepenNot,
        );
        const pack = fetchPackBytes(sendCommits, heldCommits, params.wants);
        const parts: Buffer[] = [pktLine('acknowledgments\n'), pktLine('NAK\n'), PKT_DELIM];
        if (shallowOut.length > 0 || unshallowOut.length > 0) {
          parts.push(pktLine('shallow-info\n'));
          for (const oid of shallowOut) parts.push(pktLine(`shallow ${oid}\n`));
          for (const oid of unshallowOut) parts.push(pktLine(`unshallow ${oid}\n`));
          parts.push(PKT_DELIM);
        }
        if (pack !== null) {
          parts.push(pktLine('packfile\n'));
          parts.push(...sidebandPackets(pack));
        }
        parts.push(PKT_FLUSH);
        sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
        return;
      }
      sendJsonError(res, 400, 'unknown command');
      return;
    }
    // v0 fetch: section 1 = wants (+shallow/deepen), flush, section 2 = haves + done, flush.
    const sections: string[][] = [[]];
    for (const packet of packets) {
      if (packet.kind === 'flush') {
        sections.push([]);
        continue;
      }
      if (packet.kind !== 'data') continue;
      const text = packet.payload.toString('utf8');
      const nul = text.indexOf('\0');
      (sections[sections.length - 1] as string[]).push(nul >= 0 ? text.slice(0, nul).replace(/\n$/, '') : text.replace(/\n$/, ''));
    }
    const wantLines = sections[0] ?? [];
    const haveLines = sections[1] ?? [];
    const params = parseFetchArgs([...wantLines, ...haveLines]);
    const { sendCommits, heldCommits, shallowOut, unshallowOut } = walkFetch(
      repo,
      params.wants,
      params.haves,
      params.shallow,
      params.depth,
      params.deepenSince,
      params.deepenNot,
    );
    const pack = fetchPackBytes(sendCommits, heldCommits, params.wants);
    const parts: Buffer[] = [pktLine('NAK\n')];
    for (const oid of shallowOut) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of unshallowOut) parts.push(pktLine(`unshallow ${oid}\n`));
    if (pack !== null) parts.push(...sidebandPackets(pack));
    parts.push(PKT_FLUSH);
    sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
    return;
  }

  // POST /{o}/{r}.git/git-receive-pack (v0 only)
  if (method === 'POST' && tail.length === 1 && tail[0] === 'git-receive-pack') {
    const body = await readBody(req);
    interface PushCommand {
      oldOid: string;
      newOid: string;
      ref: string;
    }
    // Walk pkt-lines only up to the command list's flush; the pack follows as raw bytes.
    const commands: PushCommand[] = [];
    let offset = 0;
    let packOffset = body.length;
    let sawFlush = false;
    while (offset + 4 <= body.length) {
      const lenHex = body.subarray(offset, offset + 4).toString('ascii');
      if (lenHex === '0000') {
        packOffset = offset + 4;
        sawFlush = true;
        break;
      }
      if (!/^[0-9a-fA-F]{4}$/.test(lenHex)) {
        sendJsonError(res, 400, 'malformed pkt-line stream');
        return;
      }
      const len = parseInt(lenHex, 16);
      if (len < 4 || offset + len > body.length) {
        sendJsonError(res, 400, 'malformed pkt-line stream');
        return;
      }
      const text = body.subarray(offset + 4, offset + len).toString('utf8');
      const nul = text.indexOf('\0');
      const line = (nul >= 0 ? text.slice(0, nul) : text).replace(/\n$/, '');
      const match = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/.exec(line);
      if (match === null) {
        sendJsonError(res, 400, 'malformed receive-pack command');
        return;
      }
      commands.push({ oldOid: match[1] as string, newOid: match[2] as string, ref: match[3] as string });
      offset += len;
    }
    if (!sawFlush || commands.length === 0) {
      sendJsonError(res, 400, 'malformed receive-pack command');
      return;
    }
    const packBytes = body.subarray(packOffset);
    const reportLines: string[] = [];
    let unpackOk = true;
    if (packBytes.length > 0) {
      try {
        const { objects } = readPack(packBytes);
        for (const object of objects.values()) putObject(object.type, object.data);
      } catch (err) {
        unpackOk = false;
        reportLines.push(`unpack ${(err as Error).message}\n`);
      }
    }
    if (unpackOk) reportLines.push('unpack ok\n');
    for (const command of commands) {
      const current = repo.refs.get(command.ref);
      let ok = false;
      let reason = '';
      if (!unpackOk) {
        reason = 'unpack failed';
      } else if (command.newOid === ZERO_OID) {
        // Delete.
        if (current === undefined) ok = true;
        else if (command.oldOid === ZERO_OID || current === command.oldOid) ok = true;
        else reason = 'non-fast-forward';
      } else if (getObject(command.newOid) === undefined) {
        reason = 'object not found';
      } else if (command.oldOid === ZERO_OID) {
        // Create.
        if (current === undefined) ok = true;
        else reason = 'non-fast-forward';
      } else if (current === command.newOid) {
        ok = true;
      } else if (current === command.oldOid && isAncestor(command.oldOid, command.newOid)) {
        ok = true;
      } else {
        reason = 'non-fast-forward';
      }
      if (ok && unpackOk) {
        if (command.ref.startsWith('refs/heads/') && command.newOid !== ZERO_OID) {
          if (peelToCommit(command.newOid) === undefined) {
            ok = false;
            reason = 'not a commit';
          }
        }
      }
      if (ok) {
        if (command.newOid === ZERO_OID) repo.refs.delete(command.ref);
        else repo.refs.set(command.ref, command.newOid);
        repo.updatedAt = nowIso();
        reportLines.push(`ok ${command.ref}\n`);
      } else {
        reportLines.push(`ng ${command.ref} ${reason || 'failed'}\n`);
      }
    }
    const band1 = Buffer.concat(reportLines.map((line) => pktLine(line)));
    const parts = [pktLine(Buffer.concat([Buffer.from([1]), band1])), PKT_FLUSH];
    sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-receive-pack-result');
    return;
  }

  sendJsonError(res, 404, 'Not Found');
}

// -------------------------------------------------------------------------------------------
// GraphQL v4 at POST /api/graphql: a small parser and executor for the shapes gh and the
// suite use (viewer, repository, node, __type, issue/pull-request connections, mutations).
// Unknown fields answer HTTP 200 with an errors array naming the field; a batched array body
// answers an array of results in order. Unauthenticated requests are exactly 401.
// -------------------------------------------------------------------------------------------

interface GqlField {
  alias?: string;
  name: string;
  args: Record<string, unknown>;
  selections?: GqlSelection[];
}
type GqlSelection =
  | { kind: 'field'; field: GqlField }
  | { kind: 'inline'; typeCondition?: string; selections: GqlSelection[] }
  | { kind: 'spread'; name: string };
interface GqlOperation {
  kind: 'query' | 'mutation';
  name?: string;
  variables: Record<string, unknown>;
  selections: GqlSelection[];
}
interface GqlDocument {
  operations: GqlOperation[];
  fragments: Map<string, GqlSelection[]>;
}

interface GqlToken {
  kind: 'name' | 'int' | 'float' | 'string' | 'punct' | 'ellipsis' | 'variable';
  value: string;
}

function tokenizeGql(src: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i] as string;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && src.slice(i, i + 3) === '...') {
      tokens.push({ kind: 'ellipsis', value: '...' });
      i += 3;
      continue;
    }
    if ('{}():$![]=@|&'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1] as string;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += src[j] as string;
          j += 1;
        }
      }
      tokens.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      let isFloat = false;
      while (j < src.length && /[0-9.eE+-]/.test(src[j] as string)) {
        if (src[j] === '.' || src[j] === 'e' || src[j] === 'E') isFloat = true;
        j += 1;
      }
      tokens.push({ kind: isFloat ? 'float' : 'int', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j] as string)) j += 1;
      tokens.push({ kind: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`GraphQL parse error at ${JSON.stringify(src.slice(i, i + 12))}`);
  }
  return tokens;
}

class GqlParser {
  private pos = 0;
  private readonly tokens: GqlToken[];
  constructor(tokens: GqlToken[]) {
    this.tokens = tokens;
  }

  private peek(): GqlToken | undefined {
    return this.tokens[this.pos];
  }
  private next(): GqlToken {
    const token = this.tokens[this.pos];
    if (token === undefined) throw new Error('GraphQL parse error: unexpected end of document');
    this.pos += 1;
    return token;
  }
  private expectPunct(value: string): void {
    const token = this.next();
    if (token.kind !== 'punct' || token.value !== value) {
      throw new Error(`GraphQL parse error: expected '${value}', saw '${token.value}'`);
    }
  }
  private expectName(value?: string): string {
    const token = this.next();
    if (token.kind !== 'name') throw new Error(`GraphQL parse error: expected a name, saw '${token.value}'`);
    if (value !== undefined && token.value !== value) throw new Error(`GraphQL parse error: expected '${value}', saw '${token.value}'`);
    return token.value;
  }

  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, GqlSelection[]>();
    while (this.pos < this.tokens.length) {
      const token = this.peek() as GqlToken;
      if (token.kind === 'punct' && token.value === '{') {
        operations.push({ kind: 'query', variables: {}, selections: this.parseSelectionSet() });
        continue;
      }
      if (token.kind === 'name' && (token.value === 'query' || token.value === 'mutation')) {
        const kind = this.next().value as 'query' | 'mutation';
        let name: string | undefined;
        const nextToken = this.peek();
        if (nextToken?.kind === 'name') name = this.next().value;
        const variables = this.parseVariableDefinitions();
        operations.push({ kind, name, variables, selections: this.parseSelectionSet() });
        continue;
      }
      if (token.kind === 'name' && token.value === 'fragment') {
        this.next();
        const name = this.expectName();
        this.expectName('on');
        this.expectName();
        fragments.set(name, this.parseSelectionSet());
        continue;
      }
      throw new Error(`GraphQL parse error: unexpected '${token.value}'`);
    }
    return { operations, fragments };
  }

  private parseVariableDefinitions(): Record<string, unknown> {
    const defs: Record<string, unknown> = {};
    if (this.peek()?.kind === 'punct' && this.peek()?.value === '(') {
      this.next();
      while (!(this.peek()?.kind === 'punct' && this.peek()?.value === ')')) {
        this.expectPunct('$');
        const name = this.expectName();
        this.expectPunct(':');
        this.parseType();
        if (this.peek()?.kind === 'punct' && this.peek()?.value === '=') {
          this.next();
          defs[name] = this.parseValue();
        } else {
          defs[name] = undefined;
        }
        if (this.peek() === undefined) throw new Error('GraphQL parse error: unterminated variable definitions');
      }
      this.next();
    }
    return defs;
  }

  private parseType(): void {
    const token = this.peek();
    if (token?.kind === 'punct' && token.value === '[') {
      this.next();
      this.parseType();
      this.expectPunct(']');
    } else {
      this.expectName();
    }
    if (this.peek()?.kind === 'punct' && this.peek()?.value === '!') this.next();
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!(this.peek()?.kind === 'punct' && this.peek()?.value === '}')) {
      if (this.peek() === undefined) throw new Error('GraphQL parse error: unterminated selection set');
      selections.push(this.parseSelection());
    }
    this.next();
    return selections;
  }

  private parseSelection(): GqlSelection {
    const token = this.peek() as GqlToken;
    if (token.kind === 'ellipsis') {
      this.next();
      const nextToken = this.peek();
      if (nextToken?.kind === 'name' && nextToken.value === 'on') {
        this.next();
        const typeCondition = this.expectName();
        return { kind: 'inline', typeCondition, selections: this.parseSelectionSet() };
      }
      if (nextToken?.kind === 'name') {
        return { kind: 'spread', name: this.next().value };
      }
      return { kind: 'inline', selections: this.parseSelectionSet() };
    }
    let alias: string | undefined;
    let name = this.expectName();
    if (this.peek()?.kind === 'punct' && this.peek()?.value === ':') {
      this.next();
      alias = name;
      name = this.expectName();
    }
    const args = this.parseArguments();
    this.parseDirectives();
    let selections: GqlSelection[] | undefined;
    if (this.peek()?.kind === 'punct' && this.peek()?.value === '{') {
      selections = this.parseSelectionSet();
    }
    return { kind: 'field', field: { alias, name, args, selections } };
  }

  private parseArguments(): Record<string, unknown> {
    const args: Record<string, unknown> = {};
    if (this.peek()?.kind === 'punct' && this.peek()?.value === '(') {
      this.next();
      while (!(this.peek()?.kind === 'punct' && this.peek()?.value === ')')) {
        const name = this.expectName();
        this.expectPunct(':');
        args[name] = this.parseValue();
        if (this.peek() === undefined) throw new Error('GraphQL parse error: unterminated arguments');
      }
      this.next();
    }
    return args;
  }

  private parseDirectives(): void {
    while (this.peek()?.kind === 'punct' && this.peek()?.value === '@') {
      this.next();
      this.expectName();
      this.parseArguments();
    }
  }

  private parseValue(): unknown {
    const token = this.next();
    if (token.kind === 'punct' && token.value === '$') return { __var: this.expectName() };
    if (token.kind === 'string') return token.value;
    if (token.kind === 'int') return Number(token.value);
    if (token.kind === 'float') return Number(token.value);
    if (token.kind === 'name') {
      if (token.value === 'true') return true;
      if (token.value === 'false') return false;
      if (token.value === 'null') return null;
      return { __enum: token.value };
    }
    if (token.kind === 'punct' && token.value === '[') {
      const list: unknown[] = [];
      while (!(this.peek()?.kind === 'punct' && this.peek()?.value === ']')) {
        list.push(this.parseValue());
        if (this.peek() === undefined) throw new Error('GraphQL parse error: unterminated list');
      }
      this.next();
      return list;
    }
    if (token.kind === 'punct' && token.value === '{') {
      const obj: Record<string, unknown> = {};
      while (!(this.peek()?.kind === 'punct' && this.peek()?.value === '}')) {
        const name = this.expectName();
        this.expectPunct(':');
        obj[name] = this.parseValue();
        if (this.peek() === undefined) throw new Error('GraphQL parse error: unterminated input object');
      }
      this.next();
      return obj;
    }
    throw new Error(`GraphQL parse error: unexpected value '${token.value}'`);
  }
}

function resolveGqlValue(value: unknown, variables: Record<string, unknown>): unknown {
  if (isRecord(value)) {
    if ('__var' in value && typeof value.__var === 'string') return variables[value.__var] ?? null;
    if ('__enum' in value && typeof value.__enum === 'string') return value.__enum;
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) out[key] = resolveGqlValue(entry, variables);
    return out;
  }
  if (Array.isArray(value)) return value.map((entry) => resolveGqlValue(entry, variables));
  return value;
}

// --- Sources: tagged wrappers the executor resolves fields against. ---

type GqlSource =
  | { __type: 'Query' }
  | { __type: 'Mutation' }
  | { __type: 'User'; login: string }
  | { __type: 'Repository'; repo: Repo }
  | { __type: 'Issue'; repo: Repo; issue: Issue }
  | { __type: 'PullRequest'; repo: Repo; pull: Pull }
  | { __type: 'IssueComment'; repo: Repo; issue: Issue; comment: IssueComment }
  | { __type: 'Ref'; name: string }
  | { __type: 'IssueConnection'; repo: Repo; nodes: Issue[]; pageInfo: PageInfo }
  | { __type: 'PullRequestConnection'; repo: Repo; nodes: Pull[]; pageInfo: PageInfo }
  | { __type: 'FileConnection'; nodes: FileChange[]; pageInfo: PageInfo }
  | { __type: 'PageInfo'; pageInfo: PageInfo }
  | { __type: 'IssueEdge'; repo: Repo; issue: Issue; cursor: string }
  | { __type: 'PullRequestEdge'; repo: Repo; pull: Pull; cursor: string }
  | { __type: 'FileEdge'; file: FileChange; cursor: string }
  | { __type: 'FileNode'; file: FileChange }
  | { __type: '__Type'; name: string }
  | { __type: '__Schema' }
  | { __type: 'CreateIssuePayload'; repo: Repo; issue: Issue }
  | { __type: 'CloseIssuePayload'; repo: Repo; issue: Issue }
  | { __type: 'CreatePullRequestPayload'; repo: Repo; pull: Pull }
  | { __type: 'MergePullRequestPayload'; repo: Repo; pull: Pull }
  | { __type: 'AddCommentPayload'; repo: Repo; issue: Issue; comment: IssueComment }
  | { __type: 'CommentEdge'; repo: Repo; issue: Issue; comment: IssueComment };

interface PageInfo {
  hasNextPage: boolean;
  hasPreviousPage: boolean;
  startCursor: string | null;
  endCursor: string | null;
}

function encodeCursor(index: number): string {
  return Buffer.from(`cursor:${index}`, 'utf8').toString('base64');
}
function decodeCursor(cursor: unknown): number {
  if (typeof cursor !== 'string' || cursor === '') return -1;
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(text);
    return match === null ? -1 : Number(match[1]);
  } catch {
    return -1;
  }
}

/** A Relay connection over an ordered list: first/after slicing plus pageInfo. */
function makeConnection<T>(items: readonly T[], first: unknown, after: unknown): { nodes: T[]; pageInfo: PageInfo } {
  const start = decodeCursor(after) + 1;
  const count = typeof first === 'number' && first >= 0 ? first : items.length;
  const slice = items.slice(start, start + count);
  const endIndex = start + slice.length - 1;
  return {
    nodes: [...slice],
    pageInfo: {
      hasNextPage: start + slice.length < items.length,
      hasPreviousPage: start > 0,
      startCursor: slice.length === 0 ? null : encodeCursor(start),
      endCursor: slice.length === 0 ? null : encodeCursor(endIndex),
    },
  };
}

const INTROSPECTION_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'author', 'repository', 'labels', 'comments', 'closed', 'closedAt', 'assignees', 'participants', 'timelineItems'],
  PullRequest: ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files', 'title', 'body', 'url', 'createdAt', 'updatedAt', 'author', 'repository', 'headRefOid', 'baseRefOid', 'mergedAt', 'mergeCommit', 'reviewDecision'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'url', 'createdAt', 'updatedAt', 'description', 'isPrivate', 'forkCount', 'stargazerCount'],
  SearchType: [],
};
const SEARCH_TYPE_VALUES = ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE', 'COMMIT', 'LABEL', 'MILESTONE', 'PACKAGE', 'TOPIC', 'WIKI'];

interface GqlExecContext {
  errors: { message: string; path: (string | number)[] }[];
  fragments: Map<string, GqlSelection[]>;
  variables: Record<string, unknown>;
}

function executeSelections(
  source: GqlSource,
  selections: GqlSelection[],
  ctx: GqlExecContext,
  path: (string | number)[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'inline') {
      if (selection.typeCondition !== undefined && selection.typeCondition !== source.__type) continue;
      Object.assign(out, executeSelections(source, selection.selections, ctx, path));
      continue;
    }
    if (selection.kind === 'spread') {
      const fragment = ctx.fragments.get(selection.name);
      if (fragment !== undefined) Object.assign(out, executeSelections(source, fragment, ctx, path));
      continue;
    }
    const field = selection.field;
    const key = field.alias ?? field.name;
    const fieldPath = [...path, key];
    out[key] = resolveField(source, field, ctx, fieldPath);
  }
  return out;
}

function unknownField(source: GqlSource, field: GqlField, ctx: GqlExecContext, path: (string | number)[]): null {
  ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${source.__type}".`, path });
  return null;
}

function resolveField(source: GqlSource, field: GqlField, ctx: GqlExecContext, path: (string | number)[]): unknown {
  const args: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(field.args)) args[key] = resolveGqlValue(value, ctx.variables);
  const selections = field.selections ?? [];
  const select = (value: GqlSource): Record<string, unknown> => executeSelections(value, selections, ctx, path);
  const scalar = (value: unknown): unknown => {
    if (value === null || value === undefined) return null;
    if (selections.length > 0) {
      ctx.errors.push({ message: `Field "${field.name}" must not have a selection since type "${typeof value}" has no subfields.`, path });
      return null;
    }
    return value;
  };

  switch (source.__type) {
    case 'Query': {
      if (field.name === 'viewer') return select({ __type: 'User', login: VIEWER.login });
      if (field.name === 'repository') {
        const repo = typeof args.owner === 'string' && typeof args.name === 'string' ? findRepo(args.owner, args.name) : undefined;
        if (repo === undefined) return scalar(null);
        return select({ __type: 'Repository', repo });
      }
      if (field.name === 'node') {
        const parsed = typeof args.id === 'string' ? parseGlobalId(args.id) : null;
        if (parsed === null) return scalar(null);
        if (parsed.kind === 'Repository' && parsed.parts.length >= 2) {
          const repo = findRepo(parsed.parts[0] as string, parsed.parts[1] as string);
          if (repo === undefined) return scalar(null);
          return select({ __type: 'Repository', repo });
        }
        if (parsed.kind === 'Issue' && parsed.parts.length >= 3) {
          const repo = findRepo(parsed.parts[0] as string, parsed.parts[1] as string);
          const issue = repo?.issues.find((entry) => entry.number === Number(parsed.parts[2]));
          if (repo === undefined || issue === undefined) return scalar(null);
          return select({ __type: 'Issue', repo, issue });
        }
        if (parsed.kind === 'PullRequest' && parsed.parts.length >= 3) {
          const repo = findRepo(parsed.parts[0] as string, parsed.parts[1] as string);
          const pull = repo?.pulls.find((entry) => entry.number === Number(parsed.parts[2]));
          if (repo === undefined || pull === undefined) return scalar(null);
          return select({ __type: 'PullRequest', repo, pull });
        }
        return scalar(null);
      }
      if (field.name === '__type') {
        if (typeof args.name !== 'string' || !(args.name in INTROSPECTION_FIELDS)) return scalar(null);
        return select({ __type: '__Type', name: args.name });
      }
      if (field.name === '__schema') return select({ __type: '__Schema' });
      return unknownField(source, field, ctx, path);
    }
    case 'Mutation': {
      if (field.name === 'createIssue') {
        const input = isRecord(args.input) ? args.input : {};
        const parsed = typeof input.repositoryId === 'string' ? parseGlobalId(input.repositoryId) : null;
        const repo = parsed !== null && parsed.kind === 'Repository' && parsed.parts.length >= 2 ? findRepo(parsed.parts[0] as string, parsed.parts[1] as string) : undefined;
        if (repo === undefined) {
          ctx.errors.push({ message: 'createIssue: repository not found', path });
          return null;
        }
        const stamp = nowIso();
        const issue: Issue = {
          id: nextObjectId++,
          number: repo.nextIssueNumber++,
          title: typeof input.title === 'string' ? input.title : '',
          body: typeof input.body === 'string' ? input.body : '',
          state: 'open',
          labels: [],
          comments: [],
          createdAt: stamp,
          updatedAt: stamp,
        };
        repo.issues.push(issue);
        repo.updatedAt = stamp;
        return select({ __type: 'CreateIssuePayload', repo, issue });
      }
      if (field.name === 'closeIssue') {
        const input = isRecord(args.input) ? args.input : {};
        const parsed = typeof input.issueId === 'string' ? parseGlobalId(input.issueId) : null;
        const repo = parsed !== null && parsed.kind === 'Issue' && parsed.parts.length >= 3 ? findRepo(parsed.parts[0] as string, parsed.parts[1] as string) : undefined;
        const issue = repo?.issues.find((entry) => entry.number === Number(parsed?.parts[2]));
        if (repo === undefined || issue === undefined) {
          ctx.errors.push({ message: 'closeIssue: issue not found', path });
          return null;
        }
        issue.state = 'closed';
        issue.updatedAt = nowIso();
        return select({ __type: 'CloseIssuePayload', repo, issue });
      }
      if (field.name === 'createPullRequest') {
        const input = isRecord(args.input) ? args.input : {};
        const parsed = typeof input.repositoryId === 'string' ? parseGlobalId(input.repositoryId) : null;
        const repo = parsed !== null && parsed.kind === 'Repository' && parsed.parts.length >= 2 ? findRepo(parsed.parts[0] as string, parsed.parts[1] as string) : undefined;
        const head = typeof input.headRefName === 'string' ? input.headRefName : '';
        const base = typeof input.baseRefName === 'string' ? input.baseRefName : repo?.defaultBranch ?? 'main';
        if (repo === undefined) {
          ctx.errors.push({ message: 'createPullRequest: repository not found', path });
          return null;
        }
        const headTip = repo.refs.get(`refs/heads/${head}`);
        const baseTip = repo.refs.get(`refs/heads/${base}`);
        if (headTip === undefined || baseTip === undefined) {
          ctx.errors.push({ message: 'createPullRequest: head or base branch does not exist', path });
          return null;
        }
        const duplicate = repo.pulls.find((pull) => pull.state === 'open' && pull.headRef === head && pull.baseRef === base);
        if (duplicate !== undefined) {
          ctx.errors.push({ message: 'createPullRequest: a pull request already exists for this head and base', path });
          return null;
        }
        const stamp = nowIso();
        const pull: Pull = {
          id: nextObjectId++,
          number: repo.nextPullNumber++,
          title: typeof input.title === 'string' ? input.title : '',
          body: typeof input.body === 'string' ? input.body : '',
          state: 'open',
          merged: false,
          mergedAt: null,
          mergeCommitSha: null,
          headRef: head,
          baseRef: base,
          headSha: headTip,
          baseSha: baseTip,
          createdAt: stamp,
          updatedAt: stamp,
        };
        repo.pulls.push(pull);
        repo.updatedAt = stamp;
        return select({ __type: 'CreatePullRequestPayload', repo, pull });
      }
      if (field.name === 'mergePullRequest') {
        const input = isRecord(args.input) ? args.input : {};
        const parsed = typeof input.pullRequestId === 'string' ? parseGlobalId(input.pullRequestId) : null;
        const repo = parsed !== null && parsed.kind === 'PullRequest' && parsed.parts.length >= 3 ? findRepo(parsed.parts[0] as string, parsed.parts[1] as string) : undefined;
        const pull = repo?.pulls.find((entry) => entry.number === Number(parsed?.parts[2]));
        if (repo === undefined || pull === undefined) {
          ctx.errors.push({ message: 'mergePullRequest: pull request not found', path });
          return null;
        }
        if (pull.merged) {
          ctx.errors.push({ message: 'mergePullRequest: pull request is already merged', path });
          return null;
        }
        const mergeSha = squashMerge(repo, pull);
        if (mergeSha === null) {
          ctx.errors.push({ message: 'mergePullRequest: merge conflict', path });
          return null;
        }
        return select({ __type: 'MergePullRequestPayload', repo, pull });
      }
      if (field.name === 'addComment') {
        const input = isRecord(args.input) ? args.input : {};
        const parsed = typeof input.subjectId === 'string' ? parseGlobalId(input.subjectId) : null;
        const repo = parsed !== null && parsed.kind === 'Issue' && parsed.parts.length >= 3 ? findRepo(parsed.parts[0] as string, parsed.parts[1] as string) : undefined;
        const issue = repo?.issues.find((entry) => entry.number === Number(parsed?.parts[2]));
        if (repo === undefined || issue === undefined) {
          ctx.errors.push({ message: 'addComment: subject not found', path });
          return null;
        }
        const stamp = nowIso();
        const comment: IssueComment = { id: nextCommentId++, body: typeof input.body === 'string' ? input.body : '', createdAt: stamp, updatedAt: stamp };
        issue.comments.push(comment);
        issue.updatedAt = stamp;
        return select({ __type: 'AddCommentPayload', repo, issue, comment });
      }
      return unknownField(source, field, ctx, path);
    }
    case 'User': {
      if (field.name === 'login') return scalar(source.login);
      if (field.name === 'id') return scalar(globalId('User', source.login));
      if (field.name === 'name') return scalar(source.login === VIEWER.login ? VIEWER.name : source.login);
      if (field.name === 'email') return scalar(source.login === VIEWER.login ? VIEWER.email : null);
      return unknownField(source, field, ctx, path);
    }
    case 'Repository': {
      const repo = source.repo;
      if (field.name === 'id') return scalar(globalId('Repository', repo.owner, repo.name));
      if (field.name === 'databaseId') return scalar(repo.id);
      if (field.name === 'name') return scalar(repo.name);
      if (field.name === 'nameWithOwner') return scalar(`${repo.owner}/${repo.name}`);
      if (field.name === 'owner') return select({ __type: 'User', login: repo.owner });
      if (field.name === 'defaultBranchRef') return select({ __type: 'Ref', name: repo.defaultBranch });
      if (field.name === 'viewerPermission') return scalar('ADMIN');
      if (field.name === 'hasIssuesEnabled') return scalar(true);
      if (field.name === 'description') return scalar(repo.description);
      if (field.name === 'isPrivate') return scalar(repo.private);
      if (field.name === 'url') return scalar(`https://example.invalid/${repo.owner}/${repo.name}`);
      if (field.name === 'createdAt') return scalar(repo.createdAt);
      if (field.name === 'updatedAt') return scalar(repo.updatedAt);
      if (field.name === 'issue') {
        const issue = repo.issues.find((entry) => entry.number === Number(args.number));
        if (issue === undefined) return scalar(null);
        return select({ __type: 'Issue', repo, issue });
      }
      if (field.name === 'issues') {
        let list = [...repo.issues];
        if (Array.isArray(args.states)) {
          const wanted = new Set((args.states as unknown[]).map((state) => String(state).toLowerCase()));
          list = list.filter((issue) => wanted.has(issue.state));
        }
        if (isRecord(args.orderBy)) {
          const direction = String(args.orderBy.direction ?? 'DESC');
          list.sort((a, b) => (direction === 'ASC' ? a.number - b.number : b.number - a.number));
        } else {
          list.sort((a, b) => b.number - a.number);
        }
        const { nodes, pageInfo } = makeConnection(list, args.first, args.after);
        return select({ __type: 'IssueConnection', repo, nodes, pageInfo });
      }
      if (field.name === 'pullRequest') {
        const pull = repo.pulls.find((entry) => entry.number === Number(args.number));
        if (pull === undefined) return scalar(null);
        return select({ __type: 'PullRequest', repo, pull });
      }
      if (field.name === 'pullRequests') {
        let list = repo.pulls.filter((pull) => pull.state === 'open');
        if (Array.isArray(args.states)) {
          const wanted = new Set((args.states as unknown[]).map((state) => String(state).toLowerCase()));
          list = repo.pulls.filter((pull) => wanted.has(pull.state));
        }
        list.sort((a, b) => b.number - a.number);
        const { nodes, pageInfo } = makeConnection(list, args.first, args.after);
        return select({ __type: 'PullRequestConnection', repo, nodes, pageInfo });
      }
      return unknownField(source, field, ctx, path);
    }
    case 'Issue': {
      const issue = source.issue;
      if (field.name === 'id') return scalar(globalId('Issue', source.repo.owner, source.repo.name, issue.number));
      if (field.name === 'number') return scalar(issue.number);
      if (field.name === 'title') return scalar(issue.title);
      if (field.name === 'body') return scalar(issue.body);
      if (field.name === 'state') return scalar(issue.state.toUpperCase());
      if (field.name === 'url') return scalar(`https://example.invalid/${source.repo.owner}/${source.repo.name}/issues/${issue.number}`);
      if (field.name === 'createdAt') return scalar(issue.createdAt);
      if (field.name === 'updatedAt') return scalar(issue.updatedAt);
      if (field.name === 'author') return select({ __type: 'User', login: VIEWER.login });
      if (field.name === 'repository') return select({ __type: 'Repository', repo: source.repo });
      if (field.name === 'closed') return scalar(issue.state === 'closed');
      if (field.name === 'closedAt') return scalar(issue.state === 'closed' ? issue.updatedAt : null);
      return unknownField(source, field, ctx, path);
    }
    case 'PullRequest': {
      const pull = source.pull;
      if (field.name === 'id') return scalar(globalId('PullRequest', source.repo.owner, source.repo.name, pull.number));
      if (field.name === 'number') return scalar(pull.number);
      if (field.name === 'title') return scalar(pull.title);
      if (field.name === 'body') return scalar(pull.body);
      if (field.name === 'state') return scalar(pull.state.toUpperCase());
      if (field.name === 'merged') return scalar(pull.merged);
      if (field.name === 'mergedAt') return scalar(pull.mergedAt);
      if (field.name === 'headRefName') return scalar(pull.headRef);
      if (field.name === 'baseRefName') return scalar(pull.baseRef);
      if (field.name === 'headRefOid') return scalar(pull.headSha);
      if (field.name === 'baseRefOid') return scalar(pull.baseSha);
      if (field.name === 'mergeable') {
        if (pull.merged || pull.state !== 'open') return scalar('UNKNOWN');
        return scalar(mergeConflict(source.repo, pull) ? 'CONFLICTING' : 'MERGEABLE');
      }
      if (field.name === 'url') return scalar(`https://example.invalid/${source.repo.owner}/${source.repo.name}/pull/${pull.number}`);
      if (field.name === 'createdAt') return scalar(pull.createdAt);
      if (field.name === 'updatedAt') return scalar(pull.updatedAt);
      if (field.name === 'author') return select({ __type: 'User', login: VIEWER.login });
      if (field.name === 'repository') return select({ __type: 'Repository', repo: source.repo });
      if (field.name === 'files') {
        const headTip = source.repo.refs.get(`refs/heads/${pull.headRef}`) ?? pull.headSha;
        const changes = diffCommits(pull.baseSha, headTip);
        const { nodes, pageInfo } = makeConnection(changes, args.first, args.after);
        return select({ __type: 'FileConnection', nodes, pageInfo });
      }
      return unknownField(source, field, ctx, path);
    }
    case 'IssueComment': {
      if (field.name === 'id') return scalar(globalId('IssueComment', source.repo.owner, source.repo.name, source.issue.number, source.comment.id));
      if (field.name === 'body') return scalar(source.comment.body);
      if (field.name === 'createdAt') return scalar(source.comment.createdAt);
      if (field.name === 'updatedAt') return scalar(source.comment.updatedAt);
      if (field.name === 'author') return select({ __type: 'User', login: VIEWER.login });
      return unknownField(source, field, ctx, path);
    }
    case 'Ref': {
      if (field.name === 'name') return scalar(source.name);
      if (field.name === 'prefix') return scalar('refs/heads/');
      return unknownField(source, field, ctx, path);
    }
    case 'IssueConnection': {
      if (field.name === 'nodes') {
        return source.nodes.map((issue) => select({ __type: 'Issue', repo: source.repo, issue }));
      }
      if (field.name === 'edges') {
        return source.nodes.map((issue, index) =>
          select({ __type: 'IssueEdge', repo: source.repo, issue, cursor: encodeCursor(index) }),
        );
      }
      if (field.name === 'pageInfo') return select({ __type: 'PageInfo', pageInfo: source.pageInfo });
      if (field.name === 'totalCount') return scalar(source.nodes.length);
      return unknownField(source, field, ctx, path);
    }
    case 'PullRequestConnection': {
      if (field.name === 'nodes') {
        return source.nodes.map((pull) => select({ __type: 'PullRequest', repo: source.repo, pull }));
      }
      if (field.name === 'edges') {
        return source.nodes.map((pull, index) =>
          select({ __type: 'PullRequestEdge', repo: source.repo, pull, cursor: encodeCursor(index) }),
        );
      }
      if (field.name === 'pageInfo') return select({ __type: 'PageInfo', pageInfo: source.pageInfo });
      if (field.name === 'totalCount') return scalar(source.nodes.length);
      return unknownField(source, field, ctx, path);
    }
    case 'FileConnection': {
      if (field.name === 'nodes') {
        return source.nodes.map((file) => select({ __type: 'FileNode', file }));
      }
      if (field.name === 'edges') {
        return source.nodes.map((file, index) => select({ __type: 'FileEdge', file, cursor: encodeCursor(index) }));
      }
      if (field.name === 'pageInfo') return select({ __type: 'PageInfo', pageInfo: source.pageInfo });
      if (field.name === 'totalCount') return scalar(source.nodes.length);
      return unknownField(source, field, ctx, path);
    }
    case 'PageInfo': {
      if (field.name === 'hasNextPage') return scalar(source.pageInfo.hasNextPage);
      if (field.name === 'hasPreviousPage') return scalar(source.pageInfo.hasPreviousPage);
      if (field.name === 'startCursor') return scalar(source.pageInfo.startCursor);
      if (field.name === 'endCursor') return scalar(source.pageInfo.endCursor);
      return unknownField(source, field, ctx, path);
    }
    case 'IssueEdge': {
      if (field.name === 'node') return select({ __type: 'Issue', repo: source.repo, issue: source.issue });
      if (field.name === 'cursor') return scalar(source.cursor);
      return unknownField(source, field, ctx, path);
    }
    case 'PullRequestEdge': {
      if (field.name === 'node') return select({ __type: 'PullRequest', repo: source.repo, pull: source.pull });
      if (field.name === 'cursor') return scalar(source.cursor);
      return unknownField(source, field, ctx, path);
    }
    case 'FileEdge': {
      if (field.name === 'node') return select({ __type: 'FileNode', file: source.file });
      if (field.name === 'cursor') return scalar(source.cursor);
      return unknownField(source, field, ctx, path);
    }
    case 'FileNode': {
      if (field.name === 'path') return scalar(source.file.filename);
      if (field.name === 'additions') return scalar(source.file.additions);
      if (field.name === 'deletions') return scalar(source.file.deletions);
      if (field.name === 'changeType') return scalar(source.file.status.toUpperCase());
      return unknownField(source, field, ctx, path);
    }
    case '__Type': {
      if (field.name === 'name') return scalar(source.name);
      if (field.name === 'kind') return scalar(source.name === 'SearchType' ? 'ENUM' : 'OBJECT');
      if (field.name === 'fields') {
        const names = INTROSPECTION_FIELDS[source.name] ?? [];
        return names.map((name) => ({ name }));
      }
      if (field.name === 'enumValues') {
        if (source.name !== 'SearchType') return scalar([]);
        return SEARCH_TYPE_VALUES.map((name) => ({ name }));
      }
      if (field.name === 'description') return scalar(null);
      return unknownField(source, field, ctx, path);
    }
    case '__Schema': {
      if (field.name === 'queryType') return { name: 'Query' };
      if (field.name === 'mutationType') return { name: 'Mutation' };
      if (field.name === 'types') {
        return Object.keys(INTROSPECTION_FIELDS).map((name) => ({ name }));
      }
      return unknownField(source, field, ctx, path);
    }
    case 'CreateIssuePayload': {
      if (field.name === 'issue') return select({ __type: 'Issue', repo: source.repo, issue: source.issue });
      return unknownField(source, field, ctx, path);
    }
    case 'CloseIssuePayload': {
      if (field.name === 'issue') return select({ __type: 'Issue', repo: source.repo, issue: source.issue });
      return unknownField(source, field, ctx, path);
    }
    case 'CreatePullRequestPayload': {
      if (field.name === 'pullRequest') return select({ __type: 'PullRequest', repo: source.repo, pull: source.pull });
      return unknownField(source, field, ctx, path);
    }
    case 'MergePullRequestPayload': {
      if (field.name === 'pullRequest') return select({ __type: 'PullRequest', repo: source.repo, pull: source.pull });
      return unknownField(source, field, ctx, path);
    }
    case 'AddCommentPayload': {
      if (field.name === 'commentEdge') {
        return select({ __type: 'CommentEdge', repo: source.repo, issue: source.issue, comment: source.comment });
      }
      if (field.name === 'subject') return select({ __type: 'Issue', repo: source.repo, issue: source.issue });
      return unknownField(source, field, ctx, path);
    }
    case 'CommentEdge': {
      if (field.name === 'node') return select({ __type: 'IssueComment', repo: source.repo, issue: source.issue, comment: source.comment });
      if (field.name === 'cursor') return scalar(encodeCursor(source.comment.id));
      return unknownField(source, field, ctx, path);
    }
  }
}

function executeGqlOperation(query: string, variables: Record<string, unknown>): Record<string, unknown> {
  let parsed: GqlDocument;
  try {
    parsed = new GqlParser(tokenizeGql(query)).parseDocument();
  } catch (err) {
    return { data: null, errors: [{ message: (err as Error).message }] };
  }
  const operation = parsed.operations[0];
  if (operation === undefined) {
    return { data: null, errors: [{ message: 'No operation in document' }] };
  }
  const mergedVariables: Record<string, unknown> = { ...operation.variables, ...variables };
  const ctx: GqlExecContext = { errors: [], fragments: parsed.fragments, variables: mergedVariables };
  const root: GqlSource = operation.kind === 'mutation' ? { __type: 'Mutation' } : { __type: 'Query' };
  const data = executeSelections(root, operation.selections, ctx, []);
  if (ctx.errors.length > 0) return { data, errors: ctx.errors };
  return { data };
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!isAuthed(req)) {
    sendJsonError(res, 401, 'Requires authentication');
    return;
  }
  const raw = await readBody(req);
  let payload: unknown;
  try {
    payload = JSON.parse(raw.toString('utf8'));
  } catch {
    sendJsonError(res, 400, 'Invalid JSON body');
    return;
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    if (!isRecord(entry) || typeof entry.query !== 'string') {
      return { data: null, errors: [{ message: 'A GraphQL operation needs a query string' }] };
    }
    const variables = isRecord(entry.variables) ? entry.variables : {};
    return executeGqlOperation(entry.query, variables);
  };
  if (Array.isArray(payload)) {
    sendJson(res, 200, payload.map(runOne));
    return;
  }
  sendJson(res, 200, runOne(payload));
}

// -------------------------------------------------------------------------------------------
// MCP at POST /mcp: JSON-RPC 2.0 over Streamable HTTP, modern revision 2026-07-28
// (server/discover, no handshake, no session) with the legacy initialize path kept for
// older clients. tools/list is a frozen constant, so two calls answer byte for byte.
// -------------------------------------------------------------------------------------------

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, { type: string; description: string }>;
    required: string[];
    additionalProperties: boolean;
  };
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository for the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        owner: { type: 'string', description: 'The repository owner (defaults to the authenticated user).' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
      additionalProperties: true,
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The repository full name (owner/repo).' },
      },
      required: ['owner', 'repo'],
      additionalProperties: true,
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The repository full name (owner/repo).' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
      additionalProperties: true,
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The repository full name (owner/repo).' },
        state: { type: 'string', description: 'Issue state filter: open, closed or all.' },
      },
      required: ['owner', 'repo'],
      additionalProperties: true,
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The repository full name (owner/repo).' },
        title: { type: 'string', description: 'The pull request title.' },
        body: { type: 'string', description: 'The pull request body.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
      additionalProperties: true,
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash merge.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The repository full name (owner/repo).' },
        pull_number: { type: 'number', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
      additionalProperties: true,
    },
  },
  {
    name: 'get_issue',
    description: 'Get one issue by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The repository full name (owner/repo).' },
        issue_number: { type: 'number', description: 'The issue number.' },
      },
      required: ['owner', 'repo', 'issue_number'],
      additionalProperties: true,
    },
  },
  {
    name: 'list_pull_requests',
    description: 'List pull requests in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The repository full name (owner/repo).' },
        state: { type: 'string', description: 'Pull request state filter: open, closed or all.' },
      },
      required: ['owner', 'repo'],
      additionalProperties: true,
    },
  },
];

/** owner/repo out of a tool's arguments, accepting a full_name fallback. */
function mcpOwnerRepo(args: Record<string, unknown>): { owner: string; repo: string } {
  let owner = typeof args.owner === 'string' ? args.owner : '';
  let repo = typeof args.repo === 'string' ? args.repo : '';
  if ((owner === '' || repo === '') && typeof args.full_name === 'string') {
    const slash = args.full_name.indexOf('/');
    if (slash > 0) {
      owner = owner === '' ? args.full_name.slice(0, slash) : owner;
      repo = repo === '' ? args.full_name.slice(slash + 1) : repo;
    }
  }
  return { owner, repo };
}

function mcpToolResult(result: unknown): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: JSON.stringify(result) }],
    structuredContent: result,
    isError: false,
  };
}
function mcpToolError(message: string): Record<string, unknown> {
  return {
    content: [{ type: 'text', text: message }],
    structuredContent: { error: message },
    isError: true,
  };
}

function mcpCallTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const missing = (field: string): Record<string, unknown> => mcpToolError(`Missing required argument: ${field}`);
  switch (name) {
    case 'create_repo': {
      if (typeof args.name !== 'string' || args.name === '') return missing('name');
      const owner = typeof args.owner === 'string' && args.owner !== '' ? args.owner : VIEWER.login;
      if (repos.has(repoKey(owner, args.name))) {
        return mcpToolError(`A repository named ${owner}/${args.name} already exists`);
      }
      const stamp = nowIso();
      const repo: Repo = {
        id: nextRepoId++,
        name: args.name,
        owner,
        private: args.private === true,
        description: typeof args.description === 'string' ? args.description : '',
        defaultBranch: 'main',
        createdAt: stamp,
        updatedAt: stamp,
        refs: new Map(),
        issues: [],
        nextIssueNumber: 1,
        pulls: [],
        nextPullNumber: 1,
        labels: new Map(),
        order: repoOrderSeq++,
      };
      repos.set(repoKey(owner, args.name), repo);
      return mcpToolResult(repoView(repo));
    }
    case 'get_repo': {
      const { owner, repo: repoName } = mcpOwnerRepo(args);
      if (owner === '' || repoName === '') return missing('owner/repo');
      const repo = findRepo(owner, repoName);
      if (repo === undefined) return mcpToolError(`Repository ${owner}/${repoName} not found`);
      return mcpToolResult(repoView(repo));
    }
    case 'create_issue': {
      const { owner, repo: repoName } = mcpOwnerRepo(args);
      if (owner === '' || repoName === '') return missing('owner/repo');
      if (typeof args.title !== 'string' || args.title === '') return missing('title');
      const repo = findRepo(owner, repoName);
      if (repo === undefined) return mcpToolError(`Repository ${owner}/${repoName} not found`);
      const stamp = nowIso();
      const issue: Issue = {
        id: nextObjectId++,
        number: repo.nextIssueNumber++,
        title: args.title,
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        labels: [],
        comments: [],
        createdAt: stamp,
        updatedAt: stamp,
      };
      repo.issues.push(issue);
      repo.updatedAt = stamp;
      return mcpToolResult(issueView(repo, issue));
    }
    case 'list_issues': {
      const { owner, repo: repoName } = mcpOwnerRepo(args);
      if (owner === '' || repoName === '') return missing('owner/repo');
      const repo = findRepo(owner, repoName);
      if (repo === undefined) return mcpToolError(`Repository ${owner}/${repoName} not found`);
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = repo.issues.filter((issue) => state === 'all' || issue.state === state);
      return mcpToolResult({ issues: list.map((issue) => issueView(repo, issue)) });
    }
    case 'create_pull_request': {
      const { owner, repo: repoName } = mcpOwnerRepo(args);
      if (owner === '' || repoName === '') return missing('owner/repo');
      if (typeof args.title !== 'string' || args.title === '') return missing('title');
      if (typeof args.head !== 'string' || args.head === '') return missing('head');
      if (typeof args.base !== 'string' || args.base === '') return missing('base');
      const repo = findRepo(owner, repoName);
      if (repo === undefined) return mcpToolError(`Repository ${owner}/${repoName} not found`);
      const headTip = repo.refs.get(`refs/heads/${args.head}`);
      const baseTip = repo.refs.get(`refs/heads/${args.base}`);
      if (headTip === undefined || baseTip === undefined) {
        return mcpToolError('head or base branch does not exist');
      }
      const duplicate = repo.pulls.find((pull) => pull.state === 'open' && pull.headRef === args.head && pull.baseRef === args.base);
      if (duplicate !== undefined) return mcpToolError('A pull request already exists for this head and base');
      const stamp = nowIso();
      const pull: Pull = {
        id: nextObjectId++,
        number: repo.nextPullNumber++,
        title: args.title,
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        headRef: args.head,
        baseRef: args.base,
        headSha: headTip,
        baseSha: baseTip,
        createdAt: stamp,
        updatedAt: stamp,
      };
      repo.pulls.push(pull);
      repo.updatedAt = stamp;
      return mcpToolResult(pullView(repo, pull));
    }
    case 'merge_pull_request': {
      const { owner, repo: repoName } = mcpOwnerRepo(args);
      if (owner === '' || repoName === '') return missing('owner/repo');
      if (typeof args.pull_number !== 'number') return missing('pull_number');
      const repo = findRepo(owner, repoName);
      if (repo === undefined) return mcpToolError(`Repository ${owner}/${repoName} not found`);
      const pull = repo.pulls.find((entry) => entry.number === args.pull_number);
      if (pull === undefined) return mcpToolError(`Pull request #${args.pull_number} not found`);
      if (pull.merged) return mcpToolError('Pull request is already merged');
      const mergeSha = squashMerge(repo, pull);
      if (mergeSha === null) return mcpToolError('Merge conflict');
      return mcpToolResult({ merged: true, sha: mergeSha, message: 'Pull request successfully merged' });
    }
    case 'get_issue': {
      const { owner, repo: repoName } = mcpOwnerRepo(args);
      if (owner === '' || repoName === '') return missing('owner/repo');
      if (typeof args.issue_number !== 'number') return missing('issue_number');
      const repo = findRepo(owner, repoName);
      if (repo === undefined) return mcpToolError(`Repository ${owner}/${repoName} not found`);
      const issue = repo.issues.find((entry) => entry.number === args.issue_number);
      if (issue === undefined) return mcpToolError(`Issue #${args.issue_number} not found`);
      return mcpToolResult(issueView(repo, issue));
    }
    case 'list_pull_requests': {
      const { owner, repo: repoName } = mcpOwnerRepo(args);
      if (owner === '' || repoName === '') return missing('owner/repo');
      const repo = findRepo(owner, repoName);
      if (repo === undefined) return mcpToolError(`Repository ${owner}/${repoName} not found`);
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = repo.pulls.filter((pull) => state === 'all' || pull.state === state);
      return mcpToolResult({ pull_requests: list.map((pull) => pullView(repo, pull)) });
    }
    default:
      return mcpToolError(`Unknown tool: ${name}`);
  }
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!isAuthed(req)) {
    sendJsonError(res, 401, 'Requires authentication');
    return;
  }
  if (req.method !== 'POST') {
    sendJsonError(res, 405, 'Method not allowed');
    return;
  }
  const raw = await readBody(req);
  let payload: unknown;
  try {
    payload = JSON.parse(raw.toString('utf8'));
  } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (!isRecord(payload) || typeof payload.method !== 'string') {
    sendJson(res, 400, {
      jsonrpc: '2.0',
      id: isRecord(payload) && 'id' in payload ? payload.id : null,
      error: { code: -32600, message: 'Invalid Request' },
    });
    return;
  }
  const id = 'id' in payload ? payload.id : undefined;
  const params = isRecord(payload.params) ? payload.params : {};
  // Notifications carry no id and are answered with 202 and an empty body.
  if (id === undefined) {
    sendNoContent(res, 202);
    return;
  }
  const reply = (result: unknown): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, result });
  };
  const replyError = (code: number, message: string): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, error: { code, message } });
  };
  switch (payload.method) {
    case 'server/discover': {
      reply({
        resultType: 'server/discover',
        supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18'],
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: '1.0.0' },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'forge', version: '1.0.0' } },
      });
      return;
    }
    case 'initialize': {
      reply({
        protocolVersion: '2026-07-28',
        capabilities: { tools: {} },
        serverInfo: { name: 'forge', version: '1.0.0' },
      });
      return;
    }
    case 'tools/list': {
      reply({ tools: MCP_TOOLS });
      return;
    }
    case 'tools/call': {
      const name = typeof params.name === 'string' ? params.name : '';
      const args = isRecord(params.arguments) ? params.arguments : {};
      const found = MCP_TOOLS.some((tool) => tool.name === name);
      if (!found) {
        replyError(-32602, `Unknown tool: ${name}`);
        return;
      }
      reply(mcpCallTool(name, args));
      return;
    }
    case 'ping': {
      reply({});
      return;
    }
    default: {
      replyError(-32601, `Method not found: ${payload.method}`);
      return;
    }
  }
}

// -------------------------------------------------------------------------------------------
// HTTP router.
// -------------------------------------------------------------------------------------------

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://entry');
  const pathname = url.pathname;
  const segments = pathname.split('/').filter((segment) => segment !== '');

  if (pathname === '/healthz') {
    sendJson(res, 200, { status: 'ok' });
    return;
  }
  if (pathname === '/mcp') {
    await handleMcp(req, res);
    return;
  }
  if (pathname === '/api/graphql') {
    if (req.method !== 'POST') {
      sendJsonError(res, 404, 'Not Found');
      return;
    }
    await handleGraphql(req, res);
    return;
  }
  if (segments[0] === 'api' && segments[1] === 'v3') {
    await handleRest(req, res, segments.slice(2), url.searchParams);
    return;
  }
  if (segments.length >= 2 && segments[1]?.endsWith('.git')) {
    await handleGit(req, res, segments, url.searchParams);
    return;
  }
  sendJsonError(res, 404, 'Not Found');
}

export function createApp(): Server {
  const server = createServer((req: IncomingMessage, res: ServerResponse): void => {
    void handleRequest(req, res).catch((err: unknown) => {
      console.error(err);
      if (!res.headersSent) sendJsonError(res, 500, 'Internal server error');
    });
  });
  return server;
}
