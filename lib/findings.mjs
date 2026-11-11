// Findings: one shape and one identity for whatever a check reports.
//
// Every tool writes SARIF 2.1.0, but none gives an identity that survives an unrelated edit, so
// the pack computes one. Comparing two sets of findings by that identity is the single operation
// behind both "did this change add a finding?" (base against head) and, later, "is this finding
// gone from what is deployed?" (the last record against a new scan).
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { applyExceptions } from './config.mjs';
import { matchesAny, sha256 } from './util.mjs';

export const FINGERPRINT_KEY = 'whs/v1';

/**
 * The path a tool reported, as written. The pinned tools write plain paths relative to what they
 * scanned and do not percent-encode them, so nothing is decoded: decoding would turn a file
 * named "fixtures%2Fx.sql" into "fixtures/x.sql", a path that an exception for fixtures/ covers.
 */
const reportedPath = (uri) => String(uri ?? '').replace(/^\.\//, '');

/**
 * The flagged lines with indentation and runs of spaces removed, so reformatting keeps the
 * identity. A finding at a path that is not a file of the surface cannot be identified, and that
 * is a failure of the check, never a reason to fall back to the line number.
 */
function flaggedText(surface, path, startLine, endLine) {
  if (!surface.files.includes(path)) throw new Error(`a finding is at "${path}", which is not a file of the surface`);
  const lines = readFileSync(join(surface.dir, path), 'utf8').split('\n').slice(startLine - 1, endLine);
  return lines.map((line) => line.trim().replace(/\s+/g, ' ')).join('\n');
}

/**
 * Reads what a tool wrote as a SARIF log in the pack's naming. A tool that wrote anything but
 * runs that each hold a list of results has not reported, and the caller treats that as a
 * failure. Rule ids lose the prefix the tool adds (rule_id_strip; for Semgrep the prefix is the
 * path of the rules directory on this machine), in the results and in the tool's rule list, so
 * the record names a rule the same way on every machine and holds no local path.
 */
export function readSarif(text, check) {
  const log = JSON.parse(text);
  if (!Array.isArray(log?.runs) || log.runs.length === 0 || !log.runs.every((run) => Array.isArray(run?.results))) {
    throw new Error('expected runs that each hold a list of results');
  }
  if (!check.rule_id_strip) return log;
  const strip = new RegExp(check.rule_id_strip);
  const inJson = (value) => JSON.stringify(value).slice(1, -1);
  for (const run of log.runs) {
    for (const result of run.results) result.ruleId = String(result.ruleId).replace(strip, '');
    const rules = run.tool?.driver?.rules ?? [];
    for (const [index, rule] of rules.entries()) {
      // The raw id also appears in a rule's name and descriptions; it is replaced wherever the rule holds it.
      rules[index] = JSON.parse(JSON.stringify(rule).replaceAll(inJson(rule.id), () => inJson(String(rule.id).replace(strip, ''))));
    }
  }
  return log;
}

/**
 * Reads one check's SARIF log into findings.
 * Identity for a tree: check, rule, path and the flagged text, never the line number.
 * Identity for commits, and for a result with no file: check, rule, path, commit and line,
 * because history does not move.
 */
export function findingsFromSarif(log, check, surface) {
  const findings = [];
  for (const run of log.runs) {
    for (const result of run.results) {
      const location = result.locations?.[0]?.physicalLocation ?? {};
      const path = reportedPath(location.artifactLocation?.uri);
      const startLine = location.region?.startLine ?? 1;
      const endLine = location.region?.endLine ?? startLine;
      const rule = String(result.ruleId);
      const commit = result.partialFingerprints?.commitSha ?? null;
      const text = surface.kind === 'tree' && path !== '' ? flaggedText(surface, path, startLine, endLine) : null;
      const identity = text === null ? [check.id, rule, path, commit ?? '', String(startLine)] : [check.id, rule, path, text];
      findings.push({
        check: check.id,
        rule,
        path,
        startLine,
        endLine,
        commit,
        message: String(result.message?.text ?? '').replace(/\s+/g, ' ').trim(),
        fingerprint: sha256(identity.join('\u0000')),
        state: null,
        exception: null,
        result,
      });
    }
  }
  return findings;
}

/** The rule ids a tool loaded, in the pack's naming. */
export const loadedRules = (log) => log.runs.flatMap((run) => (run.tool?.driver?.rules ?? []).map((rule) => rule.id));

/**
 * Compares two sets of findings by fingerprint, counting repeats. Marks each head finding
 * "new" or "unchanged" and returns the base findings that are no longer present.
 */
export function compareFindings(base, head) {
  const remaining = new Map();
  for (const finding of base) remaining.set(finding.fingerprint, (remaining.get(finding.fingerprint) ?? 0) + 1);
  for (const finding of head) {
    const count = remaining.get(finding.fingerprint) ?? 0;
    finding.state = count > 0 ? 'unchanged' : 'new';
    if (count > 0) remaining.set(finding.fingerprint, count - 1);
  }
  const absent = [];
  for (const finding of base) {
    const count = remaining.get(finding.fingerprint) ?? 0;
    if (count > 0) {
      absent.push({ ...finding, state: 'absent' });
      remaining.set(finding.fingerprint, count - 1);
    }
  }
  return { absent };
}

/** A finding stops a change when it is new (or was never compared) and nobody accepted it. */
export const blocks = (finding) => finding.exception === null && finding.state !== 'unchanged';

/** Where a finding is, for a person: path and line, and the commit for a finding in history. */
export const place = (finding) => `${finding.path}:${finding.startLine}${finding.commit ? ` @ ${finding.commit.slice(0, 12)}` : ''}`;

/**
 * A result as a reader who must not see the file may have it: rule, message, path, lines and
 * commit. Everything else a tool attaches (snippets, code flows, fixes, its own properties) may
 * quote the file, so the result is rebuilt from the fields that are kept, never trimmed.
 */
function withoutText({ ruleId, level, kind, message, locations = [], partialFingerprints }) {
  const position = ({ startLine, endLine, startColumn, endColumn } = {}) => ({ startLine, endLine, startColumn, endColumn });
  return {
    ruleId,
    level,
    kind,
    message,
    locations: locations.map(({ physicalLocation = {} }) => ({
      physicalLocation: { artifactLocation: { uri: physicalLocation.artifactLocation?.uri }, region: position(physicalLocation.region) },
    })),
    partialFingerprints,
  };
}

/**
 * One SARIF log for the whole scan: each tool's own run, with identity, state and exceptions
 * added. `hidden` lists the paths whose text the reader of this log must not see. The text is
 * left out here, before anything is written, so no file ever holds it.
 */
export function toSarif(checkResults, hidden = []) {
  const runs = [];
  for (const { log, findings } of checkResults) {
    if (!log) continue;
    const byResult = new Map(findings.map((finding) => [finding.result, finding]));
    for (const run of log.runs) {
      runs.push({
        ...run,
        results: run.results.map((result) => {
          const finding = byResult.get(result);
          const out = {
            ...(matchesAny(hidden, finding.path) ? withoutText(result) : result),
            partialFingerprints: { ...(result.partialFingerprints ?? {}), [FINGERPRINT_KEY]: finding.fingerprint },
          };
          if (finding.state === 'new' || finding.state === 'unchanged') out.baselineState = finding.state;
          if (finding.exception) {
            out.suppressions = [{ kind: 'external', justification: `${finding.exception.reason} (owner: ${finding.exception.owner})` }];
          }
          return out;
        }),
      });
    }
  }
  return { $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs };
}

/**
 * Applies exceptions, writes scan.sarif and summary.json, and decides the outcome. These two
 * files are everything the pack keeps of a scan. `hidden` is passed on to toSarif.
 */
export function finish(results, config, outDir, meta, hidden = []) {
  const findings = results.flatMap((result) => result.findings);
  const { expired } = applyExceptions(findings, config);
  const summary = {
    ...meta,
    expired_exceptions: expired,
    checks: results.map((result) => ({
      check: result.check,
      surface: result.surface,
      status: result.status,
      version: result.version ?? null,
      error: result.error ?? null,
      findings: result.findings.length,
      blocking: result.findings.filter(blocks).length,
      unchanged: result.findings.filter((finding) => finding.state === 'unchanged' && !finding.exception).length,
      excepted: result.findings.filter((finding) => finding.exception).length,
    })),
  };
  summary.errors = summary.checks.filter((check) => check.status === 'error').length;
  summary.blocking = summary.checks.reduce((total, check) => total + check.blocking, 0);
  summary.outcome = summary.errors > 0 ? 'error' : summary.blocking > 0 ? 'findings' : 'pass';
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'scan.sarif'), `${JSON.stringify(toSarif(results, hidden), null, 2)}\n`);
  writeFileSync(join(outDir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  return { summary, findings, results };
}
