// The whs command. Every subcommand is a composition of the same parts: a repository config,
// a surface, the checks in the registry, canaries, and findings.
import { resolve } from 'node:path';
import { prepareAudit } from './audit.mjs';
import { runCanaries } from './canary.mjs';
import { emptyConfig, loadConfigAtCommit, loadConfigFile } from './config.mjs';
import { blocks, finish, place } from './findings.mjs';
import { resolveFragments, sourcePins } from './fragments.mjs';
import { installPins, toolPin } from './pins.mjs';
import { loadRegistry } from './registry.mjs';
import { gateChange, scan } from './scan.mjs';
import { commitTree, commits, requireCommit, tempDir } from './surface.mjs';
import { UsageError, parseArgs } from './util.mjs';

const USAGE = `whs: InStrand's security scanning pack

  whs install                              install every pin, each verified: the scanners and the audit process
  whs canary                               prove every check against its known cases
  whs gate <repo> --base <ref> --head <ref> [--config <file>] [--out <dir>]
                                           judge a change: only what it adds can stop it
  whs scan <repo> [--ref <ref>] [--history] [--config <file>] [--out <dir>]
                                           scan one commit's files, or every commit with --history
  whs fragments <repo> [--ref <ref>]       which knowledge sources and fragments an audit would use
  whs audit prepare <repo> --config <file> [--ref <ref>] [--runs <dir>]
                                           build the surface and the deterministic inputs for a deep audit

Exit codes: 0 pass, 1 findings, 2 a check or the command failed.`;

const exitCode = (summary) => ({ pass: 0, findings: 1, error: 2 })[summary.outcome];

/** Everything `whs install` installs: the scanners and the sources that are fetched. Nothing else fetches. */
export const allPins = (registry) => [...Object.entries(registry.tools).map(([name, tool]) => toolPin(name, tool)), ...sourcePins()];

function printSummary({ summary, findings }, log = console.log) {
  for (const check of summary.checks) {
    const detail = check.status === 'ran'
      ? `${check.blocking} blocking, ${check.unchanged} unchanged, ${check.excepted} excepted`
      : check.status === 'error' ? check.error : 'no matching files';
    log(`${check.check.padEnd(10)} ${check.surface.padEnd(8)} ${check.status.padEnd(15)} ${detail}`);
  }
  for (const finding of findings.filter(blocks)) {
    log(`  ${finding.check}/${finding.rule}  ${place(finding)}\n    ${finding.message.slice(0, 220)}`);
  }
  if (summary.expired_exceptions > 0) log(`${summary.expired_exceptions} exception(s) have expired and no longer apply`);
  log(`outcome: ${summary.outcome}`);
}

function scanCommand(registry, repoArg, options) {
  const repo = resolve(repoArg);
  const commit = requireCommit(repo, options.ref ?? 'HEAD');
  const outDir = resolve(options.out ?? tempDir('out'));
  const config = options.config ? loadConfigFile(resolve(options.config)) : loadConfigAtCommit(repo, commit) ?? emptyConfig();
  const target = options.history ? commits(repo, '--all') : commitTree(repo, commit);
  const outcome = finish(scan(registry, target, config.data_paths), config, outDir, { operation: 'scan', commit, surface: target.kind });
  printSummary(outcome);
  console.log(`report: ${outDir}/scan.sarif`);
  return exitCode(outcome.summary);
}

function gate(registry, repoArg, options) {
  if (!options.head) throw new UsageError('gate needs --head <ref> and, for anything but a first push, --base <ref>');
  const outDir = resolve(options.out ?? tempDir('out'));
  const outcome = gateChange(registry, resolve(repoArg), options.base, options.head, outDir, options.config && resolve(options.config));
  const { base, head } = outcome.summary;
  console.log(base ? `change ${base.slice(0, 12)}..${head.slice(0, 12)}` : `first push ${head.slice(0, 12)}: no base revision, every finding counts`);
  printSummary(outcome);
  console.log(`report: ${outDir}/scan.sarif`);
  return exitCode(outcome.summary);
}

export async function main(argv) {
  try {
    const [command, ...rest] = argv;
    if (!command || command === 'help' || command === '--help') {
      console.log(USAGE);
      return command ? 0 : 2;
    }
    const registry = loadRegistry();
    if (command === 'install') {
      await installPins(allPins(registry));
      return 0;
    }
    if (command === 'canary') return runCanaries(registry) === 0 ? 0 : 1;
    if (command === 'gate') {
      const { options, positional } = parseArgs(rest, { base: 'value', head: 'value', config: 'value', out: 'value' });
      if (positional.length !== 1) throw new UsageError('gate needs one repository path');
      return gate(registry, positional[0], options);
    }
    if (command === 'scan') {
      const { options, positional } = parseArgs(rest, { ref: 'value', history: 'flag', config: 'value', out: 'value' });
      if (positional.length !== 1) throw new UsageError('scan needs one repository path');
      return scanCommand(registry, positional[0], options);
    }
    if (command === 'fragments') {
      const { options, positional } = parseArgs(rest, { ref: 'value' });
      if (positional.length !== 1) throw new UsageError('fragments needs one repository path');
      console.log(JSON.stringify(resolveFragments(resolve(positional[0]), options.ref ?? 'HEAD'), null, 2));
      return 0;
    }
    if (command === 'audit' && rest[0] === 'prepare') {
      const { options, positional } = parseArgs(rest.slice(1), { config: 'value', ref: 'value', runs: 'value' });
      if (positional.length !== 1) throw new UsageError('audit prepare needs one repository path');
      return prepareAudit(registry, resolve(positional[0]), options);
    }
    throw new UsageError(`unknown command "${argv.join(' ')}"\n\n${USAGE}`);
  } catch (error) {
    if (error instanceof UsageError) {
      console.error(`whs: ${error.message}`);
      return 2;
    }
    throw error;
  }
}
