#!/usr/bin/env node
// Generate the five npm platform packages for `trishul-cli` from a goreleaser
// build, using the esbuild-style optionalDependencies pattern.
//
// For each supported platform it writes:
//   <out>/<pkg>/package.json      (name/version/os/cpu, no bin field)
//   <out>/<pkg>/bin/<trishul[.exe]>   (the platform binary, chmod 0755)
//
// It also stamps the matching version into the ROOT package
// (packages/npm/package.json): the package `version` and every
// optionalDependencies value, so a subsequent `npm publish` is coherent.
//
// Binaries are located via goreleaser's `dist/artifacts.json` (robust against
// goreleaser's per-arch directory suffixes like `_amd64_v1`). The version is
// taken from --version, then $TRISHUL_VERSION / $GITHUB_REF_NAME, then
// `dist/metadata.json`, then the root package.json (if not a placeholder).
//
// Idempotent: the output directory is rebuilt from scratch on every run.
//
// Usage:
//   node scripts/npm/build-packages.mjs [--dist dist] [--out packages/npm/dist-platform]
//                                       [--version X.Y.Z] [--no-sync-root]
//   node scripts/npm/build-packages.mjs --help

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..", "..");
const ROOT_PKG = path.join(REPO_ROOT, "packages", "npm", "package.json");

const TARGETS = [
  { pkg: "trishul-cli-darwin-arm64", os: ["darwin"], cpu: ["arm64"], goos: "darwin", goarch: "arm64", bin: "trishul" },
  { pkg: "trishul-cli-darwin-x64", os: ["darwin"], cpu: ["x64"], goos: "darwin", goarch: "amd64", bin: "trishul" },
  { pkg: "trishul-cli-linux-x64", os: ["linux"], cpu: ["x64"], goos: "linux", goarch: "amd64", bin: "trishul" },
  { pkg: "trishul-cli-linux-arm64", os: ["linux"], cpu: ["arm64"], goos: "linux", goarch: "arm64", bin: "trishul" },
  { pkg: "trishul-cli-win32-x64", os: ["win32"], cpu: ["x64"], goos: "windows", goarch: "amd64", bin: "trishul.exe" },
];

const PLACEHOLDER = "0.0.0-placeholder";

function parseArgs(argv) {
  const out = { dist: "dist", out: "packages/npm/dist-platform", version: null, syncRoot: true, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--dist") out.dist = argv[++i];
    else if (a === "--out") out.out = argv[++i];
    else if (a === "--version") out.version = argv[++i];
    else if (a === "--no-sync-root") out.syncRoot = false;
    else if (a.startsWith("--dist=")) out.dist = a.slice(7);
    else if (a.startsWith("--out=")) out.out = a.slice(6);
    else if (a.startsWith("--version=")) out.version = a.slice(10);
    else {
      console.error(`unknown argument: ${a}`);
      process.exit(2);
    }
  }
  return out;
}

const HELP = `build-packages.mjs — generate trishul-cli npm platform packages

Usage:
  node scripts/npm/build-packages.mjs [options]

Options:
  --dist <dir>       goreleaser dist directory (default: dist)
  --out <dir>        output directory for platform packages
                     (default: packages/npm/dist-platform)
  --version <X.Y.Z>  version to stamp (default: env/metadata/package.json)
  --no-sync-root     do not rewrite packages/npm/package.json version + deps
  -h, --help         show this help

Generates these packages (each with bin/ holding the platform binary):
${TARGETS.map((t) => `  - ${t.pkg} (${t.goos}/${t.goarch})`).join("\n")}
`;

function stripV(v) {
  return v && v.startsWith("v") ? v.slice(1) : v;
}

function resolveVersion(args, distDir) {
  if (args.version) return stripV(args.version);
  if (process.env.TRISHUL_VERSION) return stripV(process.env.TRISHUL_VERSION);
  if (process.env.GITHUB_REF_NAME) return stripV(process.env.GITHUB_REF_NAME);
  const metaPath = path.join(distDir, "metadata.json");
  if (fs.existsSync(metaPath)) {
    try {
      const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
      if (meta.version) return stripV(meta.version);
      if (meta.tag) return stripV(meta.tag);
    } catch {
      /* ignore */
    }
  }
  const rootPkg = JSON.parse(fs.readFileSync(ROOT_PKG, "utf8"));
  if (rootPkg.version && rootPkg.version !== PLACEHOLDER) return stripV(rootPkg.version);
  throw new Error(
    "could not determine version; pass --version, set TRISHUL_VERSION/GITHUB_REF_NAME, or provide dist/metadata.json"
  );
}

// Find the trishul-cli Binary for a goos/goarch in dist/artifacts.json.
function findBinary(artifacts, goos, goarch) {
  const matches = artifacts.filter(
    (a) =>
      a.type === "Binary" &&
      a.goos === goos &&
      a.goarch === goarch &&
      ((a.extra && a.extra.ID === "trishul-cli") || a.name === "trishul" || a.name === "trishul.exe")
  );
  // Prefer the trishul-cli ID when present.
  const byId = matches.filter((a) => a.extra && a.extra.ID === "trishul-cli");
  const chosen = (byId.length ? byId : matches)[0];
  return chosen ? path.isAbsolute(chosen.path) ? chosen.path : path.join(REPO_ROOT, chosen.path) : null;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(HELP);
    return;
  }

  const distDir = path.resolve(REPO_ROOT, args.dist);
  const outDir = path.resolve(REPO_ROOT, args.out);
  const artifactsPath = path.join(distDir, "artifacts.json");

  if (!fs.existsSync(artifactsPath)) {
    throw new Error(
      `missing ${artifactsPath}. Run a goreleaser build first (e.g. "goreleaser build --snapshot --clean" or "goreleaser release").`
    );
  }

  const version = resolveVersion(args, distDir);
  const artifacts = JSON.parse(fs.readFileSync(artifactsPath, "utf8"));

  // Rebuild output dir from scratch (idempotent).
  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });

  const built = [];
  for (const t of TARGETS) {
    const srcBin = findBinary(artifacts, t.goos, t.goarch);
    if (!srcBin || !fs.existsSync(srcBin)) {
      throw new Error(`no trishul-cli binary found in dist for ${t.goos}/${t.goarch} (looked via artifacts.json)`);
    }

    const pkgDir = path.join(outDir, t.pkg);
    const binDir = path.join(pkgDir, "bin");
    fs.mkdirSync(binDir, { recursive: true });

    const pkgJson = {
      name: t.pkg,
      version,
      description: `trishul CLI prebuilt binary for ${t.os[0]}/${t.cpu[0]}.`,
      license: "MIT",
      homepage: "https://trishul.dev",
      repository: { type: "git", url: "git+https://github.com/Armur-Ai/Trishul.git" },
      os: t.os,
      cpu: t.cpu,
      files: ["bin/"],
    };
    fs.writeFileSync(path.join(pkgDir, "package.json"), JSON.stringify(pkgJson, null, 2) + "\n");

    const destBin = path.join(binDir, t.bin);
    fs.copyFileSync(srcBin, destBin);
    fs.chmodSync(destBin, 0o755);

    built.push({ pkg: t.pkg, bin: destBin });
    console.log(`built ${t.pkg}@${version} (${t.goos}/${t.goarch}) <- ${path.relative(REPO_ROOT, srcBin)}`);
  }

  if (args.syncRoot) {
    const rootPkg = JSON.parse(fs.readFileSync(ROOT_PKG, "utf8"));
    rootPkg.version = version;
    rootPkg.optionalDependencies = rootPkg.optionalDependencies || {};
    for (const t of TARGETS) rootPkg.optionalDependencies[t.pkg] = version;
    fs.writeFileSync(ROOT_PKG, JSON.stringify(rootPkg, null, 2) + "\n");
    console.log(`synced ${path.relative(REPO_ROOT, ROOT_PKG)} to version ${version}`);
  }

  console.log(`\nDone: ${built.length} platform packages in ${path.relative(REPO_ROOT, outDir)}`);
}

try {
  main();
} catch (err) {
  console.error(`build-packages: ${err.message}`);
  process.exit(1);
}
