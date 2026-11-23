#!/usr/bin/env node
"use strict";

// trishul-cli launcher.
//
// Normal path: the matching platform package (an optionalDependency such as
// `trishul-cli-darwin-arm64`) was installed by npm because its `os`/`cpu`
// fields matched this machine. We resolve its bundled binary and exec it.
// No download, no postinstall.
//
// Fallback path (only if no platform package resolved — e.g. the install ran
// with --no-optional, or on an unusual registry mirror): download the matching
// archive from the GitHub release, verify its SHA-256 against the release's
// `checksums.txt`, then extract and run. This path FAILS CLOSED: any download
// error or checksum mismatch exits non-zero with a clear message and never
// runs an unverified binary.
//
// Pure Node stdlib only — no runtime dependencies.

const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const https = require("https");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

const REPO = "Armur-Ai/Trishul";
const pkg = require("../package.json");
const VERSION = pkg.version;

// key -> npm platform package name
const PLATFORM_PACKAGES = {
  "darwin arm64": "trishul-cli-darwin-arm64",
  "darwin x64": "trishul-cli-darwin-x64",
  "linux x64": "trishul-cli-linux-x64",
  "linux arm64": "trishul-cli-linux-arm64",
  "win32 x64": "trishul-cli-win32-x64",
};

// key -> goreleaser archive descriptor (os/arch/ext as produced by .goreleaser.yml)
const RELEASE_TARGETS = {
  "darwin arm64": { os: "darwin", arch: "arm64", ext: "tar.gz" },
  "darwin x64": { os: "darwin", arch: "amd64", ext: "tar.gz" },
  "linux x64": { os: "linux", arch: "amd64", ext: "tar.gz" },
  "linux arm64": { os: "linux", arch: "arm64", ext: "tar.gz" },
  "win32 x64": { os: "windows", arch: "amd64", ext: "zip" },
};

const KEY = `${process.platform} ${process.arch}`;
const BIN_NAME = process.platform === "win32" ? "trishul.exe" : "trishul";

function fail(msg) {
  console.error(`trishul-cli: ${msg}`);
  process.exit(1);
}

function unsupported() {
  fail(
    `unsupported platform ${process.platform}/${process.arch}.\n` +
      `Supported: ${Object.keys(PLATFORM_PACKAGES).join(", ")}.\n` +
      `Install manually from https://github.com/${REPO}/releases`
  );
}

function run(binPath) {
  const res = spawnSync(binPath, process.argv.slice(2), { stdio: "inherit" });
  if (res.error) {
    if (res.error.code === "ENOENT") {
      fail(`binary not found at ${binPath}`);
    }
    fail(`failed to execute binary: ${res.error.message}`);
  }
  // Propagate the child's exit code, or 128+signal on a signal.
  if (res.signal) {
    process.exit(1);
  }
  process.exit(res.status == null ? 1 : res.status);
}

// 1) Normal path: resolve the platform package's bundled binary.
function resolvePlatformBinary() {
  const platformPkg = PLATFORM_PACKAGES[KEY];
  if (!platformPkg) return null;
  try {
    // require.resolve returns the absolute path to the file if it exists on
    // the resolution paths, even though it is not a JS module.
    return require.resolve(`${platformPkg}/bin/${BIN_NAME}`);
  } catch (_) {
    return null;
  }
}

// --- Fallback: download + verify + extract ------------------------------

function httpGet(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 10) return reject(new Error("too many redirects"));
    https
      .get(url, { headers: { "User-Agent": "trishul-cli-launcher" } }, (res) => {
        const code = res.statusCode || 0;
        if (code >= 300 && code < 400 && res.headers.location) {
          res.resume();
          const next = new URL(res.headers.location, url).toString();
          resolve(httpGet(next, redirects + 1));
          return;
        }
        if (code !== 200) {
          res.resume();
          reject(new Error(`HTTP ${code} for ${url}`));
          return;
        }
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

// Parse `checksums.txt` ("<sha256>  <filename>" per line) into a map.
function parseChecksums(text) {
  const map = Object.create(null);
  for (const line of text.split(/\r?\n/)) {
    const m = line.trim().match(/^([0-9a-fA-F]{64})\s+\*?(.+)$/);
    if (m) map[m[2].trim()] = m[1].toLowerCase();
  }
  return map;
}

// Minimal tar (ustar) reader over a gunzipped buffer; returns the target file.
function extractFromTarGz(gzBuf, targetName) {
  const tar = zlib.gunzipSync(gzBuf);
  let off = 0;
  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512);
    const name = header.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    if (name === "") break; // end-of-archive marker
    const sizeStr = header
      .subarray(124, 136)
      .toString("utf8")
      .replace(/\0.*$/, "")
      .trim();
    const size = parseInt(sizeStr, 8) || 0;
    const typeflag = String.fromCharCode(header[156]);
    off += 512;
    const data = tar.subarray(off, off + size);
    off += Math.ceil(size / 512) * 512;
    const isFile = typeflag === "0" || typeflag === "\0" || typeflag === "";
    if (isFile && path.basename(name) === targetName) {
      return Buffer.from(data);
    }
  }
  return null;
}

// Minimal ZIP reader via the central directory; returns the target file.
function extractFromZip(buf, targetName) {
  const EOCD_SIG = 0x06054b50;
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return null;
  const total = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < total; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) break; // central dir header
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString("utf8");
    p += 46 + nameLen + extraLen + commentLen;
    if (path.basename(name) !== targetName) continue;
    if (buf.readUInt32LE(localOffset) !== 0x04034b50) return null; // local header
    const lNameLen = buf.readUInt16LE(localOffset + 26);
    const lExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + lNameLen + lExtraLen;
    const comp = buf.subarray(dataStart, dataStart + compSize);
    if (method === 0) return Buffer.from(comp);
    if (method === 8) return zlib.inflateRawSync(comp);
    return null; // unsupported compression method
  }
  return null;
}

function cacheDir() {
  const base = os.homedir() || os.tmpdir();
  return path.join(base, ".cache", "trishul-cli", VERSION);
}

async function downloadVerifyExtract() {
  const target = RELEASE_TARGETS[KEY];
  if (!target) unsupported();

  const dir = cacheDir();
  const binPath = path.join(dir, BIN_NAME);
  if (fs.existsSync(binPath)) return binPath; // already fetched & verified earlier

  const tag = `v${VERSION}`;
  const archive = `trishul_${VERSION}_${target.os}_${target.arch}.${target.ext}`;
  const baseURL = `https://github.com/${REPO}/releases/download/${tag}`;

  console.error(
    `trishul-cli: no prebuilt platform package found; ` +
      `fetching verified binary for ${process.platform}/${process.arch} from the ${tag} release...`
  );

  let archiveBuf, checksumsText;
  try {
    [archiveBuf, checksumsText] = await Promise.all([
      httpGet(`${baseURL}/${archive}`),
      httpGet(`${baseURL}/checksums.txt`).then((b) => b.toString("utf8")),
    ]);
  } catch (err) {
    fail(
      `download failed: ${err.message}\n` +
        `Install manually from https://github.com/${REPO}/releases/tag/${tag}`
    );
  }

  const checksums = parseChecksums(checksumsText);
  const expected = checksums[archive];
  if (!expected) {
    fail(
      `checksums.txt has no entry for ${archive}; refusing to run an unverified binary.`
    );
  }
  const actual = sha256(archiveBuf);
  if (actual !== expected) {
    fail(
      `checksum mismatch for ${archive}\n` +
        `  expected ${expected}\n  actual   ${actual}\n` +
        `Refusing to run a binary that does not match the published release.`
    );
  }

  let binBuf;
  try {
    binBuf =
      target.ext === "zip"
        ? extractFromZip(archiveBuf, BIN_NAME)
        : extractFromTarGz(archiveBuf, BIN_NAME);
  } catch (err) {
    fail(`failed to extract ${BIN_NAME} from ${archive}: ${err.message}`);
  }
  if (!binBuf) fail(`archive ${archive} did not contain ${BIN_NAME}`);

  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${binPath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, binBuf, { mode: 0o755 });
  if (process.platform !== "win32") fs.chmodSync(tmp, 0o755);
  fs.renameSync(tmp, binPath); // atomic publish into the cache
  return binPath;
}

async function main() {
  if (!PLATFORM_PACKAGES[KEY]) unsupported();

  const resolved = resolvePlatformBinary();
  if (resolved) {
    run(resolved);
    return;
  }
  const fetched = await downloadVerifyExtract();
  run(fetched);
}

main().catch((err) => fail(err && err.message ? err.message : String(err)));
