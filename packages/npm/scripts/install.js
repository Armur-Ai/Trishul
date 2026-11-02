#!/usr/bin/env node

const { execSync } = require("child_process");
const fs = require("fs");
const https = require("https");
const path = require("path");
const os = require("os");

const REPO = "Armur-Ai/trishul";
const BIN_NAME = os.platform() === "win32" ? "trishul.exe" : "trishul";

function getPlatform() {
  const platform = os.platform();
  const arch = os.arch();

  const platformMap = {
    darwin: "darwin",
    linux: "linux",
    win32: "windows",
  };

  const archMap = {
    x64: "amd64",
    arm64: "arm64",
  };

  const p = platformMap[platform];
  const a = archMap[arch];

  if (!p || !a) {
    throw new Error(`Unsupported platform: ${platform}/${arch}`);
  }

  return { os: p, arch: a };
}

function getLatestVersion() {
  return new Promise((resolve, reject) => {
    https.get(
      `https://api.github.com/repos/${REPO}/releases/latest`,
      { headers: { "User-Agent": "trishul-npm-installer" } },
      (res) => {
        if (res.statusCode === 302 || res.statusCode === 301) {
          https.get(
            res.headers.location,
            { headers: { "User-Agent": "trishul-npm-installer" } },
            (res2) => {
              let data = "";
              res2.on("data", (chunk) => (data += chunk));
              res2.on("end", () => {
                try {
                  resolve(JSON.parse(data).tag_name || "v0.0.1");
                } catch {
                  resolve("v0.0.1");
                }
              });
            }
          );
          return;
        }
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            const release = JSON.parse(data);
            resolve(release.tag_name || "v0.0.1");
          } catch {
            resolve("v0.0.1");
          }
        });
        res.on("error", reject);
      }
    );
  });
}

async function install() {
  try {
    const { os: osName, arch } = getPlatform();
    const version = await getLatestVersion();
    const tag = version.replace(/^v/, "");

    const ext = osName === "windows" ? "zip" : "tar.gz";
    const filename = `trishul_${tag}_${osName}_${arch}.${ext}`;
    const url = `https://github.com/${REPO}/releases/download/${version}/${filename}`;

    const binDir = path.join(__dirname, "..", "bin");
    fs.mkdirSync(binDir, { recursive: true });

    const tmpFile = path.join(os.tmpdir(), filename);

    console.log(`Downloading trishul ${version} for ${osName}/${arch}...`);

    // Download binary
    execSync(`curl -fsSL -o "${tmpFile}" "${url}"`, { stdio: "inherit" });

    // Extract
    if (ext === "tar.gz") {
      execSync(`tar -xzf "${tmpFile}" -C "${binDir}" trishul`, {
        stdio: "inherit",
      });
    } else {
      execSync(`unzip -o "${tmpFile}" trishul.exe -d "${binDir}"`, {
        stdio: "inherit",
      });
    }

    // Make executable
    const binPath = path.join(binDir, BIN_NAME);
    if (osName !== "windows") {
      fs.chmodSync(binPath, 0o755);
    }

    // Clean up
    try {
      fs.unlinkSync(tmpFile);
    } catch {}

    console.log(`trishul ${version} installed successfully!`);
    console.log(`Run: npx trishul run .`);
  } catch (err) {
    console.error("Failed to install trishul binary:", err.message);
    console.error(
      "You can install manually: brew install Armur-Ai/tap/trishul"
    );
    process.exit(0); // Don't fail npm install
  }
}

install();
