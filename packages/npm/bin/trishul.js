#!/usr/bin/env node

const { execFileSync } = require("child_process");
const path = require("path");
const os = require("os");

const binName = os.platform() === "win32" ? "trishul.exe" : "trishul";
const binPath = path.join(__dirname, binName);

try {
  execFileSync(binPath, process.argv.slice(2), { stdio: "inherit" });
} catch (err) {
  if (err.status !== undefined) {
    process.exit(err.status);
  }
  console.error(
    "Failed to run trishul. Try reinstalling: npm install -g @trishul/cli"
  );
  process.exit(1);
}
