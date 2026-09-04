#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const newPass = process.argv[2];
if (!newPass) {
  console.log("Usage: node set-password.js <new-password>");
  process.exit(1);
}

const configPath = path.join(__dirname, 'data', 'config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
config.password = newPass;
fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

const renderScript = path.join(__dirname, 'scripts', 'render_and_encrypt.js');
execSync(`node "${renderScript}"`, { stdio: 'inherit' });
console.log(`Password successfully updated and dashboard re-encrypted with: "${newPass}"`);
