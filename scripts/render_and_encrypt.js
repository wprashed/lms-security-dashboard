const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const baseDir = path.resolve(__dirname, '..');
const dataDir = path.join(baseDir, 'data');
const scriptsDir = path.join(baseDir, 'scripts');
const artifactDir = process.env.ARTIFACT_DIR || '/Users/rashed/.gemini/antigravity/brain/b00f2efc-3e7c-4717-9034-9bd84e31635d';

const datasetPath = path.join(dataDir, 'dataset.json');
const configPath = path.join(dataDir, 'config.json');
const templatePath = path.join(scriptsDir, 'inner_dashboard.html');

const dataset = JSON.parse(fs.readFileSync(datasetPath, 'utf8'));
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
let templateHtml = fs.readFileSync(templatePath, 'utf8');

const password = config.password || 'seclms2026';

console.log(`[Render] Compiling dashboard with ${dataset.length} records...`);

// Compute metrics
const tutorItems = dataset.filter(x => x.plugin === 'Tutor LMS');
const lpItems = dataset.filter(x => x.plugin === 'LearnPress');
const ldItems = dataset.filter(x => x.plugin === 'LearnDash');

function calcWis(items) {
  let total = 0;
  items.forEach(x => {
    let w = 4.0;
    const t = (x.type || '').toLowerCase();
    if (t.includes('remote code execution') || t.includes('rce')) w = 10.0;
    else if (t.includes('sql')) w = x.unauth ? 9.0 : 6.0;
    else if (t.includes('authentication bypass') || t.includes('account takeover')) w = 8.0;
    else if (t.includes('file upload')) w = 8.0;
    else if (t.includes('privilege escalation')) w = 7.0;
    else if (t.includes('stored xss')) w = 5.0;
    else if (t.includes('xss')) w = 3.0;
    if (x.unauth) w *= 1.25;
    total += w;
  });
  return total.toFixed(1);
}

const tutorWis = calcWis(tutorItems);
const lpWis = calcWis(lpItems);
const ldWis = calcWis(ldItems);

const tutorDens = (tutorItems.length / (config.active_installs['Tutor LMS'] / 100000)).toFixed(1);
const lpDens = (lpItems.length / (config.active_installs['LearnPress'] / 100000)).toFixed(1);
const ldDens = (ldItems.length / (config.active_installs['LearnDash'] / 100000)).toFixed(1);

const tutorCrit = tutorItems.filter(x => x.severity === 'CRITICAL').length;
const tutorHigh = tutorItems.filter(x => x.severity === 'HIGH').length;
const tutorMed = tutorItems.filter(x => x.severity === 'MEDIUM').length;

const lpCrit = lpItems.filter(x => x.severity === 'CRITICAL').length;
const lpHigh = lpItems.filter(x => x.severity === 'HIGH').length;
const lpMed = lpItems.filter(x => x.severity === 'MEDIUM').length;

const ldCrit = ldItems.filter(x => x.severity === 'CRITICAL').length;
const ldHigh = ldItems.filter(x => x.severity === 'HIGH').length;
const ldMed = ldItems.filter(x => x.severity === 'MEDIUM').length;

// Replace placeholders in template
templateHtml = templateHtml
  .split('__TOTAL_RECORDS__').join(dataset.length.toString())
  .split('__LD_LEN__').join(ldItems.length.toString())
  .split('__TUTOR_LEN__').join(tutorItems.length.toString())
  .split('__LP_LEN__').join(lpItems.length.toString())
  .split('__LD_DENS__').join(ldDens)
  .split('__TUTOR_DENS__').join(tutorDens)
  .split('__LP_DENS__').join(lpDens)
  .split('__LD_WIS__').join(ldWis)
  .split('__TUTOR_WIS__').join(tutorWis)
  .split('__LP_WIS__').join(lpWis)
  .split('__LD_CRIT__').join(ldCrit.toString())
  .split('__LD_HIGH__').join(ldHigh.toString())
  .split('__LD_MED__').join(ldMed.toString())
  .split('__TUTOR_CRIT__').join(tutorCrit.toString())
  .split('__TUTOR_HIGH__').join(tutorHigh.toString())
  .split('__TUTOR_MED__').join(tutorMed.toString())
  .split('__LP_CRIT__').join(lpCrit.toString())
  .split('__LP_HIGH__').join(lpHigh.toString())
  .split('__LP_MED__').join(lpMed.toString())
  .replace('__DATASET_JSON__', JSON.stringify(dataset));

// Encrypt innerDashboard using AES-256-GCM and PBKDF2
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);

const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

let encrypted = cipher.update(templateHtml, 'utf8');
encrypted = Buffer.concat([encrypted, cipher.final()]);
const tag = cipher.getAuthTag();
const combinedCipher = Buffer.concat([encrypted, tag]);

const saltBase64 = salt.toString('base64');
const ivBase64 = iv.toString('base64');
const payloadBase64 = combinedCipher.toString('base64');

const secureHtml = `<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecLMS Intelligence | WordPress LMS Security Benchmark</title>
  <meta name="description" content="Encrypted security vulnerability intelligence portal comparing Tutor LMS, LearnPress, and LearnDash with automated daily synchronizations.">
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <style>
    :root {
      --bg-main: #0b0f19;
      --bg-sidebar: #0f172a;
      --bg-card: #111827;
      --bg-card-sub: #1e293b;
      --bg-header: rgba(11, 15, 25, 0.90);
      --bg-input: #0f172a;
      --border-main: #1e293b;
      --border-subtle: #334155;
      --text-title: #f8fafc;
      --text-body: #cbd5e1;
      --text-muted: #94a3b8;
      --text-faint: #64748b;
      --table-row-hover: rgba(30, 41, 59, 0.5);
      --sidebar-nav-active-bg: rgba(14, 165, 233, 0.15);
      --sidebar-nav-active-border: #0ea5e9;
      --sidebar-nav-active-text: #38bdf8;
    }
    .light-theme {
      --bg-main: #f8fafc;
      --bg-sidebar: #ffffff;
      --bg-card: #ffffff;
      --bg-card-sub: #f1f5f9;
      --bg-header: rgba(255, 255, 255, 0.92);
      --bg-input: #f8fafc;
      --border-main: #e2e8f0;
      --border-subtle: #cbd5e1;
      --text-title: #0f172a;
      --text-body: #334155;
      --text-muted: #64748b;
      --text-faint: #94a3b8;
      --table-row-hover: #f1f5f9;
      --sidebar-nav-active-bg: rgba(14, 165, 233, 0.1);
      --sidebar-nav-active-border: #0284c7;
      --sidebar-nav-active-text: #0284c7;
    }
    body {
      background-color: var(--bg-main);
      color: var(--text-body);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      transition: background-color 0.2s ease, color 0.2s ease;
    }
    .ui-sidebar { background-color: var(--bg-sidebar); }
    .ui-header { background-color: var(--bg-header); backdrop-filter: blur(12px); }
    .ui-card { background-color: var(--bg-card); }
    .ui-subcard { background-color: var(--bg-card-sub); }
    .ui-border { border-color: var(--border-main); }
    .ui-input { background-color: var(--bg-input); }
    .ui-title { color: var(--text-title); }
    .ui-body { color: var(--text-body); }
    .ui-muted { color: var(--text-muted); }
    .ui-faint { color: var(--text-faint); }
    .ui-hover-bg:hover { background-color: var(--table-row-hover); }
    .ui-table-row:hover { background-color: var(--table-row-hover); }
    .sidebar-nav-active {
      background-color: var(--sidebar-nav-active-bg) !important;
      color: var(--sidebar-nav-active-text) !important;
      border-left: 3px solid var(--sidebar-nav-active-border) !important;
      font-weight: 700 !important;
    }
    .glow-tutor { box-shadow: 0 4px 20px -4px rgba(245, 158, 11, 0.12); }
    .glow-lp { box-shadow: 0 4px 20px -4px rgba(244, 63, 94, 0.12); }
    .glow-ld { box-shadow: 0 4px 20px -4px rgba(16, 185, 129, 0.12); }

    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-main); }
    ::-webkit-scrollbar-thumb { background: var(--border-main); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--text-faint); }

    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      20%, 60% { transform: translateX(-8px); }
      40%, 80% { transform: translateX(8px); }
    }
    .shake { animation: shake 0.4s ease-in-out; }
  </style>
</head>
<body class="antialiased min-h-screen">
  <!-- Authentication Lock Screen -->
  <div id="auth-lock-screen" class="fixed inset-0 z-50 flex items-center justify-center p-4" style="background-color: var(--bg-main);">
    <div class="absolute inset-0 bg-[radial-gradient(#64748b_1px,transparent_1px)] [background-size:24px_24px] opacity-25 pointer-events-none"></div>

    <div id="auth-card" class="relative max-w-md w-full ui-card rounded-3xl p-8 shadow-2xl space-y-6 border ui-border">
      <div class="text-center space-y-3">
        <div class="w-16 h-16 rounded-2xl bg-gradient-to-tr from-sky-500/20 to-indigo-500/20 border border-sky-500/30 flex items-center justify-center text-3xl mx-auto shadow-md">
          🔒
        </div>
        <div class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold tracking-widest uppercase bg-sky-500/10 text-sky-500 border border-sky-500/20 whitespace-nowrap">
          <span>AES-256-GCM Encrypted</span>
        </div>
        <h1 class="text-xl font-black ui-title tracking-tight">SecLMS Intelligence Portal</h1>
        <p class="text-xs ui-muted leading-relaxed">
          Daily synchronized vulnerability benchmark for Tutor LMS, LearnPress, and LearnDash. Please authenticate to decrypt.
        </p>
      </div>

      <form id="auth-form" onsubmit="handleUnlock(event)" class="space-y-4">
        <div class="space-y-1.5">
          <label class="block text-xs font-semibold ui-body">Access Key / Password</label>
          <div class="relative">
            <input type="password" id="input-password" placeholder="Enter dashboard password..." required
              class="w-full ui-input border ui-border focus:border-sky-500 rounded-xl px-4 py-3 text-sm ui-title placeholder:ui-faint focus:outline-none transition pr-10 shadow-sm">
            <button type="button" onclick="togglePasswordVisibility()" class="absolute right-3 top-3 ui-muted hover:ui-title text-sm focus:outline-none">
              <span id="eye-icon">👁️</span>
            </button>
          </div>
        </div>

        <div class="flex items-center justify-between text-xs">
          <label class="flex items-center gap-2 ui-muted cursor-pointer select-none">
            <input type="checkbox" id="remember-session" checked class="rounded ui-input border ui-border text-sky-500 focus:ring-0">
            <span>Remember for this browser session</span>
          </label>
        </div>

        <div id="auth-error-msg" class="hidden p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-500 text-xs font-medium flex items-center gap-2">
          <span>⚠️</span>
          <span>Incorrect password. Access denied.</span>
        </div>

        <button type="submit" id="btn-unlock"
          class="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white font-bold text-xs uppercase tracking-wider transition shadow-lg shadow-sky-500/25 flex items-center justify-center gap-2">
          <span id="unlock-spinner" class="hidden animate-spin">⏳</span>
          <span id="unlock-btn-text">🔓 Decrypt & Access Dashboard</span>
        </button>
      </form>
    </div>
  </div>

  <div id="dashboard-root" class="hidden min-h-screen"></div>

  <script>
    const ENCRYPTED_SALT = "${saltBase64}";
    const ENCRYPTED_IV = "${ivBase64}";
    const ENCRYPTED_PAYLOAD = "${payloadBase64}";

    function base64ToUint8Array(base64) {
      const binaryString = atob(base64);
      const len = binaryString.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) bytes[i] = binaryString.charCodeAt(i);
      return bytes;
    }

    async function deriveKey(password, salt) {
      const enc = new TextEncoder();
      const passKey = await window.crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
      );

      return await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: 100000,
          hash: 'SHA-256'
        },
        passKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
    }

    async function decryptDashboard(password) {
      const salt = base64ToUint8Array(ENCRYPTED_SALT);
      const iv = base64ToUint8Array(ENCRYPTED_IV);
      const ciphertextWithTag = base64ToUint8Array(ENCRYPTED_PAYLOAD);

      const key = await deriveKey(password, salt);

      const decrypted = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        key,
        ciphertextWithTag
      );

      const dec = new TextDecoder();
      return dec.decode(decrypted);
    }

    function togglePasswordVisibility() {
      const inp = document.getElementById('input-password');
      const eye = document.getElementById('eye-icon');
      if (inp.type === 'password') {
        inp.type = 'text';
        eye.textContent = '🙈';
      } else {
        inp.type = 'password';
        eye.textContent = '👁️';
      }
    }

    async function handleUnlock(e) {
      if (e) e.preventDefault();
      const password = document.getElementById('input-password').value.trim();
      const errorBox = document.getElementById('auth-error-msg');
      const btnText = document.getElementById('unlock-btn-text');
      const spinner = document.getElementById('unlock-spinner');
      const card = document.getElementById('auth-card');

      errorBox.classList.add('hidden');
      btnText.textContent = 'Decrypting...';
      spinner.classList.remove('hidden');

      try {
        const decryptedHtml = await decryptDashboard(password);

        const remember = document.getElementById('remember-session').checked;
        if (remember) {
          sessionStorage.setItem('seclms_auth_pass', password);
        }

        document.getElementById('auth-lock-screen').classList.add('hidden');
        const root = document.getElementById('dashboard-root');
        root.innerHTML = decryptedHtml;

        const scripts = root.querySelectorAll('script');
        scripts.forEach(oldScript => {
          const newScript = document.createElement('script');
          Array.from(oldScript.attributes).forEach(attr => newScript.setAttribute(attr.name, attr.value));
          newScript.appendChild(document.createTextNode(oldScript.innerHTML));
          oldScript.parentNode.replaceChild(newScript, oldScript);
        });

        root.classList.remove('hidden');

      } catch (err) {
        console.error("Decryption failed:", err);
        errorBox.classList.remove('hidden');
        card.classList.add('shake');
        setTimeout(() => card.classList.remove('shake'), 450);
      } finally {
        btnText.textContent = '🔓 Decrypt & Access Dashboard';
        spinner.classList.add('hidden');
      }
    }

    function lockSession() {
      sessionStorage.removeItem('seclms_auth_pass');
      document.getElementById('dashboard-root').innerHTML = '';
      document.getElementById('dashboard-root').classList.add('hidden');
      document.getElementById('input-password').value = '';
      document.getElementById('auth-lock-screen').classList.remove('hidden');
      document.getElementById('input-password').focus();
    }

    // Initialize saved theme on lock screen
    const savedTheme = localStorage.getItem('seclms_theme');
    if (savedTheme === 'light') {
      document.body.classList.add('light-theme');
    }

    window.addEventListener('DOMContentLoaded', () => {
      const savedPass = sessionStorage.getItem('seclms_auth_pass');
      if (savedPass) {
        document.getElementById('input-password').value = savedPass;
        handleUnlock();
      } else {
        document.getElementById('input-password').focus();
      }
    });
  </script>
</body>
</html>
`;

// Save encrypted index.html to workspace
fs.writeFileSync(path.join(baseDir, 'index.html'), secureHtml);
// Save to artifact if directory exists
if (fs.existsSync(artifactDir)) {
  fs.writeFileSync(path.join(artifactDir, 'lms_security_website.html'), secureHtml);
}

console.log(`[Render] Successfully generated and encrypted index.html!`);
