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
      --bg-color: #0b0f19;
      --surface-color: #111827;
      --card-color: #1f2937;
      --border-color: #374151;
      --text-main: #f9fafb;
      --text-dim: #9ca3af;
      --accent-tutor: #f59e0b;
      --accent-lp: #f43f5e;
      --accent-ld: #10b981;
      --accent-brand: #38bdf8;
    }
    .light-theme {
      --bg-color: #f8fafc;
      --surface-color: #ffffff;
      --card-color: #f1f5f9;
      --border-color: #cbd5e1;
      --text-main: #0f172a;
      --text-dim: #64748b;
    }
    body {
      background-color: var(--bg-color);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      transition: background-color 0.2s ease, color 0.2s ease;
    }
    .surface-card {
      background-color: var(--surface-color);
      border: 1px solid var(--border-color);
    }
    .sub-card {
      background-color: var(--card-color);
      border: 1px solid var(--border-color);
    }
    .glass-nav {
      background-color: rgba(11, 15, 25, 0.88);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-color);
    }
    .light-theme .glass-nav {
      background-color: rgba(255, 255, 255, 0.9);
    }
    .light-theme aside#app-sidebar {
      background-color: rgba(248, 250, 252, 0.96);
      border-color: #e2e8f0;
    }
    .light-theme aside#app-sidebar nav a.sidebar-nav-link {
      color: #334155;
    }
    .light-theme aside#app-sidebar nav a.sidebar-nav-link:hover {
      background-color: #e2e8f0;
      color: #0f172a;
    }
    .glow-tutor { box-shadow: 0 0 25px -5px rgba(245, 158, 11, 0.15); }
    .glow-lp { box-shadow: 0 0 25px -5px rgba(244, 63, 94, 0.15); }
    .glow-ld { box-shadow: 0 0 25px -5px rgba(16, 185, 129, 0.15); }

    ::-webkit-scrollbar { width: 7px; height: 7px; }
    ::-webkit-scrollbar-track { background: var(--bg-color); }
    ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: #64748b; }

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
  <div id="auth-lock-screen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0b0f19]">
    <div class="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-40 pointer-events-none"></div>

    <div id="auth-card" class="relative max-w-md w-full surface-card rounded-3xl p-8 shadow-2xl space-y-6 border border-slate-700/80">
      <div class="text-center space-y-3">
        <div class="w-16 h-16 rounded-2xl bg-gradient-to-tr from-sky-500/20 to-indigo-500/20 border border-sky-500/30 flex items-center justify-center text-3xl mx-auto shadow-lg shadow-sky-500/10">
          🔒
        </div>
        <div class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold tracking-widest uppercase bg-sky-500/10 text-sky-400 border border-sky-500/20 whitespace-nowrap">
          <span>AES-256-GCM Encrypted</span>
        </div>
        <h1 class="text-xl font-black text-white tracking-tight">SecLMS Intelligence Portal</h1>
        <p class="text-xs text-slate-400 leading-relaxed">
          Daily synchronized vulnerability benchmark for Tutor LMS, LearnPress, and LearnDash. Please authenticate to decrypt.
        </p>
      </div>

      <form id="auth-form" onsubmit="handleUnlock(event)" class="space-y-4">
        <div class="space-y-1.5">
          <label class="block text-xs font-semibold text-slate-300">Access Key / Password</label>
          <div class="relative">
            <input type="password" id="input-password" placeholder="Enter dashboard password..." required
              class="w-full bg-slate-900 border border-slate-700 focus:border-sky-500 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none transition pr-10">
            <button type="button" onclick="togglePasswordVisibility()" class="absolute right-3 top-3 text-slate-400 hover:text-slate-200 text-sm focus:outline-none">
              <span id="eye-icon">👁️</span>
            </button>
          </div>
        </div>

        <div class="flex items-center justify-between text-xs">
          <label class="flex items-center gap-2 text-slate-400 cursor-pointer select-none">
            <input type="checkbox" id="remember-session" checked class="rounded bg-slate-900 border-slate-700 text-sky-500 focus:ring-0">
            <span>Remember for this browser session</span>
          </label>
        </div>

        <div id="auth-error-msg" class="hidden p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-medium flex items-center gap-2">
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
