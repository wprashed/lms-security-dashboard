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
    :root, html, body {
      --bg-main: #07090e;
      --bg-sidebar: #0b0f17;
      --bg-card: #131926;
      --bg-card-sub: #1b2334;
      --bg-header: rgba(11, 15, 23, 0.95);
      --bg-input: #0b0f17;
      --border-main: #243047;
      --border-subtle: #34425d;
      --text-title: #ffffff;
      --text-body: #e1e7f0;
      --text-muted: #9caec7;
      --text-faint: #6b7f9d;
      --table-row-hover: rgba(40, 53, 78, 0.5);
      --sidebar-nav-active-bg: rgba(255, 255, 255, 0.09);
      --sidebar-nav-active-border: #ffffff;
      --sidebar-nav-active-text: #ffffff;
    }
    body {
      background-color: var(--bg-main);
      color: var(--text-body);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    .ui-sidebar { background-color: var(--bg-sidebar); }
    .ui-header { background-color: var(--bg-header); backdrop-filter: blur(12px); }
    .ui-card {
      background-color: var(--bg-card);
      border: 1px solid var(--border-main);
      box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.4);
    }
    .ui-subcard {
      background-color: var(--bg-card-sub);
      border: 1px solid var(--border-subtle);
    }
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
    <div class="absolute inset-0 bg-[radial-gradient(#64748b_1px,transparent_1px)] [background-size:24px_24px] opacity-20 pointer-events-none"></div>

    <div id="auth-card" class="relative max-w-md w-full ui-card rounded-3xl p-8 shadow-2xl space-y-6 border ui-border">
      <div class="text-center space-y-3">
        <div class="w-14 h-14 rounded-2xl ui-subcard border ui-border flex items-center justify-center ui-title mx-auto shadow-sm">
          <svg class="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
            <path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
          </svg>
        </div>
        <div class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold tracking-widest uppercase ui-subcard ui-muted border ui-border whitespace-nowrap">
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
              class="w-full ui-input border ui-border focus:border-neutral-400 rounded-xl px-4 py-3 text-sm ui-title placeholder:ui-faint focus:outline-none transition pr-10 shadow-sm">
            <button type="button" onclick="togglePasswordVisibility()" class="absolute right-3 top-3.5 ui-muted hover:ui-title focus:outline-none" aria-label="Toggle password visibility">
              <span id="eye-icon">
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                  <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
              </span>
            </button>
          </div>
        </div>

        <div class="flex items-center justify-between text-xs">
          <label class="flex items-center gap-2 ui-muted cursor-pointer select-none">
            <input type="checkbox" id="remember-session" checked class="rounded ui-input border ui-border accent-neutral-500 focus:ring-0">
            <span>Remember for this browser session</span>
          </label>
        </div>

        <div id="auth-error-msg" class="hidden p-3 rounded-xl ui-subcard border ui-border ui-title text-xs font-medium flex items-center gap-2">
          <svg class="w-4 h-4 flex-shrink-0 opacity-80" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
          </svg>
          <span>Incorrect password. Access denied.</span>
        </div>

        <button type="submit" id="btn-unlock"
          class="w-full py-3 px-4 rounded-xl ui-card hover:ui-hover-bg ui-title border ui-border font-bold text-xs uppercase tracking-wider transition shadow-sm flex items-center justify-center gap-2">
          <span id="unlock-spinner" class="hidden">
            <svg class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
            </svg>
          </span>
          <span id="unlock-btn-icon">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
              <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 10.5V6.75a4.5 4.5 0 119 0v3.75M3.75 21.75h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H3.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
            </svg>
          </span>
          <span id="unlock-btn-text">Decrypt & Access Dashboard</span>
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

    const SVG_EYE = \`<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>\`;
    const SVG_EYE_SLASH = \`<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8"><path stroke-linecap="round" stroke-linejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" /></svg>\`;

    function togglePasswordVisibility() {
      const inp = document.getElementById('input-password');
      const eye = document.getElementById('eye-icon');
      if (inp.type === 'password') {
        inp.type = 'text';
        eye.innerHTML = SVG_EYE_SLASH;
      } else {
        inp.type = 'password';
        eye.innerHTML = SVG_EYE;
      }
    }

    async function handleUnlock(e) {
      if (e) e.preventDefault();
      const password = document.getElementById('input-password').value.trim();
      const errorBox = document.getElementById('auth-error-msg');
      const btnText = document.getElementById('unlock-btn-text');
      const spinner = document.getElementById('unlock-spinner');
      const btnIcon = document.getElementById('unlock-btn-icon');
      const card = document.getElementById('auth-card');

      errorBox.classList.add('hidden');
      btnText.textContent = 'Decrypting...';
      if (btnIcon) btnIcon.classList.add('hidden');
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
        btnText.textContent = 'Decrypt & Access Dashboard';
        if (btnIcon) btnIcon.classList.remove('hidden');
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
