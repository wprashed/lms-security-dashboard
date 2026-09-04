# WordPress LMS Security Intelligence Benchmark

> An empirical, data-driven security comparison evaluating **LearnDash**, **Tutor LMS**, and **LearnPress**. Cross-referenced across NIST NVD (National Vulnerability Database 2.0), Wordfence Intelligence, Patchstack, WPScan, and official WordPress Trac changesets.

---

## 🛡️ Benchmark Summary (Normalized Metrics)

| Metric | LearnDash | Tutor LMS | LearnPress |
| :--- | :---: | :---: | :---: |
| **Market Rank** | 🥇 **Rank #1 (Lowest Risk)** | 🥈 **Rank #2 (High Volume)** | 🥉 **Rank #3 (Highest Threat)** |
| **Active Installations** | ~75,000 | 100,000+ | 70,000+ |
| **Unique Core CVEs** | **14** *(17 raw, 3 3rd-party)* | **101** *(102 raw)* | **76** *(84 raw)* |
| **Vulns / 100k Sites** | **18.7** | **101.0** | **108.6** |
| **Median Patch Delay** | **2–4 Days** | **5–12 Days** | **14–30+ Days** |
| **Weighted Impact (WIS)** | **123.8** | **597.5** | **687.5** |
| **Primary Flaw Type** | Rare Shortcode/Regex | Custom AJAX / SQL Regressions | Unauthenticated REST SQLi |

---

## 🚀 Key Features

- **SaaS Vertical Sidebar Navigation**: Intuitive layout with section ScrollSpy, quick platform filters, and micro-counters.
- **Client-Side Cryptographic Protection**: The application is distributed as a single, self-contained `index.html` encrypted with **AES-256-GCM** and **100,000 PBKDF2 rounds**.
- **Interactive Multi-Attribute Explorer**: Filter 197+ CVEs by date ranges (2018–2026), vulnerability categories (SQLi, RCE, IDOR, XSS), CVSS thresholds, and authentication barriers.
- **Velocity Visualizations**: Longitudinal tracking of disclosure timelines and patch response speeds.
- **Architectural Root-Cause Analysis**: Deep dive into why LearnDash's native Custom Post Type (`WP_Query`) abstraction minimizes attack surfaces compared to custom AJAX and direct `$wpdb` querying.
- **Interactive Threat Simulator**: Real-time risk scenario modeler allowing organizations to customize threat factor weights (RCE, Unauth SQLi, etc.).
- **Automated Daily Sync**: Built-in GitHub Actions workflow and local daemon that queries the NIST NVD 2.0 API every 24 hours, updates records, and re-renders the encrypted portal.

---

## 🔒 Security & Access

The standalone dashboard is encrypted at rest and in transit. By default, access is unlocked with the key configured in `data/config.json`.

To change the master password:
```bash
node set-password.js "your_new_password"
```

---

## ⚡ Daily Automation

- **GitHub Actions**: Configured in `.github/workflows/daily-sync.yml` to run daily at 09:00 UTC.
- **Local Runner**:
  ```bash
  ./run_update.sh
  ```

---

## 📄 License
MIT License. Intelligence data cross-referenced from public security advisories (NIST, CVE, Wordfence, Patchstack, WPScan).
