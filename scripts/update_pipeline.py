#!/usr/bin/env python3
import json, os, sys, time, urllib.request, urllib.parse
from datetime import datetime

script_dir = os.path.dirname(os.path.abspath(__file__))
base_dir = os.path.abspath(os.path.join(script_dir, '..'))
data_dir = os.path.join(base_dir, 'data')
logs_dir = os.path.join(base_dir, 'logs')
scripts_dir = os.path.join(base_dir, 'scripts')
artifact_dir = os.environ.get('ARTIFACT_DIR', '/Users/rashed/.gemini/antigravity/brain/b00f2efc-3e7c-4717-9034-9bd84e31635d')

os.makedirs(logs_dir, exist_ok=True)
log_file = os.path.join(logs_dir, 'update.log')

def log(msg):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{now}] {msg}"
    print(entry)
    with open(log_file, "a") as f:
        f.write(entry + "\n")

log("=== Starting LMS Security Daily Update Pipeline ===")

# 1. Load config and current dataset
config_path = os.path.join(data_dir, 'config.json')
dataset_path = os.path.join(data_dir, 'dataset.json')

if not os.path.exists(config_path) or not os.path.exists(dataset_path):
    log("Error: config.json or dataset.json missing. Run init_data.py first.")
    sys.exit(1)

with open(config_path) as f:
    config = json.load(f)

with open(dataset_path) as f:
    master_dataset = json.load(f)

existing_cves = {x['cve']: x for x in master_dataset}
log(f"Current master dataset loaded: {len(master_dataset)} records.")

# 2. Query NVD API for recent updates
queries = [
    ('Tutor LMS', 'Tutor LMS'),
    ('LearnPress', 'LearnPress'),
    ('LearnDash', 'LearnDash')
]

new_cves_found = []

for canonical_name, keyword in queries:
    log(f"Checking NVD feed for {canonical_name}...")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage=200"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'})
    
    # Retry with backoff in case of NVD rate limiting (429)
    resp_data = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                resp_data = json.loads(resp.read().decode('utf-8'))
                break
        except Exception as e:
            log(f"  NVD query attempt {attempt+1} for {canonical_name} notice: {e}")
            time.sleep(8)

    if not resp_data:
        log(f"  Warning: Could not fetch new NVD data for {canonical_name}, proceeding with current records.")
        continue

    try:
        vulns = resp_data.get('vulnerabilities', [])
        log(f"  Received {len(vulns)} items from NVD for {canonical_name}.")

        for item in vulns:
            cve_obj = item.get('cve', {})
            cve_id = cve_obj.get('id', '')
            if not cve_id:
                continue

            if cve_id in existing_cves:
                continue

            # Filter out third-party false positives
            desc_en = ''
            for d in cve_obj.get('descriptions', []):
                if d.get('lang') == 'en':
                    desc_en = d.get('value', '')
                    break
            desc_lower = desc_en.lower()

            # Scope check
            if canonical_name == 'LearnDash' and ('uncanny' in desc_lower or 'powerpack' in desc_lower or 'gamipress' in desc_lower or 'wisdm' in desc_lower or 'faizaan' in desc_lower):
                continue
            if canonical_name == 'Tutor LMS' and ('certificate customizer' in desc_lower or ('export import' in desc_lower and 'tutor lms' not in desc_lower)):
                continue

            # Parse CVSS
            cvss_score = 0.0
            cvss_sev = 'UNKNOWN'
            vector_str = ''
            attack_vec = 'NETWORK'
            privs = 'NONE'

            metrics = cve_obj.get('metrics', {})
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                d = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score = d.get('baseScore', 0.0)
                cvss_sev = d.get('baseSeverity', 'UNKNOWN')
                vector_str = d.get('vectorString', '')
                privs = d.get('privilegesRequired', 'NONE')
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                d = metrics['cvssMetricV30'][0].get('cvssData', {})
                cvss_score = d.get('baseScore', 0.0)
                cvss_sev = d.get('baseSeverity', 'UNKNOWN')
                vector_str = d.get('vectorString', '')
                privs = d.get('privilegesRequired', 'NONE')

            # Vuln category
            cat = 'Other'
            vtype = 'Other'
            if 'sql' in desc_lower:
                cat = 'SQL Injection'
                vtype = 'SQL Injection'
            elif 'file type upload' in desc_lower or 'unrestricted file upload' in desc_lower or 'arbitrary file upload' in desc_lower:
                cat = 'Arbitrary File Upload'
                vtype = 'Arbitrary File Upload'
            elif 'remote code execution' in desc_lower or 'command injection' in desc_lower or 'rce' in desc_lower:
                cat = 'Remote Code Execution'
                vtype = 'Remote Code Execution'
            elif 'file inclusion' in desc_lower or 'include/require' in desc_lower:
                cat = 'File Inclusion / Read'
                vtype = 'Local File Inclusion'
            elif 'stored cross-site' in desc_lower or 'stored xss' in desc_lower:
                cat = 'Stored XSS'
                vtype = 'Stored XSS'
            elif 'reflected cross-site' in desc_lower or 'reflected xss' in desc_lower:
                cat = 'Reflected XSS'
                vtype = 'Reflected XSS'
            elif 'cross-site' in desc_lower or 'xss' in desc_lower:
                cat = 'Cross-Site Scripting (XSS)'
                vtype = 'Cross-Site Scripting (XSS)'
            elif 'authorization bypass' in desc_lower or 'broken access' in desc_lower or 'missing authorization' in desc_lower:
                cat = 'Broken Access Control'
                vtype = 'Authorization Bypass / Broken Access Control'
            elif 'insecure direct object' in desc_lower or 'idor' in desc_lower:
                cat = 'IDOR'
                vtype = 'Insecure Direct Object Reference'
            elif 'authentication bypass' in desc_lower:
                cat = 'Authentication Bypass'
                vtype = 'Authentication Bypass'
            elif 'sensitive information' in desc_lower or 'unauthorized loss of data' in desc_lower or 'data disclosure' in desc_lower:
                cat = 'Information Disclosure'
                vtype = 'Sensitive Information Disclosure'

                pub_date = cve_obj.get('published', '')[:10] or datetime.now().strftime("%Y-%m-%d")
                year = pub_date[:4]
                unauth = (privs == 'NONE') or ('unauthenticated' in desc_lower)

                refs = [r.get('url', '') for r in cve_obj.get('references', [])][:4]

                new_record = {
                    'cve': cve_id,
                    'plugin': canonical_name,
                    'score': cvss_score,
                    'severity': cvss_sev,
                    'type': vtype,
                    'cat': cat,
                    'vector': vector_str,
                    'unauth': unauth,
                    'pub': pub_date,
                    'year': year,
                    'desc': desc_en,
                    'cna': cve_obj.get('sourceIdentifier', 'NVD'),
                    'refs': refs
                }

                master_dataset.append(new_record)
                existing_cves[cve_id] = new_record
                new_cves_found.append(f"{canonical_name}: {cve_id}")
                log(f"  🌟 NEW VULNERABILITY DISCOVERED: {cve_id} ({canonical_name}) - {vtype} [CVSS {cvss_score}]")

    except Exception as e:
        log(f"  Notice during NVD query for {canonical_name}: {e} (proceeding with cached records)")
    
    time.sleep(6) # Rate limit delay between queries

if new_cves_found:
    log(f"Update Summary: {len(new_cves_found)} new vulnerabilities added to master database.")
    with open(dataset_path, 'w') as f:
        json.dump(master_dataset, f, indent=2)
else:
    log("Update Summary: All database records are currently up-to-date. No new CVEs published today.")

# 3. Update config metadata
config['last_updated'] = datetime.now().isoformat()
config['total_records'] = len(master_dataset)
with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)

# 4. Generate updated unencrypted HTML
log("Re-rendering dashboard with updated metrics...")
tutor_items = [x for x in master_dataset if x['plugin'] == 'Tutor LMS']
lp_items = [x for x in master_dataset if x['plugin'] == 'LearnPress']
ld_items = [x for x in master_dataset if x['plugin'] == 'LearnDash']

# Calculate standardized metrics for scorecards
def calc_wis(items):
    total = 0.0
    for x in items:
        w = 4.0
        t = x['type'].lower()
        if 'remote code execution' in t: w = 10.0
        elif 'sql' in t: w = 9.0 if x['unauth'] else 6.0
        elif 'authentication bypass' in t or 'account takeover' in t: w = 8.0
        elif 'file upload' in t: w = 8.0
        elif 'privilege escalation' in t: w = 7.0
        elif 'stored xss' in t: w = 5.0
        elif 'xss' in t: w = 3.0
        if x['unauth']: w *= 1.25
        total += w
    return round(total, 1)

tutor_wis = calc_wis(tutor_items)
lp_wis = calc_wis(lp_items)
ld_wis = calc_wis(ld_items)

tutor_dens = round(len(tutor_items) / (config['active_installs']['Tutor LMS'] / 100000), 1)
lp_dens = round(len(lp_items) / (config['active_installs']['LearnPress'] / 100000), 1)
ld_dens = round(len(ld_items) / (config['active_installs']['LearnDash'] / 100000), 1)

# Render builder script
render_script = os.path.join(scripts_dir, 'render_and_encrypt.js')
os.system(f"node '{render_script}' >> '{log_file}' 2>&1")

log("=== LMS Security Daily Update Pipeline Finished Successfully ===")
