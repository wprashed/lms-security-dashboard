import json, os

scratch_dir = '/Users/rashed/.gemini/antigravity/brain/b00f2efc-3e7c-4717-9034-9bd84e31635d/scratch'
base_dir = '/Users/rashed/lms-security-dashboard'
data_dir = os.path.join(base_dir, 'data')

with open(os.path.join(scratch_dir, 'tutor_parsed.json')) as f:
    tutor_data = json.load(f)
with open(os.path.join(scratch_dir, 'learnpress_parsed.json')) as f:
    lp_data = json.load(f)
with open(os.path.join(scratch_dir, 'learndash_parsed.json')) as f:
    ld_data = json.load(f)

tutor_core = [x for x in tutor_data if x['scope_type'] == 'core']
lp_core = [x for x in lp_data if x['scope_type'] == 'core']
ld_core = [x for x in ld_data if x['scope_type'] == 'core']

all_core = tutor_core + lp_core + ld_core

master_dataset = []
for item in all_core:
    vtype = item['vuln_type']
    cat = 'Other'
    if 'SQL Injection' in vtype or item.get('is_sqli'):
        cat = 'SQL Injection'
    elif 'Remote Code Execution' in vtype or item.get('is_rce'):
        cat = 'Remote Code Execution'
    elif 'Stored XSS' in vtype:
        cat = 'Stored XSS'
    elif 'Reflected XSS' in vtype:
        cat = 'Reflected XSS'
    elif 'XSS' in vtype or item.get('is_xss'):
        cat = 'Cross-Site Scripting (XSS)'
    elif 'Broken Access' in vtype or 'Missing Authorization' in vtype:
        cat = 'Broken Access Control'
    elif 'Insecure Direct Object Reference' in vtype:
        cat = 'IDOR'
    elif 'Authentication Bypass' in vtype or item.get('is_auth_bypass'):
        cat = 'Authentication Bypass'
    elif 'Account Takeover' in vtype or item.get('is_account_takeover'):
        cat = 'Account Takeover'
    elif 'Sensitive Information Disclosure' in vtype:
        cat = 'Information Disclosure'
    elif 'CSRF' in vtype:
        cat = 'CSRF'
    elif 'Arbitrary File Upload' in vtype or item.get('is_file_upload'):
        cat = 'Arbitrary File Upload'
    elif 'Local File Inclusion' in vtype or 'Arbitrary File Read' in vtype or 'Path Traversal' in vtype:
        cat = 'File Inclusion / Read'
    elif 'SSRF' in vtype:
        cat = 'SSRF'

    master_dataset.append({
        'cve': item['cve_id'],
        'plugin': item['plugin'],
        'score': item['cvss_score'] if item['cvss_score'] is not None else 0.0,
        'severity': item['cvss_severity'],
        'type': vtype,
        'cat': cat,
        'vector': item['vector_string'],
        'unauth': item['is_unauthenticated'],
        'pub': item['published_date'][:10] if item['published_date'] else '2020-01-01',
        'year': item['year'],
        'desc': item['description'],
        'cna': item['source_cna'],
        'refs': item['references'][:4] if item['references'] else []
    })

with open(os.path.join(data_dir, 'dataset.json'), 'w') as f:
    json.dump(master_dataset, f, indent=2)

config = {
    "password": "seclms2026",
    "last_updated": "2026-09-04T15:42:00",
    "active_installs": {
        "Tutor LMS": 100000,
        "LearnPress": 70000,
        "LearnDash": 75000
    },
    "total_records": len(master_dataset)
}

with open(os.path.join(data_dir, 'config.json'), 'w') as f:
    json.dump(config, f, indent=2)

print(f"Initialized dataset with {len(master_dataset)} records and config.json")
