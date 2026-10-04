#!/usr/bin/env python3
import requests
import argparse
import re
import sys
from urllib.parse import urljoin

# Ganti dengan API key-mu
WPSCAN_API_KEY = "asy0FH4vY7GvW64mabsnRosLtIlhwuELt07PuLFa8nA"
WPSCAN_API_URL = "https://wpscan.com/api/v3"

HEADERS = {
    "Authorization": f"Token token={WPSCAN_API_KEY}",
    "User-Agent": "WP-CVE-Checker/1.0",
    "Accept": "application/json"
}

def get_severity(cvss_score):
    if cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    else:
        return "low"

def fetch_url(url):
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        return resp.text, resp.status_code
    except Exception as e:
        print(f"[-] Error akses {url}: {e}")
        return "", 0

def detect_versions(html_content, base_url):
    versions = {"core": None, "plugins": {}, "themes": {}}
    
    # Deteksi WordPress core
    match = re.search(r'<meta name="generator" content="WordPress ([\d\.]+)', html_content)
    if match:
        versions["core"] = match.group(1)
    
    # Coba readme.html jika generator disembunyikan
    if not versions["core"]:
        readme_html, _ = fetch_url(urljoin(base_url, "/readme.html"))
        match = re.search(r'<h1>WordPress (\d+\.\d+\.?\d*)', readme_html)
        if match:
            versions["core"] = match.group(1)

    # Deteksi plugin dari asset URLs (ver=...)
    plugin_matches = re.findall(r'/wp-content/plugins/([^/]+)/.*?ver=([\d\.]+)', html_content)
    for plugin, ver in plugin_matches:
        if plugin not in versions["plugins"]:
            versions["plugins"][plugin] = ver

    # Deteksi tema
    theme_match = re.search(r'/wp-content/themes/([^/]+)/.*?ver=([\d\.]+)', html_content)
    if theme_match:
        versions["themes"][theme_match.group(1)] = theme_match.group(2)

    return versions

def check_core_vulnerabilities(wp_version):
    if not wp_version:
        return []
    
    try:
        resp = requests.get(
            f"{WPSCAN_API_URL}/wordpresses/{wp_version}",
            headers=HEADERS,
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("vulnerabilities", [])
        else:
            print(f"[!] WPScan API error untuk core {wp_version}: {resp.status_code}")
            return []
    except Exception as e:
        print(f"[!] Gagal cek core CVE: {e}")
        return []

def check_plugin_vulnerabilities(plugin_name, version):
    try:
        resp = requests.get(
            f"{WPSCAN_API_URL}/plugins/{plugin_name}",
            headers=HEADERS,
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            vulns = []
            for v in data.get("vulnerabilities", []):
                affected_versions = v.get("affected_versions", {})
                # Cek apakah versi kita rentan
                if version in affected_versions or "*" in affected_versions:
                    vulns.append(v)
            return vulns
        else:
            print(f"[!] WPScan API error untuk plugin {plugin_name}: {resp.status_code}")
            return []
    except Exception as e:
        print(f"[!] Gagal cek plugin CVE: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Deteksi CVE WordPress via WPScan API")
    parser.add_argument("url", help="URL target WordPress")
    parser.add_argument("--min-sev", default="medium", choices=["low","medium","high","critical"])
    
    args = parser.parse_args()
    
    target = args.url.rstrip('/')
    
    # Validasi API key
    if WPSCAN_API_KEY == "YOUR_API_KEY_HERE":
        print("❌ Harap ganti WPSCAN_API_KEY di kode dengan API key-mu!")
        sys.exit(1)
    
    print(f"[+] Memindai: {target}")
    
    html, status = fetch_url(target)
    if status != 200:
        print(f"[-] Target tidak merespons (HTTP {status})")
        return
    
    versions = detect_versions(html, target)
    
    all_vulns = []
    
    # Cek core
    if versions["core"]:
        print(f"[✓] WordPress Core: {versions['core']}")
        core_vulns = check_core_vulnerabilities(versions["core"])
        for v in core_vulns:
            cvss = v.get("cvss_score", 0.0)
            severity = get_severity(cvss)
            if severity >= args.min_sev or args.min_sev == "low":
                all_vulns.append({
                    "component": "WordPress Core",
                    "version": versions["core"],
                    "title": v.get("title", "N/A"),
                    "cve": v.get("cve", ["N/A"])[0],
                    "cvss": cvss,
                    "severity": severity,
                    "fixed_in": v.get("fixed_in", None)
                })
    
    # Cek plugin
    for plugin, ver in versions["plugins"].items():
        print(f"[✓] Plugin: {plugin} v{ver}")
        plugin_vulns = check_plugin_vulnerabilities(plugin, ver)
        for v in plugin_vulns:
            cvss = v.get("cvss_score", 0.0)
            severity = get_severity(cvss)
            if severity >= args.min_sev or args.min_sev == "low":
                all_vulns.append({
                    "component": f"Plugin: {plugin}",
                    "version": ver,
                    "title": v.get("title", "N/A"),
                    "cve": v.get("cve", ["N/A"])[0],
                    "cvss": cvss,
                    "severity": severity,
                    "fixed_in": v.get("fixed_in", None)
                })
    
    # Tampilkan hasil
    if all_vulns:
        print("\n[!] KERENTANAN DITEMUKAN:\n")
        
        # Urutkan berdasarkan severity (critical > high > medium > low)
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        all_vulns.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)

        color_map	= {"critical":"\033[91m","high":"\033[93m","medium":"\033[96m","low":"\033[92m"}
        
        for vuln	in	all_vulns[:25]:	# Batasi tampilan pertama 25 saja agar rapih.
            color	=color_map.get(vuln["severity"], "\033[97m")
            reset	="\033[0m"
            
            print(f'{color}• [{vuln["severity"].upper()}]{reset} {vuln["component"]} v{vuln["version"]}')
            print(f'   CVE: {vuln["cve"]} | CVSS: {vuln["cvss"]}')
            print(f'   Judul: {vuln["title"]}')
            if	vuln["fixed_in"]:
                print(f'   Perbaikan tersedia di versi: ≥{vuln["fixed_in"]}')
            print()

    else :
        print("[+] Tidak ditemukan kerentanan sesuai tingkat minimum.")

if __name__ =="__main__":
    main()
