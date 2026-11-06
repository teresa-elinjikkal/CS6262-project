#!/usr/bin/env python3
"""
Fast, concurrent web/email security scan for U.S. school districts.

Input:
  data/processed/combined_district_dataset.csv

Output:
  data/processed/combined_district_dataset_extended_security.csv

Install:
  pip3 install pandas dnspython requests

Design:
- Scans each unique district website domain once, then maps results back to districts.
- Uses concurrent workers (default 30).
- Reuses the HTTPS response to collect headers, cookie attributes, and
  certificate-verification outcome.
- Checks corrected DMARC classification, MTA-STS, and TLS-RPT.
- Does NOT repeat SPF, DKIM, MX-provider, or DNSSEC measurements already
  present in the combined input.
- Does NOT actively test application vulnerabilities.
"""

from __future__ import annotations

import argparse
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import dns.exception
import dns.resolver
import pandas as pd
import requests
from requests.exceptions import RequestException

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "data" / "processed" / "combined_district_dataset.csv"
DEFAULT_OUTPUT = ROOT / "data" / "processed" / "combined_district_dataset_extended_security.csv"

DNS_TIMEOUT = 2.0
HTTP_TIMEOUT = 5
USER_AGENT = "SchoolDistrictSecurityResearch/1.0 (academic measurement)"
HEADERS_TO_CHECK = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

_thread_local = threading.local()


def get_resolver() -> dns.resolver.Resolver:
    if not hasattr(_thread_local, "resolver"):
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        _thread_local.resolver = resolver
    return _thread_local.resolver


def get_session() -> requests.Session:
    if not hasattr(_thread_local, "session"):
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        _thread_local.session = session
    return _thread_local.session


def clean_domain(value) -> str:
    if pd.isna(value):
        return ""
    value = str(value).strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0].split(":")[0].strip(".")
    return value


def query_txt(name: str) -> tuple[list[str], str]:
    try:
        answer = get_resolver().resolve(name, "TXT")
        values = [b"".join(record.strings).decode("utf-8", errors="replace") for record in answer]
        return values, "ANSWER"
    except dns.resolver.NoAnswer:
        return [], "NOANSWER"
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoNameservers:
        return [], "NONAMESERVERS"
    except (dns.resolver.Timeout, dns.exception.Timeout):
        return [], "TIMEOUT"
    except Exception as exc:
        return [], f"ERROR:{type(exc).__name__}"


def check_base_domain(domain: str) -> str:
    """Return Exists / Does not exist / Timeout / NoNameservers / Unknown."""
    resolver = get_resolver()
    saw_timeout = False
    saw_no_nameservers = False

    # One A lookup keeps verification bounded. NoAnswer means the name exists
    # but has no A record; NXDOMAIN means the name does not exist.
    try:
        resolver.resolve(domain, "A")
        return "Exists"
    except dns.resolver.NoAnswer:
        return "Exists"
    except dns.resolver.NXDOMAIN:
        return "Does not exist"
    except dns.resolver.NoNameservers:
        return "NoNameservers"
    except (dns.resolver.Timeout, dns.exception.Timeout):
        return "Timeout"
    except Exception:
        return "Unknown"


def parse_dmarc_record(records: list[str]) -> tuple[str, str]:
    for record in records:
        if not re.search(r"(?:^|;)\s*v\s*=\s*DMARC1\b", record, re.I):
            continue
        match = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\b", record, re.I)
        policy = match.group(1).lower() if match else "Unknown"
        rua = "Yes" if re.search(r"(?:^|;)\s*rua\s*=", record, re.I) else "No"
        return policy, rua
    return "Unknown", "Unknown"


def check_dmarc(domain: str) -> dict:
    result = {
        "dmarc_status_corrected": "Unknown",
        "dmarc_policy_corrected": "Unknown",
        "dmarc_rua_present": "Unknown",
        "dmarc_base_domain_status": "Unknown",
    }
    if not domain:
        result.update({
            "dmarc_status_corrected": "No domain",
            "dmarc_base_domain_status": "No domain",
        })
        return result

    records, dns_status = query_txt(f"_dmarc.{domain}")
    dmarc_records = [
        record for record in records
        if re.search(r"(?:^|;)\s*v\s*=\s*DMARC1\b", record, re.I)
    ]

    if dmarc_records:
        policy, rua = parse_dmarc_record(dmarc_records)
        result.update({
            "dmarc_status_corrected": "Present",
            "dmarc_policy_corrected": policy,
            "dmarc_rua_present": rua,
            "dmarc_base_domain_status": "Exists",
        })
        return result

    if dns_status in ("NOANSWER", "NXDOMAIN"):
        base_status = check_base_domain(domain)
        if base_status == "Exists":
            status = "No DMARC record"
        elif base_status == "Does not exist":
            status = "Domain does not exist"
        else:
            status = base_status
        result.update({
            "dmarc_status_corrected": status,
            "dmarc_base_domain_status": base_status,
        })
    elif dns_status == "TIMEOUT":
        result.update({
            "dmarc_status_corrected": "Timeout",
            "dmarc_base_domain_status": "Not checked",
        })
    elif dns_status == "NONAMESERVERS":
        result.update({
            "dmarc_status_corrected": "NoNameservers",
            "dmarc_base_domain_status": "Not checked",
        })
    else:
        result.update({
            "dmarc_status_corrected": "Inconclusive",
            "dmarc_base_domain_status": "Not checked",
        })
    return result


def check_mta_sts_and_tls_rpt(domain: str) -> dict:
    output = {
        "mta_sts_record": "Unknown",
        "tls_rpt_record": "Unknown",
    }
    if not domain:
        return output

    sts_records, sts_status = query_txt(f"_mta-sts.{domain}")
    sts_found = any("v=stsv1" in record.lower() for record in sts_records)
    if sts_found:
        output["mta_sts_record"] = "Present"
    elif sts_status in ("NOANSWER", "NXDOMAIN"):
        output["mta_sts_record"] = "Absent"
    else:
        output["mta_sts_record"] = sts_status

    rpt_records, rpt_status = query_txt(f"_smtp._tls.{domain}")
    rpt_found = any("v=tlsrptv1" in record.lower() for record in rpt_records)
    if rpt_found:
        output["tls_rpt_record"] = "Present"
    elif rpt_status in ("NOANSWER", "NXDOMAIN"):
        output["tls_rpt_record"] = "Absent"
    else:
        output["tls_rpt_record"] = rpt_status

    return output


def check_website(domain: str) -> dict:
    output = {
        "web_https_reachable": "Unknown",
        "web_tls_certificate_valid": "Unknown",
        "web_https_status_code": "",
        "web_final_url": "",
        "web_http_redirects_to_https": "Unknown",
        "web_http_status_code": "",
        "web_scan_error": "",
    }
    for header in HEADERS_TO_CHECK:
        key = header.replace("-", "_")
        output[f"header_{key}"] = "Unknown"
        output[f"header_{key}_value"] = ""
    output.update({
        "cookie_secure_seen": "Unknown",
        "cookie_httponly_seen": "Unknown",
        "cookie_samesite_seen": "Unknown",
    })

    if not domain:
        output["web_scan_error"] = "No domain"
        return output

    session = get_session()
    try:
        response = session.get(
            f"https://{domain}",
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            verify=True,
        )
        output["web_https_reachable"] = "Yes"
        output["web_tls_certificate_valid"] = "Yes"  # requests verified the TLS chain/hostname
        output["web_https_status_code"] = response.status_code
        output["web_final_url"] = response.url

        response_headers = {key.lower(): value for key, value in response.headers.items()}
        for header in HEADERS_TO_CHECK:
            key = header.replace("-", "_")
            value = response_headers.get(header, "")
            output[f"header_{key}"] = "Present" if value else "Absent"
            output[f"header_{key}_value"] = value

        # Multiple Set-Cookie headers can exist; inspect the raw header collection.
        cookie_headers = []
        raw_headers = getattr(response.raw, "headers", None)
        if raw_headers is not None and hasattr(raw_headers, "getlist"):
            cookie_headers = raw_headers.getlist("Set-Cookie")
        if not cookie_headers:
            cookie_headers = [value for key, value in response.headers.items() if key.lower() == "set-cookie"]

        if cookie_headers:
            combined = " ".join(cookie_headers).lower()
            output["cookie_secure_seen"] = "Yes" if re.search(r"(?:^|[;,]\s*)secure(?:[;,]|$)", combined) else "No"
            output["cookie_httponly_seen"] = "Yes" if "httponly" in combined else "No"
            output["cookie_samesite_seen"] = "Yes" if "samesite=" in combined else "No"
        else:
            output["cookie_secure_seen"] = "No cookies observed"
            output["cookie_httponly_seen"] = "No cookies observed"
            output["cookie_samesite_seen"] = "No cookies observed"
        response.close()
    except requests.exceptions.SSLError as exc:
        output["web_https_reachable"] = "TLS error"
        output["web_tls_certificate_valid"] = "No"
        output["web_scan_error"] = f"SSLError: {exc.__class__.__name__}"
    except RequestException as exc:
        output["web_https_reachable"] = "No"
        output["web_scan_error"] = type(exc).__name__

    try:
        response = session.get(
            f"http://{domain}",
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
        output["web_http_status_code"] = response.status_code
        output["web_http_redirects_to_https"] = (
            "Yes" if response.url.lower().startswith("https://") else "No"
        )
        response.close()
    except RequestException as exc:
        output["web_http_redirects_to_https"] = "Could not test"
        if not output["web_scan_error"]:
            output["web_scan_error"] = f"HTTP:{type(exc).__name__}"

    return output


def scan_domain(domain: str) -> dict:
    result = {"scan_domain": domain}
    result.update(check_dmarc(domain))
    result.update(check_mta_sts_and_tls_rpt(domain))
    result.update(check_website(domain))
    return result


def main():
    parser = argparse.ArgumentParser(description="Concurrent extended security scan.")
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--workers", type=int, default=30)
    parser.add_argument("--limit", type=int, default=0, help="Limit unique domains (0 = all)")
    parser.add_argument("--checkpoint", type=int, default=100, help="Save after this many completed domains")
    parser.add_argument("--resume", action="store_true", help="Reuse completed domains in existing output")
    args = parser.parse_args()

    if args.workers < 1 or args.workers > 100:
        raise SystemExit("--workers must be between 1 and 100")

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(input_path, dtype={"districtId": str})
    if "websiteDomain" not in df.columns and "measuredDomain" not in df.columns:
        raise SystemExit("Input needs websiteDomain or measuredDomain.")

    # Preserve the old DMARC result for before/after comparison.
    if "dmarc_status" in df.columns and "dmarc_status_original" not in df.columns:
        df["dmarc_status_original"] = df["dmarc_status"]
    if "dmarc_policy" in df.columns and "dmarc_policy_original" not in df.columns:
        df["dmarc_policy_original"] = df["dmarc_policy"]

    # Use the current website domain as the scan target; fall back to measuredDomain.
    domains = []
    for _, row in df.iterrows():
        domain = clean_domain(row.get("websiteDomain", ""))
        if not domain:
            domain = clean_domain(row.get("measuredDomain", ""))
        domains.append(domain)
    df["scan_domain"] = domains

    unique_domains = sorted({domain for domain in domains if domain})
    if args.limit > 0:
        unique_domains = unique_domains[:args.limit]

    completed = {}
    if args.resume and output_path.exists():
        previous = pd.read_csv(output_path, dtype={"districtId": str})
        if "scan_domain" in previous.columns:
            result_columns = [
                column for column in previous.columns
                if column not in df.columns or column.startswith((
                    "dmarc_status_corrected", "dmarc_policy_corrected",
                    "dmarc_rua_present", "dmarc_base_domain_status",
                    "mta_sts_", "tls_rpt_", "web_", "header_", "cookie_"
                ))
            ]
            for _, row in previous.drop_duplicates("scan_domain").iterrows():
                domain = row.get("scan_domain")
                if isinstance(domain, str) and domain:
                    completed[domain] = {col: row.get(col, "") for col in result_columns}
        print(f"Resume mode: {len(completed)} unique domains already have results.")

    pending = [domain for domain in unique_domains if domain not in completed]
    print(f"District rows: {len(df):,}")
    print(f"Unique domains to scan: {len(unique_domains):,}")
    print(f"Already completed: {len(completed):,}")
    print(f"Remaining unique domains: {len(pending):,}")
    print(f"Workers: {args.workers}")
    print("Scanning each unique domain once; existing SPF/DKIM/MX/DNSSEC results are retained.")

    started = time.time()
    done_count = 0

    def save_output():
        results_df = pd.DataFrame.from_dict(completed, orient="index")
        # scan_domain is already the dictionary index; drop the duplicate value
        # stored in each result and merge using a separate key.
        results_df = results_df.drop(columns=["scan_domain"], errors="ignore")
        results_df.index.name = "_domain_key"
        results_df = results_df.reset_index()
        merged = df.merge(results_df, left_on="scan_domain", right_on="_domain_key", how="left")
        merged = merged.drop(columns=["_domain_key"])
        merged.to_csv(output_path, index=False)

    if not pending:
        save_output()
        print("Nothing new to scan.")
        print(f"Output: {output_path}")
        return

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(scan_domain, domain): domain for domain in pending}
        for future in as_completed(futures):
            domain = futures[future]
            try:
                completed[domain] = future.result()
            except Exception as exc:
                completed[domain] = {
                    "scan_domain": domain,
                    "dmarc_status_corrected": "Scan error",
                    "web_scan_error": f"{type(exc).__name__}: {exc}",
                }
            done_count += 1

            if done_count % args.checkpoint == 0 or done_count == len(pending):
                save_output()
                elapsed = time.time() - started
                rate = done_count / elapsed if elapsed else 0
                remaining = len(pending) - done_count
                eta = remaining / rate if rate else 0
                print(
                    f"Progress: {done_count:,}/{len(pending):,} new domains | "
                    f"{rate:.2f} domains/sec | ETA {eta/60:.1f} min"
                )

    elapsed = time.time() - started
    print("\nScan complete.")
    print(f"Unique domains scanned this run: {done_count:,}")
    print(f"Elapsed: {elapsed/60:.1f} minutes")
    print(f"Output: {output_path}")
    print("\nCorrected DMARC status counts:")
    print(pd.Series([v.get("dmarc_status_corrected", "Unknown") for v in completed.values()]).value_counts().to_string())


if __name__ == "__main__":
    main()
