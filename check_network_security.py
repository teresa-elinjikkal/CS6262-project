
import pandas as pd
import dns.resolver
from pathlib import Path
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================================
# 1. FILE PATHS
# ==========================================

ROOT = Path(__file__).resolve().parents[1]

INPUT = ROOT / "data/processed/all_us_districts.csv"
OUTPUT_DIR = ROOT / "data/processed"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT = OUTPUT_DIR / "network_security_results.csv"

# Common DKIM selectors.
# This is a discovery check, not proof of DKIM absence.
DKIM_SELECTORS = [
    "google",
    "selector1",
    "selector2",
    "default",
    "k1",
    "s1",
    "s2",
    "mail"
]

# DNS resolver configuration
resolver = dns.resolver.Resolver()
resolver.timeout = 3
resolver.lifetime = 5


# ==========================================
# 2. DOMAIN EXTRACTION
# ==========================================

def extract_domain(website_url, existing_domain):

    value = existing_domain or website_url

    if not value:
        return ""

    value = value.strip().lower()

    # Handle URLs and plain domains
    if "://" not in value:
        value = "//" + value

    try:
        hostname = urlsplit(value).hostname

        if not hostname:
            return ""

        hostname = hostname.rstrip(".")

        return hostname.encode("idna").decode("ascii")

    except Exception:
        return ""


# ==========================================
# 3. DNS LOOKUP HELPER
# ==========================================

def dns_lookup(domain, record_type):

    try:
        answers = resolver.resolve(
            domain,
            record_type,
            lifetime=5
        )

        return [
            answer for answer in answers
        ], "Success"

    except dns.resolver.NoAnswer:
        return [], "No record"

    except dns.resolver.NXDOMAIN:
        return [], "Domain does not exist"

    except dns.exception.Timeout:
        return [], "Timeout"

    except Exception as error:
        return [], type(error).__name__


def txt_value(record):

    return b"".join(record.strings).decode(
        "utf-8", errors="replace"
    )


# ==========================================
# 4. SPF CHECK
# ==========================================

def check_spf(domain):

    records, status = dns_lookup(domain, "TXT")

    if status != "Success":
        return status, ""

    spf_records = [
        txt_value(record)
        for record in records
        if txt_value(record).lower().startswith("v=spf1")
    ]

    if spf_records:
        return "Present", "; ".join(spf_records)

    return "Not detected", ""


# ==========================================
# 5. DMARC CHECK
# ==========================================

def check_dmarc(domain):

    records, status = dns_lookup(
        "_dmarc." + domain,
        "TXT"
    )

    if status not in ["Success", "No record"]:
        return status, "Unknown", ""

    dmarc_records = [
        txt_value(record)
        for record in records
        if txt_value(record).lower().startswith("v=dmarc1")
    ]

    if not dmarc_records:
        return "Not detected", "Unknown", ""

    record = dmarc_records[0]

    policy = "Unknown"

    for part in record.split(";"):

        part = part.strip()

        if part.lower().startswith("p="):
            policy = part.split("=", 1)[1].strip().lower()

    return "Present", policy, record


# ==========================================
# 6. DKIM CHECK
# ==========================================

def check_dkim(domain):

    found = []
    successful_lookups = 0

    for selector in DKIM_SELECTORS:

        query = f"{selector}._domainkey.{domain}"

        records, status = dns_lookup(query, "TXT")

        if status in ["Success", "No record"]:
            successful_lookups += 1

        for record in records:

            value = txt_value(record)

            if "p=" in value.lower():
                found.append(selector)

    if found:
        return "Detected", "; ".join(found)

    if successful_lookups == 0:
        return "Inconclusive", ""

    return "Not detected by tested selectors", ""


# ==========================================
# 7. MX RECORDS AND EMAIL PROVIDER
# ==========================================

def check_mx(domain):

    records, status = dns_lookup(domain, "MX")

    if not records:
        return status, "", "Unknown"

    hosts = []

    for record in records:

        host = str(record.exchange).lower().rstrip(".")

        hosts.append(host)

    combined = " ".join(hosts)

    if (
        "google.com" in combined
        or "googlemail.com" in combined
    ):
        provider = "Google"

    elif (
        "outlook.com" in combined
        or "protection.outlook.com" in combined
    ):
        provider = "Microsoft"

    elif "proofpoint" in combined:
        provider = "Proofpoint"

    elif "mimecast" in combined:
        provider = "Mimecast"

    else:
        provider = "Other / Unknown"

    return "Present", "; ".join(hosts), provider


# ==========================================
# 8. DNSSEC CHECK
# ==========================================

def check_dnssec(domain):

    ds_records, ds_status = dns_lookup(domain, "DS")

    dnskey_records, dnskey_status = dns_lookup(
        domain, "DNSKEY"
    )

    ds_found = len(ds_records) > 0
    dnskey_found = len(dnskey_records) > 0

    if ds_found and dnskey_found:

        return (
            "DS and DNSKEY found; validation not verified",
            len(ds_records),
            len(dnskey_records)
        )

    elif not ds_found and not dnskey_found:

        if ds_status == "No record":
            return "No DS found", 0, 0

        return "Inconclusive", 0, 0

    elif ds_found:

        return (
            "DS found; DNSKEY unavailable",
            len(ds_records),
            0
        )

    else:

        return (
            "DNSKEY found but no DS",
            0,
            len(dnskey_records)
        )


# ==========================================
# 9. PROCESS ONE DISTRICT
# ==========================================

def process_district(row):

    domain = extract_domain(
        row.get("websiteUrl", ""),
        row.get("websiteDomain", "")
    )

    result = {
        "districtId": row.get("districtId", ""),
        "districtName": row.get("districtName", ""),
        "state": row.get("state", ""),
        "websiteDomain": domain
    }

    if not domain:

        result.update({
            "spf_status": "No domain",
            "spf_record": "",
            "dmarc_status": "No domain",
            "dmarc_policy": "Unknown",
            "dmarc_record": "",
            "dkim_status": "Unknown",
            "dkim_selectors_found": "",
            "mx_status": "No domain",
            "mx_records": "",
            "email_provider": "Unknown",
            "dnssec_status": "Unknown",
            "ds_count": 0,
            "dnskey_count": 0
        })

        return result

    # Email authentication
    spf_status, spf_record = check_spf(domain)

    dmarc_status, dmarc_policy, dmarc_record = (
        check_dmarc(domain)
    )

    dkim_status, dkim_selectors = check_dkim(domain)

    # Mail infrastructure
    mx_status, mx_records, email_provider = check_mx(domain)

    # DNSSEC
    dnssec_status, ds_count, dnskey_count = (
        check_dnssec(domain)
    )

    result.update({
        "spf_status": spf_status,
        "spf_record": spf_record,
        "dmarc_status": dmarc_status,
        "dmarc_policy": dmarc_policy,
        "dmarc_record": dmarc_record,
        "dkim_status": dkim_status,
        "dkim_selectors_found": dkim_selectors,
        "mx_status": mx_status,
        "mx_records": mx_records,
        "email_provider": email_provider,
        "dnssec_status": dnssec_status,
        "ds_count": ds_count,
        "dnskey_count": dnskey_count
    })

    return result


# ==========================================
# 10. MAIN PIPELINE
# ==========================================

def main():

    df = pd.read_csv(INPUT, dtype=str).fillna("")

    print("Total districts:", len(df))
    print("Starting network security measurements...\n")

    results = []

    with ThreadPoolExecutor(max_workers=5) as executor:

        futures = [
            executor.submit(process_district, row)
            for row in df.to_dict("records")
        ]

        for i, future in enumerate(as_completed(futures), 1):

            try:
                results.append(future.result())

            except Exception as error:
                print("Processing error:", error)

            if i % 100 == 0:

                print(f"Processed {i}/{len(df)}")

                # Save progress in case the script is interrupted
                pd.DataFrame(results).to_csv(
                    OUTPUT, index=False
                )

    results_df = pd.DataFrame(results)

    # Save final results
    results_df.to_csv(OUTPUT, index=False)

    # ======================================
    # SUMMARY
    # ======================================

    print("\n========== FINAL RESULTS ==========")

    print("Total districts:", len(results_df))

    for column in [
        "spf_status",
        "dmarc_status",
        "dmarc_policy",
        "dkim_status",
        "email_provider",
        "dnssec_status"
    ]:

        print(f"\n{column}:")
        print(
            results_df[column]
            .value_counts(dropna=False)
            .to_string()
        )

    print("\nResults saved to:")
    print(OUTPUT)


if __name__ == "__main__":
    main()
