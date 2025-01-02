# main.py

import os
import sys
import requests
from cloudflare import Cloudflare


def get_opn_dhcp_leases(opn_url, auth, interfaces, verify):
    """
    Query OPNsense API to get DHCP leases for specified interfaces.
    Returns a list of dicts with 'hostname' and 'address' fields.
    """
    endpoint = f"{opn_url.rstrip('/')}/api/dhcpv4/leases/searchLease/"
    headers = {
        "Content-Type": "application/json",
    }
    payload = {
        "current": 1,
        "rowCount": -1,
        "sort": {},
        "searchPhrase": "",
        "inactive": False,
        "selected_interfaces": interfaces,
    }

    try:
        resp = requests.post(endpoint, auth=auth, headers=headers, json=payload, timeout=30, verify=verify)
        resp.raise_for_status()
    except Exception as e:
        print(f"Error connecting to OPNsense: {str(e)}")
        sys.exit(1)

    data = resp.json()
    # Expecting 'rows' in the result
    if "rows" not in data:
        print("Unexpected response from OPNsense DHCP API.")
        sys.exit(1)

    leases = []
    for row in data["rows"]:
        hostname = row.get("hostname")
        address = row.get("address")
        if hostname and address:
            leases.append({"hostname": hostname, "address": address})
    return leases


def get_cf_zone_id(cf, zone_name):
    """
    Return the Cloudflare zone ID for a given zone name.
    """
    try:
        zones = cf.zones.list()
        for z in zones:
            if z.name == zone_name:
                return z.id
    except Exception as e:
        print(f"Could not fetch zones from Cloudflare: {str(e)}")
        sys.exit(1)

    print(f"Zone '{zone_name}' not found in Cloudflare.")
    sys.exit(1)


def get_cf_dns_records(cf: Cloudflare, zone_id, subdomain=None):
    """
    Get all DNS records for a given zone.
    If subdomain is specified, filter records that match the subdomain or subdomain+'.zone'.
    Returns a list of records.
    """
    try:
        records = cf.dns.records.list(zone_id=zone_id)
    except Exception as e:
        print(f"Error getting DNS records from Cloudflare: {str(e)}")
        sys.exit(1)

    if subdomain:
        # We'll keep records that are either exactly subdomain.zone_name
        # or end with subdomain.zone_name if subdomain is a wildcard prefix
        filtered = []
        for r in records:
            if r.type == "A":
                # Compare the 'name' with subdomain
                if r.name.endswith(subdomain):
                    filtered.append(r)
        return filtered
    else:
        return records


def find_dns_record(records, hostname):
    """
    Find a DNS record in the list by its name (exact match).
    Return the record dict or None if not found.
    """
    for r in records:
        if r["name"] == hostname:
            return r
    return None


def main():
    # ------------------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------------------
    # OPNsense parameters
    opn_url = os.getenv("OPN_API_URL", "https://opnsense.lo.madloba.org")
    opn_key = os.getenv("OPN_API_KEY", "SECRET")  # Replace with your actual token
    opn_secret = os.getenv("OPN_API_SECRET", "SECRET")  # Replace with your actual token
    opn_interfaces = os.getenv("OPN_INTERFACES", "opt1").split(",")
    opn_verify = bool(int(os.getenv("OPN_VERIFY", "1")))

    # Cloudflare parameters
    cf_token = os.getenv("CF_API_TOKEN", "YOUR_CLOUDFLARE_API_TOKEN")
    cf_zone_name = os.getenv("CF_ZONE", "madloba.org")  # e.g. "example.com"
    cf_subdomain = os.getenv(
        "CF_SUBDOMAIN", "lo"
    )  # e.g. "private" -> "private.example.com"

    # ------------------------------------------------------------------------------
    # Step 1: Get DHCP leases from OPNsense
    # ------------------------------------------------------------------------------
    print("Fetching DHCP leases from OPNsense...")
    leases = get_opn_dhcp_leases(opn_url, (opn_key, opn_secret), opn_interfaces, opn_verify)
    print(f"Found {len(leases)} DHCP lease(s).")

    # ------------------------------------------------------------------------------
    # Step 2: Get current DNS records from Cloudflare (for specified subdomain from zone)
    # ------------------------------------------------------------------------------
    print("Initializing Cloudflare client...")
    cf = Cloudflare(api_token=cf_token)

    print(f"Looking up zone ID for '{cf_zone_name}'...")
    zone_id = get_cf_zone_id(cf, cf_zone_name)

    print(f"Fetching DNS records for zone '{cf_zone_name}'...")
    existing_records = get_cf_dns_records(cf, zone_id, cf_subdomain+"."+cf_zone_name)
    print(f"Found {len(existing_records)} DNS record(s) for subdomain filter.")

    # ------------------------------------------------------------------------------
    # Step 3 & 4: Compare DHCP leases and DNS records; remove old or mismatched records
    # ------------------------------------------------------------------------------
    to_remove = []
    to_add = []
    to_update = []

    # Build a lookup for current DHCP info: name -> IP
    # The FQDN we create: "{hostname}.{cf_zone_name}" or maybe subdomain-based: "{hostname}.{cf_subdomain}.{cf_zone_name}"
    # Adjust as needed based on your desired naming scheme.
    # Let's assume we want "hostname.subdomain.zone"
    dhcp_lookup = {}
    for lease in leases:
        # Example FQDN
        if cf_subdomain:
            fqdn = f"{lease['hostname']}.{cf_subdomain}.{cf_zone_name}"
        else:
            fqdn = f"{lease['hostname']}.{cf_zone_name}"
        dhcp_lookup[fqdn.lower()] = lease["address"]

    # Check existing DNS records:
    for record in existing_records:
        # record["name"] is the FQDN in Cloudflare
        existing_fqdn = record.name.lower()
        if existing_fqdn in dhcp_lookup:
            # If IP differs, we'll update
            if record.content != dhcp_lookup[existing_fqdn]:
                to_update.append(
                    {
                        "id": record.id,
                        "name": existing_fqdn,
                        "old_ip": record.content,
                        "new_ip": dhcp_lookup[existing_fqdn],
                    }
                )
            # Mark that we've seen this record, so we won't add it later
            dhcp_lookup.pop(existing_fqdn)
        else:
            # Not found in DHCP => remove
            # to_remove.append(
            #     {"id": record["id"], "name": record["name"], "ip": record["content"]}
            # )
            pass

    # Now whatever remains in dhcp_lookup are new records to be added
    for fqdn, ip_addr in dhcp_lookup.items():
        to_add.append({"name": fqdn, "ip": ip_addr})

    # ------------------------------------------------------------------------------
    # Step 4 (remove old DNS records)
    # ------------------------------------------------------------------------------
    print("\nChanges to be made:")
    print("-------------------------------------------")
    summary = {"removed": [], "updated": [], "added": []}

    # Remove old DNS records
    for record in to_remove:
        print(f"Removing DNS record: {record['name']} -> {record['ip']}")
        try:
            cf.dns.records.delete(record["id"], zone_id=zone_id)
            summary["removed"].append(record["name"])
        except Exception as e:
            print(f"Error removing DNS record {record['name']}: {str(e)}")

    # ------------------------------------------------------------------------------
    # Step 4 (update mismatched DNS records)
    # ------------------------------------------------------------------------------
    for record in to_update:
        print(
            f"Updating DNS record: {record['name']} from {record['old_ip']} to {record['new_ip']}"
        )
        dns_data = {
            "type": "A",
            "name": record["name"],
            "content": record["new_ip"],
            "ttl": 120,
        }
        try:
            cf.dns.records.update(record["id"], zone_id=zone_id, name=dns_data["name"], content=dns_data["content"], ttl=dns_data["ttl"], type=dns_data["type"], proxied=False, comment="@managed by auto-sync script")
            summary["updated"].append(record["name"])
        except Exception as e:
            print(f"Error updating DNS record {record['name']}: {str(e)}")

    # ------------------------------------------------------------------------------
    # Step 5: Add new DNS records
    # ------------------------------------------------------------------------------
    for new_r in to_add:
        print(f"Adding DNS record: {new_r['name']} -> {new_r['ip']}")
        dns_data = {
            "type": "A",
            "name": new_r["name"],
            "content": new_r["ip"],
            "ttl": 120,
        }
        try:
            cf.dns.records.create(zone_id=zone_id, name=dns_data["name"], content=dns_data["content"], ttl=dns_data["ttl"], type=dns_data["type"], proxied=False, comment="@managed by auto-sync script")
            summary["added"].append(new_r["name"])
        except Exception as e:
            print(f"Error adding DNS record {new_r['name']}: {str(e)}")

    # ------------------------------------------------------------------------------
    # Step 6: Output summary of changes
    # ------------------------------------------------------------------------------
    print("\nSummary of changes:")
    print("-------------------------------------------")
    print(f"Removed records ({len(summary['removed'])}): {summary['removed']}")
    print(f"Updated records ({len(summary['updated'])}): {summary['updated']}")
    print(f"Added records ({len(summary['added'])}): {summary['added']}")


if __name__ == "__main__":
    main()
