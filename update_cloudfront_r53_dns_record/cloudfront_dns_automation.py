#!/usr/bin/env python3
"""
CloudFront CNAME Swap DNS Automation Script

Original Author: Trevor Henning (hthennin)
Enhanced Version: Derived from Trevor's original work with additional features

This script monitors a CloudFront distribution for a CNAME swap and automatically
updates the corresponding Route 53 DNS record to minimize downtime. It supports
both IPv4 (A) and IPv6 (AAAA) records based on the CloudFront distribution configuration.

Enhancements include:
- IPv6 support with automatic A and AAAA record handling
- Domain validation against actual CloudFront distribution
- API rate limiting protection with jitter
- Comprehensive input validation and error handling
- UPSERT operations for safer DNS updates

Usage:
    python3 cloudfront_dns_automation.py <new-distribution-id> <route53-hosted-zone-id> 
                                        <new-cloudfront-domain> <alias-alternate-name>

Example:
    python3 cloudfront_dns_automation.py EZDLMTR1D3MHD Z00646902JW6C5QG3Q2NG 
                                        d2mz62fpvuge8k.cloudfront.net. 
                                        www.example.com
"""

import boto3
import json
import sys
import time
import random

session = boto3.Session()
r53 = session.client('route53')
cf = session.client('cloudfront')
sts = session.client('sts')  # to assume a role if needed


def validate_inputs(cloudfront_id, hosted_zone_id, new_domain, alias):
    """
    Validate all input parameters before processing.

    Args:
        cloudfront_id (str): CloudFront distribution ID
        hosted_zone_id (str): Route 53 hosted zone ID
        new_domain (str): New CloudFront domain name
        alias (str): DNS alias name

    Raises:
        ValueError: If any parameter is invalid
    """
    errors = []

    # Check if CloudFront distribution ID exists and is non-empty
    if not cloudfront_id or not isinstance(cloudfront_id, str) or not cloudfront_id.strip():
        errors.append(
            "CloudFront distribution ID is required and must be a non-empty string")

    # Check if Route 53 hosted zone ID exists and is non-empty
    if not hosted_zone_id or not isinstance(hosted_zone_id, str) or not hosted_zone_id.strip():
        errors.append(
            "Route 53 hosted zone ID is required and must be a non-empty string")

    # Check if new domain exists and is non-empty
    if not new_domain or not isinstance(new_domain, str) or not new_domain.strip():
        errors.append(
            "New CloudFront domain is required and must be a non-empty string")

    # Check if alias exists and is non-empty
    if not alias or not isinstance(alias, str) or not alias.strip():
        errors.append("DNS alias is required and must be a non-empty string")

    if errors:
        error_message = "Input validation failed:\n" + \
            "\n".join(f"- {error}" for error in errors)
        raise ValueError(error_message)

    return True


def checkAlias(cloudfrontID, alias, expected_domain):
    response = cf.get_distribution(Id=cloudfrontID)

    # Validate that the expected domain matches the actual CloudFront domain
    actual_domain = response["Distribution"]["DomainName"]
    print(f"CloudFront distribution domain: {actual_domain}")

    if expected_domain.rstrip('.') != actual_domain.rstrip('.'):
        raise ValueError(
            f"Domain mismatch: Expected '{expected_domain}' but distribution has '{actual_domain}'")

    # Safely get aliases with proper error handling
    try:
        aliases = response["Distribution"]["DistributionConfig"]["Aliases"]["Items"]
    except KeyError:
        aliases = []

    # Handle case where aliases can be empty or None
    if aliases:
        print(f"Current aliases: {aliases}")
    else:
        print("No aliases currently configured")

    while not aliases or alias not in aliases:
        # Add jitter and delay -- too much of delay will result in a delayed DNS update. 
        base_delay = 3  # Base delay of 3 seconds
        jitter = random.uniform(0, 5)  # Random jitter between 0-5 seconds
        total_delay = base_delay + jitter

        print(f"Waiting {total_delay:.1f} seconds before next check...")
        time.sleep(total_delay)

        response = cf.get_distribution(Id=cloudfrontID)

        # Safely get aliases in the loop as well
        try:
            aliases = response["Distribution"]["DistributionConfig"]["Aliases"]["Items"]
        except KeyError:
            aliases = []

        if not aliases:
            print("Waiting for aliases to be configured...")
        elif alias not in aliases:
            print(
                f"Waiting for alias '{alias}' to be added. Current aliases: {aliases}")

    # Check IPv6 status
    ipv6_enabled = response["Distribution"]["DistributionConfig"].get(
        "IsIPV6Enabled", False)
    print(f"IPv6 enabled: {ipv6_enabled}")

    return ipv6_enabled


def updateRecord(hostedzoneID, new_domain, alias, ipv6_enabled=False):
    # To assume a role to update a record or all an API in another account, please follow our guides here:
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-api.html

    # For example, please see the below sample process to assume a role to make a call in Route 53
    # 1. assume role
    # sts_response = sts.assume_role(RoleArn="role-ARN-here", RoleSessionName="session-name-here")
    # temp_credentials = sts_response["Credentials"]

    # 2. Create r53 resource w/ new credentials
    # r53_resource = boto3.resource(
    #    "route53",
    #    aws_access_key_id=temp_credentials["AccessKeyId"],
    #    aws_secret_access_key=temp_credentials["SecretAccessKey"],
    #    aws_session_token=temp_credentials["SessionToken"],
    # )
    # 3. Call the below call w/ new r53 resource, for ex: use r53_resource.change_resource_record_sets, instead of the below r53.change_resource_record_sets

    changes = [
        {
            'Action': 'UPSERT',
            'ResourceRecordSet': {
                'Name': alias,
                'Type': 'A',
                'AliasTarget': {
                    'HostedZoneId': 'Z2FDTNDATAQYW2',
                    'DNSName': new_domain,
                    'EvaluateTargetHealth': False
                }
            }
        }
    ]

    # Add IPv6 records if enabled
    if ipv6_enabled:
        print("Adding IPv6 (AAAA) records...")
        changes.append({
            'Action': 'UPSERT',
            'ResourceRecordSet': {
                'Name': alias,
                'Type': 'AAAA',
                'AliasTarget': {
                    'HostedZoneId': 'Z2FDTNDATAQYW2',
                    'DNSName': new_domain,
                    'EvaluateTargetHealth': False
                }
            }
        })

    response = r53.change_resource_record_sets(
        HostedZoneId=hostedzoneID,
        ChangeBatch={
            'Comment': 'CloudFront CNAME swap with IPv4 and IPv6 support',
            'Changes': changes
        }
    )


def main():
    # Check if correct number of arguments provided
    if len(sys.argv) != 5:
        print("Error: Incorrect number of arguments provided.")
        print("\nUsage:")
        print("    python3 cloudfront_dns_automation.py <new-distribution-id> <route53-hosted-zone-id>")
        print("                                        <new-cloudfront-domain> <alias-alternate-name>")
        print("\nExample:")
        print(
            "    python3 cloudfront_dns_automation.py EZDLMTR1D3MHD Z00646902JW6C5QG3Q2NG")
        print("                                        d2mz62fpvuge8k.cloudfront.net.")
        print("                                        www.example.com")
        sys.exit(1)

    try:
        cloudfrontID = sys.argv[1]
        hostedzoneID = sys.argv[2]
        new_domain = sys.argv[3]
        alias = sys.argv[4]

        # Validate all input parameters
        validate_inputs(cloudfrontID, hostedzoneID, new_domain, alias)

        print("All required parameters exist. Starting CloudFront monitoring...")
        print(f"Monitoring distribution: {cloudfrontID}")
        print(
            f"Validating domain and waiting for alias '{alias}' to be available...")

        ipv6_enabled = checkAlias(cloudfrontID, alias, new_domain)

        if ipv6_enabled:
            print("Alias found! Updating DNS records (IPv4 and IPv6)...")
        else:
            print("Alias found! Updating DNS record (IPv4 only)...")

        updateRecord(hostedzoneID, new_domain, alias, ipv6_enabled)

        if ipv6_enabled:
            print("DNS records updated! (A and AAAA records)")
        else:
            print("DNS record updated! (A record only)")

    except ValueError as e:
        print(f"Validation Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
