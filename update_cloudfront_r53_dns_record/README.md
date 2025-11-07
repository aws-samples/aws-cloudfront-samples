# CloudFront CNAME Swap DNS Automation Script

**Original Author:** Trevor Henning (hthennin)  
**Enhanced Version:** Derived from Trevor's original work with additional features and improvements

## Overview

This Python automation script **significantly reduces downtime** for CloudFront CNAME migrations by automatically updating DNS records the moment AWS Support completes a CNAME swap. The script monitors a CloudFront distribution for alias changes and automatically updates Route 53 DNS records with comprehensive IPv4 and IPv6 support.

**Key Features:**
- ✅ **Minimized downtime** - Eliminates manual coordination delays between CNAME swap and DNS updates
- ⚡ **Instant response** - Automated detection and DNS updates within seconds of alias availability
- 🔄 **Continuous monitoring** - Polls CloudFront distribution with API-friendly jitter
- 🛡️ **TLS protection** - Prevents certificate errors during transitions
- 🌐 **IPv6 support** - Automatically handles both A and AAAA records
- 🔍 **Domain validation** - Ensures provided domain matches actual CloudFront distribution
- 📊 **Comprehensive validation** - Input parameter validation and error handling

## When to Use This Script

This script is specifically designed for scenarios where **AWS Support is moving an alternate domain name** between CloudFront distributions. According to AWS documentation, there are [multiple options for moving alternate domain names](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/alternate-domain-names-move-options.html#alternate-domain-names-move-contact-support), and this automation is useful when you need to **contact AWS Support** to perform the move.

**Use this script when:**
- You need AWS Support to move an alternate domain name between distributions
- The alternate domain name is currently in use and cannot be temporarily removed
- You want to minimize downtime during the migration process
- You want to automate the DNS update process after AWS Support completes the CNAME swap


For more details on when AWS Support assistance is required, see: [Contact AWS Support to move an alternate domain name](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/alternate-domain-names-move-options.html#alternate-domain-names-move-contact-support)

## Problem Statement

When AWS Support performs a CNAME swap between CloudFront distributions, TLS connections break immediately after the swap until the customer updates their DNS record to point to the new distribution. This creates downtime that can be problematic for applications with strict uptime requirements.

## Lower Downtime during alternate domain updates

This **Python-powered automation** simplfies CNAME migration, lowers the downtime and eliminates manual errors:

1. **Parameter Validation** - Validates all required parameters exist and are non-empty
2. **Domain Verification** - Confirms the provided CloudFront domain matches the actual distribution
3. **Real-time Monitoring** - Continuously polls (with delay and jitter) the target CloudFront distribution for alias changes
4. **IPv6 Detection** - Automatically detects if IPv6 is enabled on the distribution
5. **Instant Detection** - Identifies the moment AWS Support completes the CNAME swap
6. **Automated DNS Updates** - Immediately updates Route 53 records (A and/or AAAA) using UPSERT operations


## Prerequisites

- Python 3.x
- AWS SDK for Python (Boto3)
- Appropriate AWS credentials configured
- IAM permissions for CloudFront and Route 53 operations

## Installation

```bash
pip install boto3
```

## Usage

Run the script from the command line with the following parameters:

```bash
python3 cloudfront_dns_automation.py <new-distribution-id> <route53-hosted-zone-id> <new-cloudfront-domain> <alias-alternate-name>
```

### Parameters

- `new-distribution-id`: CloudFront distribution ID to monitor
- `route53-hosted-zone-id`: Route 53 hosted zone ID containing the DNS record
- `new-cloudfront-domain`: CloudFront domain name (e.g., d2mz62fpvuge8k.cloudfront.net)
- `alias-alternate-name`: DNS alias to update (e.g., www.example.com)

### Example

```bash
python3 cloudfront_dns_automation.py EZDLMTR1D3MHD Z00646902JW6C5QG3Q2NG d2mz62fpvuge8k.cloudfront.net. www.example.com
```

## Script Behavior

### Validation Phase
- Checks that all required parameters are provided and non-empty
- Validates the CloudFront domain matches the actual distribution domain
- Displays IPv6 status of the distribution

### Monitoring Phase
- Polls the CloudFront distribution every 3-8 seconds (with random jitter)
- Waits for the specified alias to appear in the distribution's aliases
- Provides clear status messages during the wait

### Update Phase
- Creates/updates DNS records using UPSERT operations
- Handles both IPv4 (A) and IPv6 (AAAA) records based on distribution configuration
- Provides confirmation of record types updated

## IPv6 Support

The script automatically detects if IPv6 is enabled on the CloudFront distribution:

- **IPv6 Disabled**: Creates only A (IPv4) records
- **IPv6 Enabled**: Creates both A (IPv4) and AAAA (IPv6) records

Both record types point to the same CloudFront domain and use the CloudFront hosted zone ID (Z2FDTNDATAQYW2).

## API Protection

To protect the CloudFront API from rate limiting:
- Base delay of 3 seconds between API calls
- Random jitter of 0-5 seconds added to each delay
- Total delay ranges from 3-8 seconds between requests
- Prevents thundering herd problems when multiple instances run

## Cross-Account Support

The script includes commented examples for assuming IAM roles when CloudFront distributions or Route 53 hosted zones are in different AWS accounts. Uncomment and modify the role assumption code as needed.

## Error Handling

- **Parameter validation**: Clear error messages for missing or invalid parameters
- **Domain mismatch**: Fails fast if provided domain doesn't match distribution
- **API errors**: Graceful handling of AWS API exceptions
- **Missing aliases**: Handles distributions without alias configuration

## Downtime Reduction Considerations

- **Reduced Downtime**: This automation significantly reduces downtime by eliminating manual coordination delays
- **DNS Propagation**: The primary remaining downtime is due to global DNS propagation (typically 1-2 minutes)
- **Instant DNS Updates**: The script updates DNS records within seconds of alias availability
- **Maintenance Windows**: Enables CNAME swaps with minimal downtime impact
- **Continuous Operation**: The script runs continuously until the swap is detected
- **Production Ready**: Designed for high-availability applications seeking to minimize downtime
- **UPSERT Operations**: Uses UPSERT instead of DELETE/CREATE for safer DNS updates

## References

- [Moving an alternate domain name to a different distribution](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/alternate-domain-names-move.html#alternate-domain-names-move-options)
- [Contact AWS Support to move an alternate domain name](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/alternate-domain-names-move-options.html#alternate-domain-names-move-contact-support)
- [AWS IAM Role Switching](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-api.html)

## Support

This script is provided as a reference implementation. Customers should test thoroughly in their environment and modify as needed for their specific use case.