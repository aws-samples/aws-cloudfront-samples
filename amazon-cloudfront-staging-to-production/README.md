# cloudfront-staging-to-production
This is a command line tool for replicating one CloudFront distribution to new or existing one.  
It is recommended to have a production and staging environment separated as a best practice, and you can use this script to apply changes of your staging CF distribution to production.  

## Setup
You need to have a JSON file that defines environment variables, all of them are optional but highly recommended to have:
  - Aliases: Host name for production domain. *Please note that CloudFront you cannot use same Alias to more than one CloudFront distribution and API call will fail.*
  - Comment: This is shown when you go to CloudFront console
  - Logging: Define S3 bucket and prefix
  - ViewerCertificate: ACM certificate arn

*example:*
```yaml
{
    "Aliases": {"Quantity": 1, "Items": ["www.example.com"]},
    "Comment": "production distribution for www.example.com",
    "Logging": {
        "Enabled": true,
        "IncludeCookies": false,
        "Bucket": "loggingbucket.s3.amazonaws.com",
        "Prefix": "examplecom-log" },
    "ViewerCertificate": {
        "ACMCertificateArn": "<arn:aws:acm:us-east-1:....>",
        "SSLSupportMethod": "sni-only",
        "MinimumProtocolVersion": "TLSv1.2_2018",
        "Certificate": "<arn:aws:acm:us-east-1:....>",
        "CertificateSource": "acm"
    }
}
```

#### Usage
```
python3 cloudfront-staging-to-production.py <settings.json> <source(staging) CF distribution ID> [destination(production) CF distribution ID]
```
*example: to create new CF distribution from E300AABBCCDDEE*
```
python3 cloudfront-staging-to-production.py www.json E300AABBCCDDEE  
```
*example: update existing CF distribution E499ZZXXYYDDEE with E300AABBCCDDEE config*

```
python3 cloudfront-staging-to-production.py www.json E300AABBCCDDEE E499ZZXXYYDDEE
```