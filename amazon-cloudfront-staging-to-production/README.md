# cloudfront-staging-to-production
Replicate one Amazon CloudFront Distribution config to another. 
Major use case for this is creating a staging CF Distribution, test/experiment features and push that to production Distribution.
based on python3 and boto3.

Usage: python3 cloudfront-staging-to-production.py <settings.json> <source(staging) CF Distribution ID> [destination(production) CF Distribution ID]

Regarding the settings.json:
example1.json shows changing only Alt name and access log setting.
example2.json shows different TLS cert between staging and production distribution.
