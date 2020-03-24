import argparse
import boto3
import json
import time

parser = argparse.ArgumentParser(description='Apply staging CF distribution config to production distribution.')
parser.add_argument('settingfile', action='store', help='Production specific settings.')
parser.add_argument('stgid', action='store', help='Staging Distribution ID.')
parser.add_argument('prdid', action='store', default='', nargs='?', help='Production Distribution ID. New Distribution will be created if no prdid is given.')

args = parser.parse_args()

#read setting json file
file = open(args.settingfile)
prod = json.load(file)
file.close()

# load staging distribution
cf_client = boto3.client("cloudfront")
stg_config = cf_client.get_distribution_config(Id=args.stgid)
dc=stg_config['DistributionConfig']
dc.update(prod)

if args.prdid:
    prd_config = cf_client.get_distribution_config(Id=args.prdid)
    Etag = prd_config['ETag']
    dc['CallerReference'] = prd_config['DistributionConfig']['CallerReference']
    print('updating...')
    result = cf_client.update_distribution(DistributionConfig=dc, Id=args.prdid, IfMatch=Etag)
    print('Done')
    
else:
    dc['CallerReference'] = '%d' % (time.time(),)
    print('creating...')
    result = cf_client.create_distribution(DistributionConfig=dc)
    print('Done')

