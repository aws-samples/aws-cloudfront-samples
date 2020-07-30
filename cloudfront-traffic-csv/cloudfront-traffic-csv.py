import boto3
import argparse
import datetime, dateutil

#GLOBAL_SETTINGS
timezone = datetime.timezone(datetime.timedelta(hours=0)) #UTC +0, this should be set accordingly.

#global resource to connect API
cf_client = boto3.client('cloudfront')

def get_cname(distribution):
    '''
    returns 1st CNAME alias or '' if not found
    '''
    return distribution['Aliases']['Items'][0] if distribution['Aliases']['Quantity'] > 0 else ''

def get_tag(arn,tag_key):
    '''
    returns given tag value of resource, or '' if not found
    '''
    tags = cf_client.list_tags_for_resource(Resource=arn)
    result = ''
    if len(tags['Tags']['Items']) != 0:
        for tag in tags['Tags']['Items']:
            if tag['Key'] == tag_key:
                result = tag['Value']
    
    return result
 
def get_traffic_csv_list(start_date, end_date, metric_name, reporting_tag=''):
    '''
    returns all CF distribution's Cloudwatch metric, as list of comma separated values.
    '''

    #first load all distributions
    distributions = cf_client.list_distributions()['DistributionList']['Items']

    #prepare metric query
    metric_data_queries = []

    for dist in distributions:
        metric_data_queries.append({
            'Id': 'm_'+dist['Id'],
            'Label': '%s,%s' % (dist['Id'], get_cname(dist), ) + (',%s' % (get_tag(dist['ARN'],reporting_tag), ) if reporting_tag else ''),
            'MetricStat': {
                'Metric': {
                    'MetricName': metric_name,
                    'Namespace': 'AWS/CloudFront',
                    'Dimensions': [
                        {'Name': 'DistributionId', 'Value': dist['Id']},
                        {'Name': 'Region', 'Value': 'Global'}
                    ]
                },
                'Period': 86400,
                'Stat': 'Sum',
                'Unit': 'None'
            }
        })

    #call Cloudwatch get_metric_data
    cw_client = boto3.client('cloudwatch', region_name='us-east-1')
    result = cw_client.get_metric_data(MetricDataQueries=metric_data_queries, StartTime=start_date, EndTime=end_date)

    #result csv
    csv=['Distribution Id, CNAME, ' + ('Tag, ' if reporting_tag else '') + 'Date, '+metric_name]
    for r in result['MetricDataResults']:
        for i in range(len(r['Timestamps'])):
            csv.append('%s,%s,%f' % (r['Label'],r['Timestamps'][i].astimezone().strftime('%Y-%m-%d'), r['Values'][i],))

    return csv

if __name__ == '__main__':
    #define command arguments
    parser = argparse.ArgumentParser(description='Read CloudWatch Metric of all CloudFront distribution')
    parser.add_argument('startdate', action='store', type=lambda x: datetime.datetime.strptime(x, '%Y-%m-%d').replace(tzinfo=timezone),
        help='Start date of data period, YYYY-MM-DD.')
    parser.add_argument('enddate', action='store', type=lambda x: datetime.datetime.strptime(x+' 23:59:59', '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone), 
        help='End date of data period, YYYY-MM-DD.')
    parser.add_argument('-m','--metric', default='BytesDownloaded', choices=['BytesDownloaded','Requests', 'BytesUploaded'],
        help='Reporting metric, default is BytesDownloaded')
    parser.add_argument('-t','--tag', help='Reporting Tag key')

    args = parser.parse_args()

    #call functions
    csv_list = get_traffic_csv_list(args.startdate, args.enddate, args.metric, args.tag)

    for line in csv_list:
        print(line)