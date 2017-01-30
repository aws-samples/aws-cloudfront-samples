'''
Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/apache2.0/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
'''

import boto3
import hashlib
import json
import urllib2

# Name of the service, as seen in the ip-groups.json file, to extract information for
SERVICE = "CLOUDFRONT"
# Ports your application uses that need inbound permissions from the service for
INGRESS_PORTS = { 'Http' : [80,80], 'Https': [443,443], '80-443' : [80,443] }
# Tags which identify the security groups you want to update
SECURITY_GROUP_TAG_FOR_HTTP = { 'Name': 'cloudfront', 'AutoUpdate': 'true', 'Protocol': 'http' }
SECURITY_GROUP_TAG_FOR_HTTPS = { 'Name': 'cloudfront', 'AutoUpdate': 'true', 'Protocol': 'https' }
SECURITY_GROUP_TAG_FOR_80_443 = { 'Name': 'cloudfront', 'AutoUpdate': 'true', 'PortRange': '80-443' }

def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, indent=2))
    message = json.loads(event['Records'][0]['Sns']['Message'])

    # Load the ip ranges from the url
    ip_ranges = json.loads(get_ip_groups_json(message['url'], message['md5']))

    # extract the service ranges
    cf_ranges = get_ranges_for_service(ip_ranges, SERVICE)

    # update the security groups
    result = update_security_groups(cf_ranges)

    return result

def get_ip_groups_json(url, expected_hash):
    print("Updating from " + url)

    response = urllib2.urlopen(url)
    ip_json = response.read()

    m = hashlib.md5()
    m.update(ip_json)
    hash = m.hexdigest()

    if hash != expected_hash:
        raise Exception('MD5 Mismatch: got ' + hash + ' expected ' + expected_hash)

    return ip_json

def get_ranges_for_service(ranges, service):
    service_ranges = list()
    for prefix in ranges['prefixes']:
        if prefix['service'] == service:
            print('Found ' + service + ' range: ' + prefix['ip_prefix'])
            service_ranges.append(prefix['ip_prefix'])

    return service_ranges

def update_security_groups(new_ranges):
    client = boto3.client('ec2')

    http_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_HTTP)
    print ('Found ' + str(len(http_group)) + ' HttpSecurityGroups to update')

    https_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_HTTPS)
    print ('Found ' + str(len(https_group)) + ' HttpsSecurityGroups to update')

    range_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_80_443)
    print ('Found ' + str(len(range_group)) + ' PortRange (80-443) SecurityGroups to update')

    result = list()
    http_updated = 0
    https_updated = 0
    range_updated = 0
    for group in http_group:
        if update_security_group(client, group, new_ranges, INGRESS_PORTS['Http'][0], INGRESS_PORTS['Http'][1]):
            http_updated += 1
            result.append('Updated ' + group['GroupId'])
    for group in https_group:
        if update_security_group(client, group, new_ranges, INGRESS_PORTS['Https'][0], INGRESS_PORTS['Https'][1]):
            https_updated += 1
            result.append('Updated ' + group['GroupId'])
    for group in range_group:
        if update_security_group(client, group, new_ranges, INGRESS_PORTS['80-443'][0], INGRESS_PORTS['80-443'][1]):
            range_updated += 1
            result.append('Updated ' + group['GroupId'])

    result.append('Updated ' + str(http_updated) + ' of ' + str(len(http_group)) + ' HttpSecurityGroups')
    result.append('Updated ' + str(https_updated) + ' of ' + str(len(https_group)) + ' HttpsSecurityGroups')
    result.append('Updated ' + str(range_updated) + ' of ' + str(len(range_group)) + ' PortRange (80-443) SecurityGroups')

    return result

def update_security_group(client, group, new_ranges, fromPort, toPort ):
    added = 0
    removed = 0

    if len(group['IpPermissions']) > 0:
        for permission in group['IpPermissions']:
            if permission['FromPort'] <= fromPort and permission['ToPort'] >= toPort :
                old_prefixes = list()
                to_revoke = list()
                to_add = list()
                for range in permission['IpRanges']:
                    cidr = range['CidrIp']
                    old_prefixes.append(cidr)
                    if new_ranges.count(cidr) == 0:
                        to_revoke.append(range)
                        print(group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))

                for range in new_ranges:
                    if old_prefixes.count(range) == 0:
                        to_add.append({ 'CidrIp': range })
                        print(group['GroupId'] + ": Adding " + range + ":" + str(permission['ToPort']))

                removed += revoke_permissions(client, group, permission, to_revoke)
                added += add_permissions(client, group, permission, to_add)
    else:
        to_add = list()
        for range in new_ranges:
            to_add.append({ 'CidrIp': range })
            print(group['GroupId'] + ": Adding " + range + ":" + str(fromPort) + "-" + str(toPort))
        permission = { 'ToPort': toPort, 'FromPort': fromPort, 'IpProtocol': 'tcp'}
        added += add_permissions(client, group, permission, to_add)

    print (group['GroupId'] + ": Added " + str(added) + ", Revoked " + str(removed))
    return (added > 0 or removed > 0)

def revoke_permissions(client, group, permission, to_revoke):
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_revoke,
            'IpProtocol': permission['IpProtocol']
        }

        client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[revoke_params])

    return len(to_revoke)

def add_permissions(client, group, permission, to_add):
    if len(to_add) > 0:
        add_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_add,
            'IpProtocol': permission['IpProtocol']
        }

        client.authorize_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[add_params])

    return len(to_add)

def get_security_groups_for_update(client, security_group_tag):
    filters = list();
    for key, value in security_group_tag.iteritems():
        filters.extend(
            [
                { 'Name': "tag-key", 'Values': [ key ] },
                { 'Name': "tag-value", 'Values': [ value ] }
            ]
        )

    response = client.describe_security_groups(Filters=filters)

    return response['SecurityGroups']

'''
Sample Event From SNS:

{
  "Records": [
    {
      "EventVersion": "1.0",
      "EventSubscriptionArn": "arn:aws:sns:EXAMPLE",
      "EventSource": "aws:sns",
      "Sns": {
        "SignatureVersion": "1",
        "Timestamp": "1970-01-01T00:00:00.000Z",
        "Signature": "EXAMPLE",
        "SigningCertUrl": "EXAMPLE",
        "MessageId": "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
        "Message": "{\"create-time\": \"yyyy-mm-ddThh:mm:ss+00:00\", \"synctoken\": \"0123456789\", \"md5\": \"03a8199d0c03ddfec0e542f8bf650ee7\", \"url\": \"https://ip-ranges.amazonaws.com/ip-ranges.json\"}",
        "Type": "Notification",
        "UnsubscribeUrl": "EXAMPLE",
        "TopicArn": "arn:aws:sns:EXAMPLE",
        "Subject": "TestInvoke"
      }
    }
  ]
}

'''
