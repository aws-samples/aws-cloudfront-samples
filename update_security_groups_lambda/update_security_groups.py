'''
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.


Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at


    http://aws.amazon.com/apache2.0/


or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
'''

# Ports your application uses that need inbound permissions from the service for
INGRESS_PORTS = { 'http' : 80, 'https': 443, 'example': 8080 }
# Tags which identify the security groups you want to update
# For a group to be updated it will need to have 3 properties that are true:
# 1. It has to be tagged 'Protocol: X' (Where 'X' is one of your INGRESS_PORTS above)
# 2. It has to be tagged 'Name: cloudfront_g' or 'Name: cloudfront_r'
# 3. It has to be tagged 'AutoUpdate: true'
# If any of these 3 are not true, the security group will be unmodified.
GLOBAL_SG_TAGS = { 'Name': 'cloudfront_g', 'AutoUpdate': 'true' }
REGION_SG_TAGS = { 'Name': 'cloudfront_r', 'AutoUpdate': 'true' }

import boto3
import hashlib
import json
import logging
import urllib.request, urllib.error, urllib.parse
import os

def lambda_handler(event, context):
    global logger
    logger.setLevel(logging.CRITICAL)

    # Set the environment variable DEBUG to 1 if you want verbose debug details in CloudWatch Logs.
    try:
        if bool(strtobool(os.environ.get('DEBUG', ''))):
            logger.setLevel(logging.DEBUG)
    except ValueError:
        pass
    

    # If you want a different service, set the SERVICE environment variable.
    # It defaults to CLOUDFRONT. Using 'jq' and 'curl' get the list of possible
    # services like this:
    # curl -s 'https://ip-ranges.amazonaws.com/ip-ranges.json' | jq -r '.prefixes[] | .service' ip-ranges.json | sort -u 
    SERVICE = os.getenv( 'SERVICE', "CLOUDFRONT")
    
    logger.debug(("Received event: " + json.dumps(event, indent=2)))
    message = json.loads(event['Records'][0]['Sns']['Message'])

    # Load the ip ranges from the url
    ip_ranges = json.loads(get_ip_groups_json(message['url'], message['md5']))

    # Extract the service ranges
    global_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "GLOBAL")
    region_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "REGION")

    # Update the security groups
    result = update_security_groups(global_cf_ranges, "GLOBAL")
    result = result + update_security_groups(global_cf_ranges, "REGION")
    
    return result


def get_ip_groups_json(url, expected_hash):
    global logger

    logger.debug("Updating from " + url)

    response = urllib.request.urlopen(url)
    ip_json = response.read()

    m = hashlib.md5()
    m.update(ip_json)
    hash = m.hexdigest()

    if hash != expected_hash:
        raise Exception('MD5 Mismatch: got ' + hash + ' expected ' + expected_hash)

    return ip_json

def get_ranges_for_service(ranges, service, subset):
    global logger

    service_ranges = list()
    for prefix in ranges['prefixes']:
        if prefix['service'] == service and ((subset == prefix['region'] and subset == "GLOBAL") or (subset != 'GLOBAL' and prefix['region'] != 'GLOBAL')):
            logger.debug(('Found ' + service + ' region: ' + prefix['region'] + ' range: ' + prefix['ip_prefix']))
            service_ranges.append(prefix['ip_prefix'])

    return service_ranges

def update_security_groups(new_ranges, rangeType):
    global logger

    client = boto3.client('ec2')
    
    # All the security groups we will need to find.
    allSGs = INGRESS_PORTS.keys()
    # Iterate over every group, doing its global and regional versions
    for curGroup in allSGs:
        tagToFind = {}
        if rangeType == "GLOBAL":
            tagToFind = GLOBAL_SG_TAGS
        else:
            tagToFind = REGION_SG_TAGS    
        tagToFind['Protocol'] = curGroup
        rangeToUpdate = get_security_groups_for_update(client, tagToFind)        
        logger.debug('Found {} groups tagged {}, proto {} to update'.format(
                str(len(rangeToUpdate)),
                tagToFind["Name"],
                curGroup))

        result = list()
        
        if update_security_group(client, rangeToUpdate[0], new_ranges, INGRESS_PORTS[curGroup] ):
            result.append('Updated ' + rangeToUpdate[0]['GroupId'])

    return result


def update_security_group(client, group, new_ranges, port):
    added = 0
    removed = 0
    global logger

    if len(group['IpPermissions']) > 0:
        for permission in group['IpPermissions']:
            if permission['FromPort'] <= port and permission['ToPort'] >= port:
                old_prefixes = list()
                to_revoke = list()
                to_add = list()
                for range in permission['IpRanges']:
                    cidr = range['CidrIp']
                    old_prefixes.append(cidr)
                    if new_ranges.count(cidr) == 0:
                        to_revoke.append(range)
                        logger.debug((group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort'])))

                for range in new_ranges:
                    if old_prefixes.count(range) == 0:
                        to_add.append({ 'CidrIp': range })
                        logger.debug((group['GroupId'] + ": Adding " + range + ":" + str(permission['ToPort'])))

                removed += revoke_permissions(client, group, permission, to_revoke)
                added += add_permissions(client, group, permission, to_add)
    else:
        to_add = list()
        for range in new_ranges:
            to_add.append({ 'CidrIp': range })
            logger.debug((group['GroupId'] + ": Adding " + range + ":" + str(port)))
        permission = { 'ToPort': port, 'FromPort': port, 'IpProtocol': 'tcp'}
        added += add_permissions(client, group, permission, to_add)

    logger.debug((group['GroupId'] + ": Added " + str(added) + ", Revoked " + str(removed)))
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
    filters = list()
    for key, value in security_group_tag.items():
        filters.extend(
            [
                { 'Name': "tag-key", 'Values': [ key ] },
                { 'Name': "tag-value", 'Values': [ value ] }
            ]
        )

    response = client.describe_security_groups(Filters=filters)

    return response['SecurityGroups']

# This is a handy test event you can use when testing your lambda function.
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
        "Message": "{\"create-time\": \"yyyy-mm-ddThh:mm:ss+00:00\", \"synctoken\": \"0123456789\", \"md5\": \"45be1ba64fe83acb7ef247bccbc45704\", \"url\": \"https://ip-ranges.amazonaws.com/ip-ranges.json\"}",
        "Type": "Notification",
        "UnsubscribeUrl": "EXAMPLE",
        "TopicArn": "arn:aws:sns:EXAMPLE",
        "Subject": "TestInvoke"
      }
    }
  ]
}

'''
