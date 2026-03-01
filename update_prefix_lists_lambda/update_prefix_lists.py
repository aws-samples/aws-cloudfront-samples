'''
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
    http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
'''


GLOBAL_PL_TAGS = { 'Name': 'cloudfront_g', 'AutoUpdate': 'true' }
REGION_PL_TAGS = { 'Name': 'cloudfront_r', 'AutoUpdate': 'true' }

import boto3
import hashlib
import json
import logging
import urllib.request, urllib.error, urllib.parse
import os


def lambda_handler(event, context):
    # Set up logging
    if len(logging.getLogger().handlers) > 0:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.basicConfig(level=logging.DEBUG)
    
    # Set the environment variable DEBUG to 'true' if you want verbose debug details in CloudWatch Logs.
    try:
        if os.environ['DEBUG'] == 'true':
            logging.getLogger().setLevel(logging.INFO)
    except KeyError:
        pass

    # If you want a different service, set the SERVICE environment variable.
    # It defaults to CLOUDFRONT. Using 'jq' and 'curl' get the list of possible
    # services like this:
    # curl -s 'https://ip-ranges.amazonaws.com/ip-ranges.json' | jq -r '.prefixes[] | .service' ip-ranges.json | sort -u 
    SERVICE = os.getenv( 'SERVICE', "CLOUDFRONT")
    
    message = json.loads(event['Records'][0]['Sns']['Message'])

    # Load the ip ranges from the url
    ip_ranges = json.loads(get_ip_groups_json(message['url'], message['md5']))
    logging.info(ip_ranges)

    # Extract the service ranges
    global_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "GLOBAL")
    region_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "REGION")

    # Update the prefix lists
    result = update_prefix_lists(global_cf_ranges, "GLOBAL")
    result = result + update_prefix_lists(region_cf_ranges, "REGION")
    
    return result


def get_ip_groups_json(url, expected_hash):
    
    logging.debug("Updating from " + url)

    response = urllib.request.urlopen(url)
    ip_json = response.read()

    m = hashlib.md5()
    m.update(ip_json)
    hash = m.hexdigest()

    if hash != expected_hash:
        raise Exception('MD5 Mismatch: got ' + hash + ' expected ' + expected_hash)

    return ip_json

def get_ranges_for_service(ranges, service, subset):
    
    service_ranges = list()
    for prefix in ranges['prefixes']:
        if prefix['service'] == service and ((subset == prefix['region'] and subset == "GLOBAL") or (subset != 'GLOBAL' and prefix['region'] != 'GLOBAL')):
            logging.info(('Found ' + service + ' region: ' + prefix['region'] + ' range: ' + prefix['ip_prefix']))
            service_ranges.append(prefix['ip_prefix'])

    return service_ranges

def update_prefix_lists(new_ranges, rangeType):
    
    client = boto3.client('ec2')
    result = list()

    tagToFind = {}
    if rangeType == "GLOBAL":
        tagToFind = GLOBAL_PL_TAGS
    else:
        tagToFind = REGION_PL_TAGS    
    rangeToUpdate = get_prefix_lists_for_update(client, tagToFind)
    msg = 'tagged Name: {} to update'.format( tagToFind["Name"] )
    logging.info('Found {} prefix lists {}'.format( str(len(rangeToUpdate)), msg ) )

    if len(rangeToUpdate) == 0:
        result.append( 'No prefix lists {}'.format(msg) )
        logging.warning( 'No prefix lists {}'.format(msg) )
    else:
        for prefixListToUpdate in rangeToUpdate:
            if update_prefix_list(client, prefixListToUpdate, new_ranges ):
                result.append('Prefix List {} updated.'.format( prefixListToUpdate['PrefixListId'] ) )
            else:
                result.append('Prefix List {} unchanged.'.format( prefixListToUpdate['PrefixListId'] ) )

    return result


def update_prefix_list(client, prefix_list, new_ranges):
    prefix_list_entries = client.get_managed_prefix_list_entries(
        PrefixListId=prefix_list["PrefixListId"]
    ).get("Entries")

    old_prefixes = list()
    to_revoke = list()
    to_add = list()

    for entry in prefix_list_entries:
        cidr = entry['Cidr']
        old_prefixes.append(cidr)
        if new_ranges.count(cidr) == 0:
            to_revoke.append(cidr)
            logging.debug((prefix_list['PrefixListId'] + ": Revoking " + cidr ))

    for range in new_ranges:
        if old_prefixes.count(range) == 0:
            to_add.append(range)
            logging.debug((prefix_list['PrefixListId'] + ": Adding " + range))

    added, removed = len(to_add), len(to_revoke)
    changed = (added or removed)

    if changed:
        client.modify_managed_prefix_list(
            PrefixListId=prefix_list['PrefixListId'],
            CurrentVersion=prefix_list['Version'],
            AddEntries=[{"Cidr": cidr} for cidr in to_add],
            RemoveEntries=[{"Cidr": cidr} for cidr in to_revoke]
        )

    logging.debug((prefix_list['PrefixListId'] + ": Added " + str(added) + ", Revoked " + str(removed)))
    return changed


def get_prefix_lists_for_update(client, tags):
    filters =[{ 'Name': "prefix-list-name", 'Values': [ tags.get("Name") ] }]

    response = client.describe_managed_prefix_lists(Filters=filters)

    return [pl for pl in response['PrefixLists'] if all({"Key": tag_key, "Value": tag_value} in pl["Tags"] for tag_key, tag_value in tags.items())]

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