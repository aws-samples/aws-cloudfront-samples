// Lambda function for updating the cloudfront EC2 security group ingress rules with the CloudFront IP range changes using the Node.js 8.10 runtime.
//
// Name of the service, as seen in the ip-groups.json file, to extract information for
const SERVICE = 'CLOUDFRONT';
// Ports your application uses that need inbound permissions from the service for
const INGRESS_PORTS = { Http: 80, Https: 443 };
// Tags which identify the security groups you want to update
const SECURITY_GROUP_TAG_FOR_GLOBAL_HTTP = { Name: 'cloudfront_g', AutoUpdate: 'true', Protocol: 'http' };
const SECURITY_GROUP_TAG_FOR_GLOBAL_HTTPS = { Name: 'cloudfront_g', AutoUpdate: 'true', Protocol: 'https' };
const SECURITY_GROUP_TAG_FOR_REGION_HTTP = { Name: 'cloudfront_r', AutoUpdate: 'true', Protocol: 'http' };
const SECURITY_GROUP_TAG_FOR_REGION_HTTPS = { Name: 'cloudfront_r', AutoUpdate: 'true', Protocol: 'https' };
const REGION = process.env.REGION; // requires REGION environment variable to be set
const request = require('request');
const crypto = require('crypto');
const AWS = require('aws-sdk');

module.exports = async function(event, context, callback) {
  console.log('Received event: ' + JSON.stringify(event, null, 2));
  let message = JSON.parse(event.Records[0].Sns.Message);
  //  Load the ip ranges from the url
  let ipRanges = await getIpGroupsJSON(message.url, message.md5).catch((err) => { console.log(err); return callback(err); });

  // extract the service ranges
  let globalCFRanges = getRangesForService(ipRanges, SERVICE, 'GLOBAL');
  let regionCFRanges = getRangesForService(ipRanges, SERVICE, 'REGION');
  ipRanges = { GLOBAL: globalCFRanges, REGION: regionCFRanges };

  // update the security groups
  let result = await updateSecurityGroups(ipRanges).catch((err) => { console.log(err); return callback(err); });

  console.log('Update results:', result);
  return callback(null, result);
};

function getIpGroupsJSON(url, expectedHash) {
  return new Promise((resolve, reject) => {
    console.log('Updating from ' + url);
    request.get(url, function(err, resp, body) {
      if (err) {
        console.log(`Encountered error when getting url: ${url} Err: ${err}`);
        return reject(err);
      }
      if (resp.statusCode !== 200) {
        console.log(`Non 200 status code when getting url: ${url} statusCode: ${resp.statusCode}, body: ${JSON.stringify(body)}`);
        return reject(new Error(`Non-200 status code when getting url: ${url} statusCode: ${resp.statusCode}, body: ${JSON.stringify(body)}`));
      }
      let ipJSON = JSON.parse(body);
      let hash = crypto.createHash('md5').update(JSON.stringify(ipJSON)).digest('hex');
      if (hash !== expectedHash) {
        return reject(new Error('MD5 Mismatch: got ' + hash + ' expected ' + expectedHash));
      }
      return resolve(ipJSON);
    });
  });
}

function getRangesForService(ranges, service, subset) {
  let serviceRanges = [];
  for (let prefix of ranges.prefixes) {
    if (prefix.service === service &&
      ((subset === prefix.region && subset === 'GLOBAL') || (subset !== 'GLOBAL' && prefix.region !== 'GLOBAL'))
    ) {
      console.log('Found ' + service + ' region: ' + prefix['region'] + ' range: ' + prefix['ip_prefix']);
      serviceRanges.push(prefix['ip_prefix']);
    }
  }
  return serviceRanges;
}

async function updateSecurityGroups(newRanges) {
  let ec2 = new AWS.EC2({ region: REGION });
  let globalHttpGroup = await getSecurityGroupsForUpdate(ec2, SECURITY_GROUP_TAG_FOR_GLOBAL_HTTP).catch((err) => { throw new Error(err); });
  let globalHttpsGroup = await getSecurityGroupsForUpdate(ec2, SECURITY_GROUP_TAG_FOR_GLOBAL_HTTPS).catch((err) => { throw new Error(err); });
  let regionHttpGroup = await getSecurityGroupsForUpdate(ec2, SECURITY_GROUP_TAG_FOR_REGION_HTTP).catch((err) => { throw new Error(err); });
  let regionHttpsGroup = await getSecurityGroupsForUpdate(ec2, SECURITY_GROUP_TAG_FOR_REGION_HTTPS).catch((err) => { throw new Error(err); });


  console.log(`Found ${JSON.stringify(globalHttpGroup)} Cloudfront_g HttpSecurityGroups to update`);
  console.log(`Found ${JSON.stringify(globalHttpsGroup)} Cloudfront_g HttpsSecurityGroups to update`);
  console.log(`Found ${JSON.stringify(globalHttpGroup)} Cloudfront_r HttpSecurityGroups to update`);
  console.log(`Found ${JSON.stringify(globalHttpsGroup)} Cloudfront_r HttpsSecurityGroups to update`);
  let result = [];

  let globalHttpUpdated = 0;
  let globalHttpsUpdated = 0;
  let regionHttpUpdated = 0;
  let regionHttpsUpdated = 0;

  if (globalHttpGroup && globalHttpGroup.length) {
    for (let group in globalHttpGroup) {
      let updatedThisGroup = await updateSecurityGroup(ec2, globalHttpGroup[group], newRanges['GLOBAL'], INGRESS_PORTS['Http']).catch((err) => { throw new Error(err); });
      if (updatedThisGroup) {
        globalHttpUpdated += 1;
        result.push(`Updated ${globalHttpGroup[group].GroupId}`);
      }
    }
  }
  if (globalHttpsGroup && globalHttpsGroup.length) {
    for (let group in globalHttpsGroup) {
      let updatedThisGroup = await updateSecurityGroup(ec2, globalHttpsGroup[group], newRanges['GLOBAL'], INGRESS_PORTS['Https']).catch((err) => { throw new Error(err); });
      if (updatedThisGroup) {
        globalHttpsUpdated += 1;
        result.push(`Updated ${globalHttpsGroup[group].GroupId}`);
      }
    }
  }
  if (regionHttpGroup && regionHttpGroup.length) {
    for (let group in regionHttpGroup) {
      let updatedThisGroup = await updateSecurityGroup(ec2, regionHttpGroup[group], newRanges['REGION'], INGRESS_PORTS['Http']).catch((err) => { throw new Error(err); });
      if (updatedThisGroup) {
        regionHttpUpdated += 1;
        result.push(`Updated ${regionHttpGroup[group].GroupId}`);
      }
    }
  }
  if (regionHttpsGroup && regionHttpsGroup.length) {
    for (let group in regionHttpsGroup) {
      let updatedThisGroup = await updateSecurityGroup(ec2, regionHttpsGroup[group], newRanges['REGION'], INGRESS_PORTS['Https']).catch((err) => { throw new Error(err); });
      if (updatedThisGroup) {
        regionHttpsUpdated += 1;
        result.push(`Updated ${regionHttpsGroup[group].GroupId}`);
      }
    }
  }

  result.push(`Updated ${globalHttpUpdated} of ${JSON.stringify(globalHttpGroup)} CloudFront_g HttpSecurityGroups`);
  result.push(`Updated ${globalHttpsUpdated} of ${JSON.stringify(globalHttpsGroup)} CloudFront_g HttpsSecurityGroups`);
  result.push(`Updated ${regionHttpUpdated} of ${JSON.stringify(regionHttpGroup)} CloudFront_r HttpSecurityGroups`);
  result.push(`Updated ${regionHttpsUpdated} of ${JSON.stringify(regionHttpsGroup)} CloudFront_r HttpsSecurityGroups`);

  return result;
}

function countOccurence(array, item) {
  let count = 0;
  for (let i = 0; i < array.length; i++) {
    if (array[i] === item) {
      count += 1;
    }
  }
  return count;
}

async function updateSecurityGroup(client, group, newRanges, port) {
  let added = 0;
  let removed = 0;
  if (group.IpPermissions && group.IpPermissions.length) {
    for (let p in group.IpPermissions) {
      let permission = group.IpPermissions[p];
      if (permission.FromPort <= port && permission.ToPort >= port) {
        let oldPrefixes = [];
        let toRevoke = [];
        let toAdd = [];
        for (let r in permission.IpRanges) {
          let range = permission.IpRanges[r];
          let cidr = range.CidrIp;
          oldPrefixes.push(cidr);
          if (countOccurence(newRanges, cidr) === 0) {
            toRevoke.push(range);
            console.log(group.GroupId + ': Revoking ' + cidr + ':' + permission['ToPort'].toString());
          }
        }

        for (let r in newRanges) {
          let range = newRanges[r];
          if (countOccurence(oldPrefixes, range) === 0) {
            toAdd.push({ CidrIp: range });
            console.log(group['GroupId'] + ': Adding ' + range + ':' + permission['ToPort'].toString());
          }
        }

        removed += await revokePermissions(client, group, permission, toRevoke).catch((err) => { throw new Error(err); });

        added += await addPermissions(client, group, permission, toAdd).catch((err) => { throw new Error(err); });

      }
    }
  } else {
    let toAdd = [];
    for (let r in newRanges) {
      let range = newRanges[r];
      toAdd.push({ CidrIp: range });
      console.log(group['GroupId'] + ': Adding ' + range + ':' + port);
    }
    let permission = { ToPort: port, FromPort: port, IpProtocol: 'tcp' };
    added += await addPermissions(client, group, permission, toAdd).catch((err) => { throw new Error(err); });
  }

  console.log(group['GroupId'] + ': Added ' + added.toString() + ', Revoked ' + removed.toString());
  return (added > 0 || removed > 0);
}

function revokePermissions(client, group, permission, toRevoke) {
  return new Promise((resolve, reject) => {
    if (!toRevoke.length) {
      return resolve(toRevoke.length);
    }
    let revokeParams = {
      ToPort: permission['ToPort'],
      FromPort: permission['FromPort'],
      IpRanges: toRevoke,
      IpProtocol: permission['IpProtocol']
    };
    client.revokeSecurityGroupIngress({
      GroupId: group.GroupId,
      IpPermissions: [revokeParams]
    }, function(err) {
      if (err) {
        return reject(err);
      }
      return resolve(toRevoke.length);
    });
  });
}

function addPermissions(client, group, permission, toAdd) {
  return new Promise((resolve, reject) => {
    if (!toAdd.length) {
      return resolve(toAdd.length);
    }
    let addParams = {
      ToPort: permission['ToPort'],
      FromPort: permission['FromPort'],
      IpRanges: toAdd,
      IpProtocol: permission['IpProtocol']
    };
    client.authorizeSecurityGroupIngress({
      GroupId: group.GroupId,
      IpPermissions: [addParams]
    }, function(err) {
      if (err) {
        return reject(err);
      }
      return resolve(toAdd.length);
    });
  });
}

function getSecurityGroupsForUpdate(client, securityGroupTag) {
  let filters = [];
  for (let i in securityGroupTag) {
    filters.push({
      Name: 'tag-key',
      Values: [i]
    });
    filters.push({
      Name: 'tag-value',
      Values: [securityGroupTag[i]]
    });
  }
  return new Promise((resolve, reject) => {
    client.describeSecurityGroups({
      Filters: filters
    }, function(err, response) {
      if (err) {
        return reject(err);
      }
      return resolve(response.SecurityGroups);
    });
  });
}
