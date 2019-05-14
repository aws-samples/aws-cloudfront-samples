/*
Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.


Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at


    http://aws.amazon.com/apache2.0/


or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
*/

const { get, each, reduce, find } = require('lodash');
const rp = require('request-promise');
const crypto = require('crypto');
const AWS = require('aws-sdk');

const SERVICE = "CLOUDFRONT";

const INGRESS_PORTS =  { 'Http' : 80, 'Https': 443 };

// Tags which identify the security groups you want to update
const SECURITY_GROUP_TAG_FOR_GLOBAL_HTTP = { 'Name': 'cloudfront_g', 'AutoUpdate': 'true', 'Protocol': 'http' };
const SECURITY_GROUP_TAG_FOR_GLOBAL_HTTPS = { 'Name': 'cloudfront_g', 'AutoUpdate': 'true', 'Protocol': 'https' };
const SECURITY_GROUP_TAG_FOR_REGION_HTTP = { 'Name': 'cloudfront_r', 'AutoUpdate': 'true', 'Protocol': 'http' };
const SECURITY_GROUP_TAG_FOR_REGION_HTTPS = { 'Name': 'cloudfront_r', 'AutoUpdate': 'true', 'Protocol': 'https' };

const get_ip_groups_json = (uri, expected_hash) => {

    return rp({ uri })
        .then(actual_resp => {
            console.log('actual response from uri: ', actual_resp);
            if(crypto.createHash('md5').update(actual_resp).digest("hex") !== expected_hash){
                console.log("MD5 Mismatch: actual: " + crypto.createHash('md5').update(actual_resp).digest("hex") + " expected: " + expected_hash);
                throw new Error("MD5 Mismatch: actual: " + crypto.createHash('md5').update(actual_resp).digest("hex") + " expected: " + expected_hash);
            }
            return JSON.parse(actual_resp);
        })
}

const  get_ranges_for_service = (ranges, service, subset) => reduce(ranges.prefixes, (accum, prefix) => {
        if(prefix.service === service && ((subset === prefix.region && subset === "GLOBAL") || ( subset !== "GLOBAL" && prefix.region !== "GLOBAL"))){
           console.log(`Found ${service} region: ${prefix.region} range: ${prefix.ip_prefix}`);
           accum.push(prefix.ip_prefix) ;
        }
        return accum;
    }, [])

const get_security_groups_for_update = (client, security_group_tag) => {
    const filters = reduce(security_group_tag, (accum, value, key) => {
        accum.push({ 'Name': `tag:${key}`, 'Values': [ value ] })
        return accum;
    }, []);

    return client.describeSecurityGroups({Filters: filters}).promise().then(response => response.SecurityGroups) 
}

const update_security_groups = (new_ranges) => {
    const client = new AWS.EC2();

    return Promise.all([
        get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_GLOBAL_HTTP),
        get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_GLOBAL_HTTPS),
        get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_REGION_HTTP),
        get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_REGION_HTTPS) 
    ]).then(data => {
        const global_http_group = data[0];
        const global_https_group = data[1];
        const region_http_group = data[2];
        const region_https_group = data[3];
        console.log('Found ' + JSON.stringify(global_http_group) + ' CloudFront_g HttpSecurityGroups to update');
        console.log('Found ' + JSON.stringify(global_https_group) + ' CloudFront_g HttpsSecurityGroups to update');
        console.log('Found ' + JSON.stringify(region_http_group) + ' CloudFront_r HttpSecurityGroups to update');
        console.log('Found ' + JSON.stringify(region_https_group) + ' CloudFront_r HttpsSecurityGroups to update');

        each( global_http_group,    group =>   update_security_group(client, group, new_ranges["GLOBAL"], INGRESS_PORTS["Http"]));
        each( global_https_group,   group =>   update_security_group(client, group, new_ranges["GLOBAL"], INGRESS_PORTS["Https"]));
        each( region_http_group,    group =>   update_security_group(client, group, new_ranges["REGION"], INGRESS_PORTS["Http"]));
        each( region_https_group,   group =>   update_security_group(client, group, new_ranges["REGION"], INGRESS_PORTS["Https"]));

    })
}


const update_security_group   =   (client, group, new_ranges, port)  =>  {
    const added = 0
    const removed = 0

    if(group.IpPermissions && group.IpPermissions.length > 0){
        each(group.IpPermissions, permission => {
            if(permission.FromPort <= port && permission.ToPort >= port){
                const old_prefixes = [];

                const to_revoke = reduce(permission.IpRanges, (accum, range) => {
                    const cidr  =   range.CidrIp;
                    old_prefixes.push(cidr);
                    if(!find(new_ranges, new_range => new_range === cidr)) accum.push(range);
                    return accum;
                }, [])

                const to_add    = reduce(new_ranges, (accum, range) => {
                    if(!find(old_prefixes, old_range => old_range === range)) accum.push({"CidrIp": range});
                    return accum;
                }, [])

                revoke_permissions(client, group, permission, to_revoke);
                add_permissions(client, group, permission, to_add);
            }
        })
    } else {
        const to_add    = reduce(new_ranges, (accum, range) => {
            accum.push({"CidrIp": range});
            return accum;
        }, []);
        const permission    =  { 'ToPort': port, 'FromPort': port, 'IpProtocol': 'tcp'};
        add_permissions(client, group, permission, to_add); 
    }
}


const revoke_permissions    =   (client, group, permission, to_revoke)  =>  {
    if(to_revoke && to_revoke.length >0){
        console.log("Revoke Permissions:");
        const revoke_params = {
            'ToPort': permission.ToPort,
            'FromPort': permission.FromPort,
            'IpRanges': to_revoke,
            'IpProtocol': permission.IpProtocol
        };  
        client.revokeSecurityGroupIngress({
            GroupId: group.GroupId,
            IpPermissions:  [revoke_params]
        }).promise().then(data => console.log("success:", group.GroupId)).catch(err => console.log(err));
        console.log(group.GroupId, JSON.stringify(revoke_params));
    }
}

const add_permissions   =   (client, group, permission, to_add) => {
    if(to_add && to_add.length >0){
        console.log("Add Permissions:");
        const add_params = {
            'ToPort': permission.ToPort,
            'FromPort': permission.FromPort,
            'IpRanges': to_add,
            'IpProtocol': permission.IpProtocol
        };  
        client.authorizeSecurityGroupIngress({
            GroupId: group.GroupId,
            IpPermissions:  [add_params]
        }).promise().then(data => console.log("success:", group.GroupId)).catch(err => console.log(err));
        console.log(group.GroupId, JSON.stringify(add_params));
    }
}

exports.handler = (event, context, cb) => {
    console.log("Received event: " + JSON.stringify(event, null, 2));
    const message = JSON.parse(get(event, 'Records.0.Sns.Message'));


    // Load the ip ranges from the url
    get_ip_groups_json(message.url, message.md5)
        .then(ip_ranges => {
            console.log("Got ip ranges");
            // extract the service ranges
            const global_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "GLOBAL");
            const region_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "REGION");
            const parsed_ip_ranges = { "GLOBAL": global_cf_ranges, "REGION": region_cf_ranges };

            // update the security groups
            return update_security_groups(parsed_ip_ranges);
            
        })
        .catch(e => {
            console.log(e.message);
            cb(null, e);
        });
}