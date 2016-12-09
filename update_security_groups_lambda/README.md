# update-security-groups

A Lambda function for updating the **cloudfront** EC2 security group ingress rules
with the CloudFront IP range changes.


## Security Group

This Lambda function updates EC2 security groups tagged with `Name: cloudfront` and `AutoUpdate: true` and a `Protocol` tag with value `http` or `https`.


## Event Source

This lambda function is designed to be subscribed to the 
[AmazonIpSpaceChanged](http://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html#subscribe-notifications) 
SNS topic. In the _Add Event Source_ dialog, select **SNS** in the *Event source type*, and populate *SNS Topic* with `arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged`.


## Policy

To be able to make sufficient use of this Lambda function, you will require a role with a number of permissions. An example policy is as follows:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress"
            ],
            "Resource": "arn:aws:ec2:[region]:[account-id]:security-group/*"
        },
        {
            "Effect": "Allow",
            "Action": "ec2:DescribeSecurityGroups",
            "Resource": "*"
        },
        {
            "Action": [
                "logs:CreateLogGroup",
                 "logs:CreateLogStream",
                 "logs:PutLogEvents"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:logs:*:*:*"
        }
    ]
}
```

Be sure to replace `[region]` with the AWS Region for your security groups, and `[account-id]` with your account number.

For more information on ip-ranges.json, read the documentation on [AWS IP Address Ranges](http://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html).

***

Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/apache2.0/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
