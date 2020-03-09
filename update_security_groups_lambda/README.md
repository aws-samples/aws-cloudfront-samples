# Setup

## update-security-groups

A Lambda function for updating EC2 security group ingress rules to permit ingress from Amazon CloudFront IPv4 addresses. See [this blog post](https://aws.amazon.com/blogs/security/how-to-automatically-update-your-security-groups-for-amazon-cloudfront-and-aws-waf-by-using-aws-lambda/)for discussion on how to use it and why it is useful.

## Security Groups

This Lambda function updates security groups based on their tags. You can stipulate some number of ingress protocol/ports in the code. For each protocol/port number you specify, you will need to have 2 security groups (a *regional* and a *global* one). 

*  `Name: cloudfront_g` and `AutoUpdate: true` and a `Protocol` tag with value `http` or `https`.
*  `Name: cloudfront_r` and `AutoUpdate: true` and a `Protocol` tag with value `http` or `https`.

**Note:** For CloudFront to properly connect to your origin over HTTP or HTTPS only, you will need two security groups with `Name: cloudfront_g` and `Name: cloudfront_r` set for http or https depending on the protocol used. If you require both HTTP and HTTPS protocols to your origin, you will need a total of 4 security groups.

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

## Test Lambda Function
Now that you have created your function, it’s time to test it and initialize your security group:

1.  In the Lambda console on the Functions page, choose your function, choose the Actions drop-down menu, and then Configure test event.
2.  Enter the following as your sample event, which will represent an SNS notification.

```
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
        "Message": "{\"create-time\": \"yyyy-mm-ddThh:mm:ss+00:00\", \"synctoken\": \"0123456789\", \"md5\": \"7fd59f5c7f5cf643036cbd4443ad3e4b\", \"url\": \"https://ip-ranges.amazonaws.com/ip-ranges.json\"}",
        "Type": "Notification",
        "UnsubscribeUrl": "EXAMPLE",
        "TopicArn": "arn:aws:sns:EXAMPLE",
        "Subject": "TestInvoke"
      }
    }
  ]
}
```
3.  After you’ve added the test event, click Save and test. Your Lambda function will be invoked, and you should see log output at the bottom of the console similar to the following.
<pre>
Updating from https://ip-ranges.amazonaws.com/ip-ranges.json
MD5 Mismatch: got <b>2e967e943cf98ae998efeec05d4f351c</b> expected 7fd59f5c7f5cf643036cbd4443ad3e4b: Exception
Traceback (most recent call last):
  File "/var/task/lambda_function.py", line 29, in lambda_handler
    ip_ranges = json.loads(get_ip_groups_json(message['url'], message['md5']))
  File "/var/task/lambda_function.py", line 50, in get_ip_groups_json
    raise Exception('MD5 Missmatch: got ' + hash + ' expected ' + expected_hash)
Exception: MD5 Mismatch: got <b>2e967e943cf98ae998efeec05d4f351c</b> expected 7fd59f5c7f5cf643036cbd4443ad3e4b
</pre>
You will see a message indicating there was a hash mismatch. Normally, a real SNS notification from the IP Ranges SNS topic will include the right hash, but because our sample event is a test case representing the event, you will need to update the sample event manually to have the expected hash.

4.  Edit the sample event again, and this time change the md5 hash **that is bold** to be the first hash provided in the log output. In this example, we would update the sample event with the hash “2e967e943cf98ae998efeec05d4f351c”.


5.  Click Save and test, and your Lambda function will be invoked.

This time, you should see output indicating your security group was properly updated. If you go back to the EC2 console and view the security group you created, you will now see all the CloudFront IP ranges added as allowed points of ingress. If your log output is different, it should help you identify the issue.

## Configure your Lambda function’s trigger
After you have validated that your function is executing properly, it’s time to connect it to the SNS topic for IP changes. To do this, use the AWS Command Line Interface (CLI). Enter the following command, making sure to replace <Lambda ARN> with the Amazon Resource Name (ARN) of your Lambda function. You will find this ARN at the top right when viewing the configuration of your Lambda function.

`aws sns subscribe --topic-arn arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged --protocol lambda --notification-endpoint <Lambda ARN>`

You should receive an ARN of your Lambda function’s SNS subscription. Your Lambda function will now be invoked whenever AWS publishes new IP ranges!
***

Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/apache2.0/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
