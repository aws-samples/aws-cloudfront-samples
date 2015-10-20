# aws-cloudfront-samples
Samples for use of Amazon CloudFront, including Lambda functions, and SDK usage examples.

## update_security_groups_lambda

This AWS Lambda function is written in Python and can be used to automatically
update EC2 security group ingress rules when CloudFront IP ranges change.

By subscribing this function to the SNS topic
[AmazonIpSpaceChanged](http://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html#subscribe-notifications)
your security groups tagged with `Name: cloudfront` and `AutoUpdate: true` will be
updated accordingly.


For more informationi on ip-ranges.json, read the documentation on [AWS IP Address Ranges](http://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html).

***

Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at

    http://aws.amazon.com/apache2.0/

or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
