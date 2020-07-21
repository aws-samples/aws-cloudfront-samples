# cloudfront-traffic-csv
Ever had to create regular traffic report for 100+ Amazon CloudFront distributions?  
CloudFront Usage Reports under CloudFront console provides great one but it requires user to select each distribution and generate report one by one.  
This script pulls Amazon CloudFront metric from CloudWatch, which can be modified to your requirement.  

### Usage:
```
python cloudfront-traffic-csv.py <Startdate %Y-%m-%d> <Enddate %Y-%m-%d> [--metric <BytesDownloaded|Requests|BytesUploaded>] [--tag tag_key]
```
Startdate, Enddate defines period of data.  
metric is the metric name for CloudFront, default is BytesDownloaded.  
Use tag to insert tag value into result if needed.  

You can use command line to pull bytedownload and store to csv
```
python cloudfront-traffic-csv.py 2020-01-01 2020-05-31 > result.csv
```