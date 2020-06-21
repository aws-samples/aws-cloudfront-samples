# cloudfront-traffic-csv
Ever had to create regular traffic report per 100+ Amazon CloudFront distributions?  
CloudFront Usage Reports under CloudFront console provides great one but it requires user to select each distribution and generate report one by one - which is not scalable at all.  
This script pulls Amazon CloudFront metric from CloudWatch, which can e modified for your requirement.  

### Usage:
```
python cloudfront-traffic-csv.py <BytesDownloaded|Requests|BytesUploaded> <Startdate %Y-%m-%d> <Enddate %Y-%m-%d> [mailto=receive@mail.com]
```
You can use command line to pull bytedownload and store to csv
```
python cloudfront-traffic-csv.py BytesDownloaded 2020-01-01 2020-05-31 > result.csv
```
or your can send it via e-mail
```
python cloudfront-traffic-csv.py BytesDownloaded 2020-01-01 2020-05-31 mailto=my@example.com
```