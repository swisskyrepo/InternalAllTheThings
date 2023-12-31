# AWS - S3 Buckets

## Tools

* [digi.ninja/bucket-finder](https://digi.ninja/projects/bucket_finder.php) - Search for public buckets, list and download all files if directory indexing is enabled
	```powershell
	wget https://digi.ninja/files/bucket_finder_1.1.tar.bz2 -O bucket_finder_1.1.tar.bz2
	./bucket_finder.rb my_words
	./bucket_finder.rb --region ie my_words
	./bucket_finder.rb --download --region ie my_words
	./bucket_finder.rb --log-file bucket.out my_words
	```

* [aws-sdk/boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) - Amazon Web Services (AWS) SDK for Python
	```python
	import boto3
	s3 = boto3.client('s3',aws_access_key_id='AKIAJQDP3RKREDACTED',aws_secret_access_key='igH8yFmmpMbnkcUaCqXJIRIozKVaREDACTED',region_name='us-west-1')

	try:
		result = s3.list_buckets()
		print(result)
	except Exception as e:
		print(e)
	```

* [nccgroup/s3_objects_check](https://github.com/nccgroup/s3_objects_check) - Whitebox evaluation of effective S3 object permissions, to identify publicly accessible files
    ```powershell
    $ python3 -m venv env && source env/bin/activate
    $ pip install -r requirements.txt
    $ python s3-objects-check.py -h
    $ python s3-objects-check.py -p whitebox-profile -e blackbox-profile
    ```


## 



## References

* []()