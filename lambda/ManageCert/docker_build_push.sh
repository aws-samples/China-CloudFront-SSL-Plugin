# excute it before
export ACCOUNT_ID="YOUR_AWS_ACCOUNT_ID"

### List
cd ListCert
docker build -t list_iam_cert:latest .
aws ecr get-login-password --region cn-northwest-1 | docker login --username AWS --password-stdin  $ACCOUNT_ID.dkr.ecr.cn-northwest-1.amazonaws.com.cn
docker tag list_iam_cert:latest $ACCOUNT_ID.dkr.ecr.cn-northwest-1.amazonaws.com.cn/cloudfront_ssl_plugin/list_iam_cert:latest
docker push $ACCOUNT_ID.dkr.ecr.cn-northwest-1.amazonaws.com.cn/cloudfront_ssl_plugin/list_iam_cert:latest

aws ecr get-login-password --region cn-north-1 | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.cn-north-1.amazonaws.com.cn
docker tag list_iam_cert:latest $ACCOUNT_ID.dkr.ecr.cn-north-1.amazonaws.com.cn/cloudfront_ssl_plugin/list_iam_cert:latest
docker push $ACCOUNT_ID.dkr.ecr.cn-north-1.amazonaws.com.cn/cloudfront_ssl_plugin/list_iam_cert:latest

cd ..

### Delete
cd DeleteCert
docker build -t delete_iam_cert:latest .
aws ecr get-login-password --region cn-northwest-1 | docker login --username AWS --password-stdin  $ACCOUNT_ID.dkr.ecr.cn-northwest-1.amazonaws.com.cn
docker tag delete_iam_cert:latest $ACCOUNT_ID.dkr.ecr.cn-northwest-1.amazonaws.com.cn/cloudfront_ssl_plugin/delete_iam_cert:latest
docker push $ACCOUNT_ID.dkr.ecr.cn-northwest-1.amazonaws.com.cn/cloudfront_ssl_plugin/delete_iam_cert:latest


aws ecr get-login-password --region cn-north-1 | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.cn-north-1.amazonaws.com.cn
docker tag delete_iam_cert:latest $ACCOUNT_ID.dkr.ecr.cn-north-1.amazonaws.com.cn/cloudfront_ssl_plugin/delete_iam_cert:latest
docker push $ACCOUNT_ID.dkr.ecr.cn-north-1.amazonaws.com.cn/cloudfront_ssl_plugin/delete_iam_cert:latest