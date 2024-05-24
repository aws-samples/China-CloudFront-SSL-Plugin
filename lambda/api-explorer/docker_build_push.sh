export ACCOUNT_ID="YOUR_AWS_ACCOUNT_ID"

docker build -t api_explorer:latest .

aws ecr get-login-password --region cn-northwest-1 | docker login --username AWS --password-stdin  $ACCOUNT_ID.dkr.ecr.cn-northwest-1.amazonaws.com.cn
docker tag api_explorer:latest $ACCOUNT_ID.dkr.ecr.cn-northwest-1.amazonaws.com.cn/cloudfront_ssl_plugin/api_explorer_iam_cert:latest
docker push $ACCOUNT_ID.dkr.ecr.cn-northwest-1.amazonaws.com.cn/cloudfront_ssl_plugin/api_explorer_iam_cert:latest


aws ecr get-login-password --region cn-north-1 | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.cn-north-1.amazonaws.com.cn
docker tag api_explorer:latest $ACCOUNT_ID.dkr.ecr.cn-north-1.amazonaws.com.cn/cloudfront_ssl_plugin/api_explorer_iam_cert:latest
docker push $ACCOUNT_ID.dkr.ecr.cn-north-1.amazonaws.com.cn/cloudfront_ssl_plugin/api_explorer_iam_cert:latest