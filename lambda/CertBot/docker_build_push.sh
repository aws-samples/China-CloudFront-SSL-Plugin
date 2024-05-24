cd certbot
docker build -t certbot:latest .

export ACCOUNT_ID="YOUR_AWS_ACCOUNT_ID"
export TAG="latest"

aws ecr get-login-password --region cn-northwest-1 | docker login --username AWS --password-stdin  $ACCOUNT_ID.dkr.ecr.cn-northwest-1.amazonaws.com.cn
docker tag certbot:latest $ACCOUNT_ID.dkr.ecr.cn-northwest-1.amazonaws.com.cn/cloudfront_ssl_plugin/certbot:$TAG
docker push $ACCOUNT_ID.dkr.ecr.cn-northwest-1.amazonaws.com.cn/cloudfront_ssl_plugin/certbot:$TAG


aws ecr get-login-password --region cn-north-1 | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.cn-north-1.amazonaws.com.cn
docker tag certbot:latest $ACCOUNT_ID.dkr.ecr.cn-north-1.amazonaws.com.cn/cloudfront_ssl_plugin/certbot:$TAG
docker push $ACCOUNT_ID.dkr.ecr.cn-north-1.amazonaws.com.cn/cloudfront_ssl_plugin/certbot:$TAG