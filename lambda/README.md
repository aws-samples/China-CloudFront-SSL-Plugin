# China CloudFront SSL Plugin - Lambda Code

This section contains Lambda code for China CloudFront SSL Plugin.


## Table of Contents
| Directory                       | Description                                                                                        |
|---------------------------------|----------------------------------------------------------------------------------------------------|
| [api-explorer](./api-explorer/) | API Doc & API Explorer Code for IAM Certificate Management                                         |
| [CertBot](./lambda/)            | Code for Let's Encrypt/Certbot certificate issuance/renew & CloudFront IAM certificate replacement |
| [ManageCert](./ManageCert/)     | Code for IAM Certificate Management                                                                |


## Build Guidance

We recommend running Lambda in a containerized manner. Please ensure that you have the necessary permissions. You can modify the Account ID field in the docker_build_push.sh file under each directory, then run the file to automatically build and push the container to Amazon ECR (Amazon Elastic Container Registry).