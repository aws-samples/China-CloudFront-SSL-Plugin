import json
import logging
import os

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))

def handler(event, lambda_context):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.list_server_certificates()
        certificates = response['ServerCertificateMetadataList']

        cert_list = []
        for cert in certificates:
            cert_info = {
                "certName": cert['ServerCertificateName'],
                "certId": cert['ServerCertificateId'],
                "arn": cert['Arn'],
                "uploadDate": cert['UploadDate'].isoformat(),
                "expiration": cert['Expiration'].isoformat()
            }
            cert_list.append(cert_info)

        return {
            "statusCode": 200,
            "headers": {
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "*"
            },
            "isBase64Encoded": False,
            "body": json.dumps({"certificates": cert_list})
        }

    except iam_client.exceptions.ServiceFailureException as e:
        logger.error(f"Failed to list certificates: {e}")
        return {
            "statusCode": 500,
            "headers": {
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "*"
            },
            "isBase64Encoded": False,
            "body": json.dumps({"message": "Failed to list certificates"})
        }

