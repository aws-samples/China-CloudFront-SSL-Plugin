import json
import logging
import os

import boto3

logger = logging.getLogger(__name__)
logger.setLevel(os.getenv("LOG_LEVEL", "INFO"))


def handler(event, context):

    body = json.loads(event['body'])
    cert_name = body['certName']
    delete_response = delete_iam_cert(cert_name)

    if delete_response == "DeletedCert":
        status_code = 200
        body = {"certName": cert_name, "deletionResult": "Successfully deleted!"}
    elif delete_response == "NoSuchEntityException":
        status_code = 400
        body = {"certName": cert_name, "deletionResult": "Failed to delete! Exception is NoSuchEntityException."}
    elif delete_response == "DeleteConflictException":
        status_code = 400
        body = {"certName": cert_name, "deletionResult": "Failed to delete! Exception is DeleteConflictException."}


    response = {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*"
        },
        "isBase64Encoded": False,
        "body": json.dumps(body)
    };
    return response


def delete_iam_cert(cert_name):
    iam_client = boto3.client('iam')
    try:
        response = iam_client.delete_server_certificate(ServerCertificateName=cert_name)
        logger.info(f"Deleted certificate: {cert_name}, response: {response}")
        return "DeletedCert"
    except iam_client.exceptions.NoSuchEntityException as e:
        logger.info(f"Certificate does not exist: {e}")
        return "NoSuchEntityException"
    except iam_client.exceptions.DeleteConflictException as d:
        logger.info(f"Delete conflict: {d}")
        return "DeleteConflictException"
    raise

