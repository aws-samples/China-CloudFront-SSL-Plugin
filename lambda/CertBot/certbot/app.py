import os
import logging

import boto3
import botocore
import certbot.main
import json
from datetime import datetime, timezone, timedelta
import tarfile
import traceback

region = os.environ["REGION"]
# Get S3/SNS/IAM/CDN clients
s3_client = boto3.client('s3', region_name=region)
sns_client = boto3.client('sns', region_name=region)
iam_client = boto3.client('iam')
cdn_client = boto3.client('cloudfront')

bucket = os.environ["CERTBOT_BUCKET"]
stack_name = os.environ["STACK_NAME"]

# Temp dir of Lambda runtime
CERTBOT_DIR = '/tmp/certbot'
NEW_IAM_SSL_INFO = 'new_iam_ssl_info.txt'
LAST_IAM_SSL_INFO = "last_iam_ssl_info(don't delete or modify).txt"

api_mgmt_link = os.environ['API_EXPLORER']
s3_link = f"https://{region}.console.amazonaws.cn/s3/buckets/{bucket}"
# Let’s Encrypt acme-v02 server that supports wildcard certificates
# CERTBOT_SERVER = 'https://acme-v02.api.letsencrypt.org/directory'

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event, context):
    logger.info(f"Domain list is {os.environ['DOMAINS_LIST']}")
    if (os.environ['DOMAINS_LIST'] != '') and (os.environ['DOMAINS_EMAIL'] != ''):
        try:
            os.system(f"rm -rf {CERTBOT_DIR}")
            os.system(f"mkdir {CERTBOT_DIR}")
            return request_certs(os.environ['DOMAINS_LIST'], os.environ['DOMAINS_EMAIL'])
        except Exception as e:
            logger.error(traceback.format_exc())
            return return_502(traceback.format_exc())
    else:
        return return_502("Invalid Domain list or Domain Email")


def request_certs(domains, email):
    domains = domains.replace(" ", "")
    logger.info(f"Function: request_certs, {domains}")

    certbot_args = [
        '--config-dir', CERTBOT_DIR + "/config",
        '--work-dir', CERTBOT_DIR + "/work",
        '--logs-dir', CERTBOT_DIR + "/logs",

        '--cert-name', "ssl",

        # Obtain a cert but don't install it
        'certonly',

        # Run in non-interactive mode
        '--non-interactive',

        # Agree to the terms of service
        '--agree-tos',

        # Email of domain administrators
        '--email', email,

        # Use dns challenge with dns plugin
        '--dns-route53',
        # '--dns-route53-propagation-seconds', '720' #deprecated,
        '--preferred-challenges', 'dns-01',
        '--issuance-timeout', '900',

        # Use this server instead of default acme-v01
        # '--server', CERTBOT_SERVER,

        # Domains to provision certs for (comma separated)
        '--domains', domains

        # '--dry-run'
    ]

    cert_code = certbot.main.main(certbot_args)
    logger.info(f"CertBot request exec code: {cert_code}")

    # None代表成功
    if cert_code is None:
        now = get_now_time();
        expiration_date = (now + timedelta(days=89, hours=23)).strftime("%Y-%m-%d-%H%M")
        iam_ssl_name = stack_name + '-' + expiration_date
        upload_iam_certificate(now, iam_ssl_name)
        iam_ssl_id = get_iam_ssl_id(iam_ssl_name)
        replace_msg = replace_cloudfront_ssl(iam_ssl_id)
        upload_iam_info_to_s3(iam_ssl_name, iam_ssl_id)
        sns_notification = send_confirm_notification(domains, expiration_date, iam_ssl_name, iam_ssl_id, replace_msg);

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": f"Success request new cert {domains}",
                "notification": sns_notification,
            }),
        }
    else:
        e = f"[Error]CertBot request exec code: {cert_code}"
        logger.error(e)
        return return_502(e)


def upload_iam_info_to_s3(iam_ssl_name, iam_ssl_id):
    logger.info("Function: upload_iam_info_to_s3")
    with open(f"/tmp/{NEW_IAM_SSL_INFO}", 'w') as ssl_info_file:
        ssl_info_file.write(f"{iam_ssl_id}\n{iam_ssl_name}")
    s3_client.upload_file(f"/tmp/{NEW_IAM_SSL_INFO}", bucket, LAST_IAM_SSL_INFO)


def upload_iam_certificate(now, iam_ssl_name):
    logger.info("Function: upload_iam_certificate")
    iam_client.upload_server_certificate(
        Path=f"/cloudfront/{region}/{stack_name}/",
        ServerCertificateName=iam_ssl_name,
        CertificateBody=get_file_contents(CERTBOT_DIR + "/config/live/ssl/cert.pem"),
        PrivateKey=get_file_contents(CERTBOT_DIR + "/config/live/ssl/privkey.pem"),
        CertificateChain=get_file_contents(CERTBOT_DIR + "/config/live/ssl/chain.pem"),
    )
    folder_time = now.strftime("%Y-%m-%d-%H%M")
    tar_file_name = f"{folder_time}.tar.gz"
    tar_file_path = f"/tmp/{tar_file_name}"
    logger.info(f"Tar file: {tar_file_path}")
    tar_file = tarfile.open(tar_file_path, "w:gz")
    tar_file.add(CERTBOT_DIR)
    tar_file.close()
    s3_client.upload_file(tar_file_path, bucket, tar_file_name)


def get_file_contents(filename):
    logger.info(f"Function: get_file_contents {filename}")
    in_file = open(filename, "rb")
    data = in_file.read()
    in_file.close()
    return data.decode("utf-8")


def send_confirm_notification(domains, expiration_date, iam_ssl_name, iam_ssl_id, update_cdn_msg):
    subject = f"Success request SSL certification for {stack_name} stack.";
    msg = f'The certificate automatically generated for your domain [ {domains} ] is successful. \n\nPlease find your SSL certificate "{iam_ssl_name}" (ID: {iam_ssl_id}) on CloudFront dashboard, and attach it in time. \n\nThe certificate is valid until (UTC+8): {expiration_date}\n\n'

    msg = msg + f'自动为您域名: [ {domains} ] \n\n生成的证书已成功。请及时在CloudFront页面中找到您的SSL证书："{iam_ssl_name}" (ID: {iam_ssl_id})，并为您的CloudFront分配绑定您的证书。\n\n证书有效期截止(北京时间)：{expiration_date}\n\n'

    msg = msg + "CloudFront Update SSL Certificate Doc/ CloudFront绑定证书操作文档: \nhttps://docs.amazonaws.cn/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-procedures.html#cnames-and-https-updating-cloudfront\n\n"

    msg = msg + "#############SSL Renew Information / 证书更新信息##############\n\n"

    msg = msg + "If the SSL certificate has already been attached, please review the following automatic update " \
                "records to ensure that the CloudFront certificate that has been updated. If all certificates have " \
                "been successfully updated, you can delete the expired certificates via IAM SSL Certificate Management.\n\n"

    msg = msg + "如果该证书已经绑定CloudFront，请查看以下自动更新记录，确保全部绑定的CloudFront证书已经更新。如果证书都已更新完毕，您可以通过管理界面删除过期的证书。"

    msg = msg + "\n\n=====CloudFront SSL Certificate Renew Records======\n" + json.dumps(
        update_cdn_msg, indent=4)

    msg = msg + "\n\n=================Records Ends=================\n\n"

    msg = msg + "\n\n###########################\n\n"

    msg = msg + "If there are errors in the renew list, please refer to the troubleshooting section in the deployment documentation.\n若更新列表中出现错误，请参考部署文档中的问题排查。\n\n"

    msg = msg + f"Download SSL Certificate From S3 / 从S3下载证书：\n {s3_link} \n"

    msg = msg + f"IAM SSL Certificate Management / IAM SSL证书管理界面：\n {api_mgmt_link} \n"

    logger.info(f"Function: send_confirm_notification: SUBJECT: {subject}, MSG: {msg}")

    response = sns_client.publish(
        TopicArn=os.environ['TOPIC_ARN'],
        Message=msg,
        Subject=subject,
    )
    return response


def send_error_notification(msg):
    subject = f"Error for request SSL certification with {stack_name} stack.";

    logger.info(f"Function: send_error_notification: SUBJECT: {subject}, MSG: {msg}")

    response = sns_client.publish(
        TopicArn=os.environ['TOPIC_ARN'],
        Message=msg,
        Subject=subject,
    )
    return response


def get_now_time():
    bj_time = timezone(timedelta(hours=8))
    now = datetime.utcnow().astimezone(bj_time)
    return now;


def return_502(e):
    sns_error_notification = send_error_notification(str(e))
    return {
        "statusCode": 502,
        "body": json.dumps({
            "message": str(e),
            "notification": sns_error_notification,
        }),
    };


def replace_cloudfront_ssl(new_iam_ssl_id):
    logger.info("Function: replace_cloudfront_ssl")
    replace_msg = {"Get_Last_IAM_SSL_Info": "No Last IAM SSL Information", "Matched_CloudFront": {},
                   "Update_CloudFront_Status": [],
                   "Delete_Last_IAM_SSL_Cert": {}};
    error_tag = False;
    try:
        last_iam_ssl_info = get_last_iam_ssl_from_s3();
    except Exception as e:
        logger.error(traceback.format_exc())
        replace_msg["Get_Last_IAM_SSL_Info"] = "An error occurred when get last IAM SSL info:" + traceback.format_exc()
        return replace_msg;
    if len(last_iam_ssl_info) == 2:
        last_iam_ssl_id = last_iam_ssl_info[0]
        last_iam_ssl_name = last_iam_ssl_info[1]
        replace_msg["Get_Last_IAM_SSL_Info"] = {"IAM_SSL_ID": last_iam_ssl_id, "IAM_SSL_NAME": last_iam_ssl_name}
        list_dist_paginator = cdn_client.get_paginator('list_distributions')
        list_dist_res_iterator = list_dist_paginator.paginate(
            PaginationConfig={
                'MaxItems': os.getenv("MAX_DIST_ITEMS", 200),
                'PageSize': os.getenv("DIST_PAGE_SIZE", 20)
            }
        )

        # 匹配绑定上一次SSL证书的CDN ID
        replace_dist_id_list = []
        error_dist_res_list = []
        for list_dist_res in list_dist_res_iterator:
            if list_dist_res["ResponseMetadata"]["HTTPStatusCode"] == 200:
                dist_list = list_dist_res["DistributionList"]
                if dist_list["Quantity"] > 0:
                    dist_items = dist_list["Items"]
                    for item in dist_items:
                        if "IAMCertificateId" in item["ViewerCertificate"] and item["ViewerCertificate"][
                            "IAMCertificateId"] == last_iam_ssl_id:
                            replace_dist_id_list.append(item["Id"])
            else:
                error_tag = True
                logger.error("List_Dist_Res_Error:" + list_dist_res["ResponseMetadata"])
                error_dist_res_list.append(list_dist_res["ResponseMetadata"])
        if len(error_dist_res_list) == 0 and len(replace_dist_id_list) == 0:
            replace_msg["Matched_CloudFront"] = f"No Matched CloudFront on IAM Cert ID {last_iam_ssl_id}"
        elif len(error_dist_res_list) != 0:
            replace_msg["Matched_CloudFront"]["Error"] = error_dist_res_list
        elif len(replace_dist_id_list) != 0:
            replace_msg["Matched_CloudFront"]["ID_LIST"] = replace_dist_id_list

        # 获取CDN配置，修改CDN配置
        for dist_id in replace_dist_id_list:
            try:
                dist_config_res = cdn_client.get_distribution_config(Id=dist_id)
                logger.info(f'get_dist_config_res:{dist_id},{dist_config_res["ResponseMetadata"]}')
                if dist_config_res["ResponseMetadata"]["HTTPStatusCode"] == 200:
                    ETag = dist_config_res["ETag"]
                    dist_config = dist_config_res["DistributionConfig"]
                    dist_config["ViewerCertificate"]["IAMCertificateId"] = new_iam_ssl_id
                    # dist_config["ViewerCertificate"]["Certificate"] = new_iam_ssl_id
                    update_dist_res = cdn_client.update_distribution(Id=dist_id, IfMatch=ETag,
                                                                     DistributionConfig=dist_config)
                    logger.info(
                        f'update_dist_res:{dist_id},{update_dist_res["ResponseMetadata"]}')
                    if update_dist_res["ResponseMetadata"]["HTTPStatusCode"] == 200:
                        updated_dist_config = update_dist_res["Distribution"]["DistributionConfig"]
                        if "IAMCertificateId" in updated_dist_config["ViewerCertificate"] and \
                                updated_dist_config["ViewerCertificate"]["IAMCertificateId"] == new_iam_ssl_id:
                            replace_msg["Update_CloudFront_Status"].append(
                                {dist_id: "Success"})
                        else:
                            error_tag = True
                            logger.error(f"Update_Dist_Failed {dist_id}: " + updated_dist_config)
                            replace_msg["Update_CloudFront_Status"].append(
                                {dist_id: "Failed"})
                    else:
                        error_tag = True
                        logger.error("Update_Dist_Error:" + update_dist_res["ResponseMetadata"])
                        replace_msg["Update_CloudFront_Status"].append(
                            {dist_id: {"Update_Dist_Error": update_dist_res["ResponseMetadata"]}})
                else:
                    error_tag = True
                    logger.error("Get_Dist_Error:" + dist_config_res["ResponseMetadata"])
                    replace_msg["Update_CloudFront_Status"].append(
                        {dist_id: {"Get_Dist_Error": dist_config_res["ResponseMetadata"]}})
            except Exception as e:
                error_tag = True
                logger.error(traceback.format_exc())
                replace_msg["Update_CloudFront_Status"].append({dist_id: traceback.format_exc()})

        # 如果没有任何错误则可删除证书
        if not error_tag:
            try:
                delete_ssl_res = iam_client.delete_server_certificate(ServerCertificateName=last_iam_ssl_name)
                if delete_ssl_res["ResponseMetadata"]["HTTPStatusCode"] == 200:
                    replace_msg["Delete_Last_IAM_SSL_Cert"] = f"Successfully deleted IAM SSL Cert {last_iam_ssl_name}"
                else:
                    logger.error("Delete_SSL_Res_Error:" + delete_ssl_res["ResponseMetadata"])
                    replace_msg["Delete_Last_IAM_SSL_Cert"] = delete_ssl_res["ResponseMetadata"]
            except Exception as e:
                logger.error("Delete_IAM_Cert_Error:" + traceback.format_exc())
                replace_msg["Delete_Last_IAM_SSL_Cert"] = traceback.format_exc()
        else:
            replace_msg["Delete_Last_IAM_SSL_Cert"] = "Due to a failed CloudFront certificate renewal, please update " \
                                                      "it and then delete the old SSL Cert ."
    return replace_msg


def get_last_iam_ssl_from_s3():
    try:
        logger.info("Function: get_last_iam_ssl_from_s3")
        last_file = f"{CERTBOT_DIR}/{LAST_IAM_SSL_INFO}"
        s3_client.download_file(bucket, LAST_IAM_SSL_INFO, last_file)
        last_file = open(f"{CERTBOT_DIR}/{LAST_IAM_SSL_INFO}", "r")
        file_line = last_file.readlines();
        logger.info(f"file_line:{file_line}")
        last_iam_ssl_id = file_line[0].strip('\n')
        last_iam_ssl_name = file_line[1].strip('\n')
        return [last_iam_ssl_id, last_iam_ssl_name];
    except botocore.exceptions.ClientError as client_e:
        if client_e.response['Error']['Code'] == '404':
            logger.info("IAM Info File Not Found")
            return [];
        else:
            raise client_e
    except Exception as e:
        raise e


def get_iam_ssl_id(iam_ssl_name):
    logger.info("Function: get_iam_ssl_id")
    iam_ssl_info = iam_client.get_server_certificate(ServerCertificateName=iam_ssl_name);
    iam_ssl_id = iam_ssl_info["ServerCertificate"]["ServerCertificateMetadata"]["ServerCertificateId"]
    return iam_ssl_id;


def delete_iam_ssl_cert(iam_ssl_name):
    logger.info("Function: delete_iam_ssl_cert")
    iam_ssl_info = iam_client.get_server_certificate(ServerCertificateName=iam_ssl_name);
    iam_ssl_id = iam_ssl_info["ServerCertificate"]["ServerCertificateMetadata"]["ServerCertificateId"]
    return iam_ssl_id;
