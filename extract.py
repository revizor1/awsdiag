#!/usr/bin/python3
# WONTDO: move Config queries into own file - comments not allowed.
# WONTDO: Token expiration compare to last run duration
import concurrent.futures
import glob
import json
import logging
import os
import re
import time
import warnings
import webbrowser
from time import sleep
import csv

from boto3.session import Session
from botocore.client import Config
from botocore.exceptions import ClientError, OperationNotPageableError, ConnectTimeoutError

import transform


def do_job(id: str, region: str) -> None:
    """This is where the work is done"""
    if not region in [main_region] and DEBUG:
        return
    session = account_session(sso, access_token, id, region)
    if not session:
        return

    kw = {"region_name": region, "id": id, "session": session}
    cred_report = None
    if not region in [main_region]:
        logging.debug(f"[+] {id}:{region}")
    else:
        logging.info(f"[+] {id}:{region}")
        if os.environ.get("id") == id:  ### BREAKPOINT ###
            logging.info("*** Good breakpoint spot ***")

        cred_report = get_credential_report(session=session)
        if cred_report == False:
            _ = generate_credential_report(session=session)

        svc, key, call = "account", "contact", "get_contact_information"
        for o in pg(svc, key, call, **kw):
            account_sso = [s for s in sso_accounts if s["accountId"] == id]
            if bool(account_sso):
                o["emailaddress"] = account_sso[0]["emailAddress"]
            assets[key][f"::{svc}::{id}:contact"] = o
        svc, key, call = "account", "alternate", "get_alternate_contact"
        for o in pg(svc, key, call, op={"AlternateContactType": "SECURITY"}, **kw):
            assets[key][f"::{svc}::{id}:alternate"] = o

        svc, key, call = "apigateway", "apigateway", "get_rest_apis"  # Should do this in all regions
        for o in pg(svc, key, call, **kw):
            assets[key][f"::{svc}:{region}:{id}:{o['id']}"] = o
        svc, key, call = "apigatewayv2", "apigateway", "get_apis"
        for o in pg(svc, key, call, **kw):
            assets[key][f"::{svc}:{region}:{id}:{o['ApiId']}"] = o

        svc, key, call = "appmesh", "appmesh", "list_meshes"  # Should do this in all regions
        for o in pg(svc, key, call, **kw):
            assets[key][o["arn"]] = o

        svc, key, call = "athena", "athena", "list_data_catalogs"  # Should do this in all regions
        for o in pg(svc, key, call, **kw):
            if o["CatalogName"] == "AwsDataCatalog" and o["Type"] == "GLUE":
                continue
            svc, key2, call2 = svc, key, "list_databases"
            for d in pg(svc, key2, call2, op={"CatalogName": o["CatalogName"]}, **kw):
                assets[key2][f"::{svc}:{region}:{id}:{o['CatalogName']}/{d['Name']}"] = d
            assets[key][f"::{svc}:{region}:{id}:{o['CatalogName']}"] = o
        if COMPREHENSIVE:  # Not using the results yet
            # May not be worth it
            svc, key, call = svc, "athenaqueryexecution", "list_query_executions"
            for o in pg(svc, key, call, **kw):
                # logging.info(o)    # --query 'QueryExecution.ResultConfiguration.EncryptionConfiguration'
                svc, key2, call2 = svc, key, "get_query_execution"
                assets[key][f"::{svc}:{region}:{id}:queryexecution/{o}"] = pg(
                    svc, key2, call2, op={"QueryExecutionId": o}, **kw
                )
            svc, key, call = svc, "athenaworkgroup", "list_work_groups"
            for o in pg(svc, key, call, **kw):
                if o["Name"] == "primary":
                    continue
                svc, key2, call2 = svc, key, "get_work_group"
                assets[key][f"::{svc}:{region}:{id}:workgroup/{o['Name']}"] = pg(
                    svc, key2, call2, op={"WorkGroup": o["Name"]}, **kw
                )

        svc, key, call = "cloudfront", "cloudfront", "list_distributions"
        for o in pg(svc, key, call, **kw):
            if o != "Items":
                continue
            assert False  # Data structure check
            assets[key][f"::{svc}:{region}:{id}:{o}"] = o["Items"]

        svc, key, call = "cognito-idp", "cognito", "list_user_pools"  # Should do this in all regions
        for o in pg(svc, key, call, op={"MaxResults": 60}, **kw):
            assets[key][f"::{key}:{region}:{id}:{o['Id']}"] = o

        svc, key, call = "ds", "ds", "describe_directories"
        for o in pg(svc, key, call, **kw):
            assets[key][f"::{svc}:{region}:{id}:{o['DirectoryId']}"] = o

        svc, key, call = "glacier", "glacier", "list_vaults"  # Should do this in all regions
        for o in pg(svc, key, call, **kw):
            assets[key][o["VaultARN"]] = o

        svc, key, call = "glue", "glue", "list_registries"  # Should do this in all regions
        for o in pg(svc, key, call, **kw):
            assets[svc][o["RegistryArn"]] = o
        svc, key, call = "glue", "glue", "get_databases"
        for o in pg(svc, key, call, **kw):
            svc, key2, call2 = svc, key, "get_tables"
            o["Tables"] = pg(svc, key2, call2, op={"DatabaseName": o["Name"]}, **kw)
            assets[key][f"arn:aws:{svc}:{region}:{id}:database/{o['Name']}"] = o

        svc, key, call = "iam", "role", "get_account_authorization_details"
        for o in pg(svc, key, call, op={"Filter": ["Role"]}, **kw):
            if o.get("PolicyName"):
                continue
            if o.get("UserName"):
                continue
            if o.get("GroupName"):
                continue
            if not o.get("RoleName"):
                continue
            if not re.search("/aws-reserved/|/aws-service-role/", o["Path"]):
                assets[key][o["Arn"]] = o
        svc, key, call = "iam", "user", "get_account_authorization_details"
        for o in pg(svc, key, call, op={"Filter": ["User"]}, **kw):
            if not o.get("UserName"):
                continue
            assets[key][o["Arn"]] = o

        svc, key, call = "kinesis", "kinesis", "list_streams"  # Do this in all regions
        for o in pg(svc, key, call, **kw):
            assets[key][o] = o

        svc, key, call = "lakeformation", "lakeformation", "list_resources"  # TODO: Do this in all regions
        for o in pg(svc, key, call, **kw):
            p = o["ResourceArn"].split(":")
            p[4] = id
            p[3] = region
            p[2] = key
            assets[key][":".join(p)] = o

        svc, key, call = "organizations", "organizations", "list_accounts"
        for o in pg(svc, key, call, **kw):
            assets[key][o["Arn"]] = o

        if COMPREHENSIVE:
            svc, key, call = "quicksight", "quicksightnamespaces", "list_namespaces"
            for o in pg(svc, key, call, op={"AwsAccountId": id}, **kw):
                assets[key][o["Arn"]] = o
        svc, key, call = "quicksight", "quicksightdatasets", "list_data_sets"  # FIXME: Do this in all regions
        for o in pg(svc, key, call, op={"AwsAccountId": id}, **kw):
            assets[key][o["Arn"]] = o

        svc, key, call = "route53domains", "route53domains", "list_domains"
        for o in pg(svc, key, call, **kw):
            assert False, key
            assets[key][f"::{svc}:{region}:{id}:{o['DomainName']}"] = o

        svc, key, call = "s3control", "s3ap", "list_access_points"
        for o in pg(svc, key, call, op={"AccountId": id}, **kw):
            assets[key][o["AccessPointArn"]] = o
            svc, key2, call2 = svc, key, "get_access_point"
            for o2 in pg(svc, key2, call2, op={"AccountId": id, "Name": o["Name"]}, **kw):
                assets[key].update({o["AccessPointArn"]: o2})
            assets[key][o["AccessPointArn"]]["BucketPolicy"] = {}
            svc, key2, call2 = svc, key, "get_access_point_policy"
            for policyText in pg(svc, key2, call2, op={"AccountId": id, "Name": o["Name"]}, **kw):
                assets[key][o["AccessPointArn"]]["BucketPolicy"]["policyText"] = policyText

        svc, key, call = "s3", "s3", "list_buckets"
        for o in pg(svc, key, call, **kw):
            reg = main_region
            svc, key2, call2 = svc, key, "get_bucket_location"
            for o2 in pg(svc, key2, call2, op={"Bucket": o["Name"]}, **kw):
                reg = o2
            arn = f"arn:aws:s3:{reg}:{id}:{o['Name']}"
            o["BucketPolicy"] = {}
            svc, key2, call2 = svc, key, "get_bucket_policy"
            for policyText in pg(svc, key2, call2, op={"Bucket": o["Name"]}, **kw):
                o["BucketPolicy"]["policyText"] = policyText
            o["BucketLoggingConfiguration"] = {}
            svc, key2, call2 = svc, key, "get_bucket_logging"
            for loggingConfiguration in pg(svc, key2, call2, op={"Bucket": o["Name"]}, **kw):
                o["BucketLoggingConfiguration"] = loggingConfiguration
            svc, key2, call2 = svc, key, "get_bucket_encryption"
            o["ServerSideEncryptionConfiguration"] = {"rules": pg(svc, key2, call2, op={"Bucket": o["Name"]}, **kw)}
            svc, key2, call2 = svc, key, "get_bucket_policy_status"
            ps = pg(svc, key2, call2, op={"Bucket": o["Name"]}, **kw)
            for p in ps:
                o.update(p)
            assets[key][arn] = o

        svc, key, call = "sagemaker", "sagemaker", "list_notebook_instances"  # Should do this in all regions
        for o in pg(svc, key, call, **kw):
            assets[key][o["NotebookInstanceArn"]] = o
        svc, key, call = "sagemaker", "sagemaker", "list_endpoints"  # Should be a separate namespace?
        for o in pg(svc, key, call, **kw):
            assets[key][o["EndpointArn"]] = o
        svc, key, call = "sagemaker", "sagemaker", "list_models"  # Should be a separate namespace?
        for o in pg(svc, key, call, **kw):
            assets[key][o["ModelArn"]] = o

        svc, key, call = "ses", "ses", "list_identities"  # Should do this in all regions
        for o in pg(svc, key, call, **kw):
            assets[key][f"::{svc}:{region}:{id}:{o}"] = o

        svc, key, call = "sso-admin", "sso", "list_instances"
        for o in pg(svc, key, call, **kw):
            arn = f"::{key}:{region}:{id}:identitystore/{o['IdentityStoreId']}"
            assets[key][arn] = o  # Yes, I know...
            svc2, key2, call2 = "identitystore", "Users", "list_users"
            assets[key][arn][key2] = pg(svc2, key2, call2, op={"IdentityStoreId": o["IdentityStoreId"]}, **kw)

        svc, key, call = "storagegateway", "storagegateway", "list_gateways"  # Should do this in all regions
        for o in pg(svc, key, call, **kw):
            assets[key][o["GatewayARN"]] = o

        svc, key, call = "workspaces", "workspaces", "describe_workspaces"
        for o in pg(svc, key, call, **kw):
            assets[key][f"::{svc}:{region}:{id}:{o['WorkspaceId']}"] = o

    svc, key, call = "acm", "certificate", "list_certificates"
    for o in pg(svc, key, call, **kw):
        assets[key][o["CertificateArn"]] = o
        svc, key2, call2 = svc, key, "describe_certificate"
        for c in pg(svc, key2, call2, op={"CertificateArn": o["CertificateArn"]}, **kw):
            o.update(c)

    svc, key, call = "accessanalyzer", "accessanalyzer", "list_analyzers"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "list_findings"
        o["findings"] = [
            c
            for c in pg(
                svc, key2, call2, op={"analyzerArn": o["arn"], "filter": {"status": {"neq": ["RESOLVED"]}}}, **kw
            )
        ]
        assets[key][o["arn"]] = o

    svc, key, call = "autoscaling", "autoscaling", "describe_auto_scaling_groups"
    for o in pg(svc, key, call, **kw):
        assets[key][o["AutoScalingGroupARN"]] = o

    svc, key, call = "backup", "backup", "list_backup_vaults"
    for o in pg(svc, key, call, **kw):
        assets[key][o["BackupVaultArn"]] = o

    svc, key, call = "batch", "batch", "describe_job_queues"
    for o in pg(svc, key, call, **kw):
        assets[key][o["jobQueueArn"]] = o

    svc, key, call = "codeartifact", "codeartifact", "list_repositories"
    for o in pg(svc, key, call, **kw):
        assets[key][o["arn"]] = o

    svc, key, call = "codebuild", "codebuild", "list_projects"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{svc}:{region}:{id}:{o}"] = o

    svc, key, call = "codecommit", "codecommit", "list_repositories"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{svc}:{region}:{id}:{o['repositoryName']}"] = o

    svc, key, call = "codedeploy", "codedeploy", "list_deployments"
    for o in pg(svc, key, call, **kw):
        assets[key][o] = o

    svc, key, call = "codepipeline", "codepipeline", "list_pipelines"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{svc}:{region}:{id}:{o['name']}"] = o

    svc, key, call = "codestar", "codestar", "list_projects"
    for o in pg(svc, key, call, **kw):
        assert False
        assets[key][o["projectArn"]] = o

    svc, key, call = "datasync", "datasync", "list_tasks"
    for o in pg(svc, key, call, **kw):
        assets[key][o["TaskArn"]] = o

    svc, key, call = "directconnect", "dxgw", "describe_direct_connect_gateways"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "describe_direct_connect_gateway_associations"
        o["associations"] = pg(svc, key2, call2, op={"directConnectGatewayId": o["directConnectGatewayId"]}, **kw)
        svc, key2, call2 = svc, key, "describe_direct_connect_gateway_attachments"
        o["attachments"] = pg(svc, key2, call2, op={"directConnectGatewayId": o["directConnectGatewayId"]}, **kw)
        assets[key][f"::{key}:{region}:{id}:{o['directConnectGatewayId']}"] = o
    svc, key, call = "directconnect", "dxcon", "describe_connections"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "describe_virtual_interfaces"
        o["virtualinterfaces"] = pg(svc, key2, call2, op={"connectionId": o["connectionId"]}, **kw)
        assets[key][f"::{svc}:{region}:{id}:{o['connectionId']}"] = o
    if COMPREHENSIVE:  # adds 1 minute
        svc, key, call = "directconnect", "dxlag", "describe_lags"
        for o in pg(svc, key, call, **kw):
            assets[key][f"::{svc}:{region}:{id}:{o['lagId']}"] = o
        svc, key, call = "directconnect", "dxvgw", "describe_virtual_gateways"
        for o in pg(svc, key, call, **kw):
            assets[key][f"::{svc}:{region}:{id}:{o['virtualGatewayId']}"] = o

    svc, key, call = "dynamodb", "dynamodb", "list_tables"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "describe_table"
        assets[key][f"arn:aws:{svc}:{region}:{id}:table/{o}"] = pg(svc, key2, call2, op={"TableName": o}, **kw)

    if not region in assets.get("SSM", {}):  # No need to query parameters in every account if region reported already
        svc, key, call = "ssm", "SSMAMI", "get_parameters_by_path"
        SSMPATHS = [
            "/aws/service/ami-amazon-linux-latest",
            "/aws/service/ami-windows-latest",
            "/aws/service/ami-macos-latest",
        ]
        for x in SSMPATHS:
            for o in pg(svc, key, call, op={"Path": x, "Recursive": False}, **kw):
                value = o["Value"]
                o["account"] = id
                o["region"] = region
                if value.startswith("{"):
                    value = json.loads(value).get("image_id")
                assets[key][value] = o
                if not "SSM" in assets:
                    assets["SSM"] = {}
                if not region in assets["SSM"]:
                    assets["SSM"][region] = region
    svc, key, call = "ssm", "ssmec2", "describe_instance_information"
    for o in pg(svc, key, call, **kw):
        assets[key][f"arn:aws:{svc}:{region}:{id}:managed-instance-inventory/{o['InstanceId']}"] = {
            "AWS:InstanceInformation": {"Content": {o["InstanceId"]: o}}
        }

    svc, key, call = "ec2", "ec2", "describe_instances"
    for reservations in pg(svc, key, call, **kw):
        for o in reservations.get("Instances", {}):
            assets[key][f"arn:aws:{svc}:{region}:{id}:instance/{o['InstanceId']}"] = o
    svc, key, call = "ec2", "ebsdefaultencryption", "get_ebs_encryption_by_default"
    for o in pg(svc, key, call, **kw):
        assets[key][f"arn:aws:{svc}:{region}:{id}:ebs_encryption_by_default"] = o
    svc, key, call = "ec2", "natgw", "describe_nat_gateways"
    for o in pg(svc, key, call, **kw):
        assets[key][f"arn:aws:{svc}:{region}:{id}:natgateway/{o['NatGatewayId']}"] = o
    svc, key, call = "ec2", "igw", "describe_internet_gateways"
    for o in pg(svc, key, call, **kw):
        assets[key][f"arn:aws:{svc}:{region}:{id}:internet-gateway/{o['InternetGatewayId']}"] = o
    svc, key, call = "ec2", "tgw", "describe_transit_gateways"
    for o in pg(svc, key, call, **kw):
        assets[key][o["TransitGatewayArn"]] = o
    svc, key, call = "ec2", "customergateway", "describe_customer_gateways"
    for o in pg(svc, key, call, **kw):
        assets[key][f"arn:aws:{svc}:{region}:{id}:customer-gateway/{o['CustomerGatewayId']}"] = o
    svc, key, call = "ec2", "vpc", "describe_vpcs"
    for o in pg(svc, key, call, **kw):
        assets[key][f"arn:aws:{svc}:{region}:{id}:vpc/{o['VpcId']}"] = o
    svc, key, call = "ec2", "vpce", "describe_vpc_endpoints"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{svc}:{region}:{id}:vpc-endpoint/{o['VpcEndpointId']}"] = o
    svc, key, call = "ec2", "vpces", "describe_vpc_endpoint_services"
    for o in pg(svc, key, call, op={"Filters": [{"Name": "owner", "Values": [id]}]}, **kw):
        svc, key2, call2 = svc, key, "describe_vpc_endpoint_service_permissions"
        o["vpcespermissions"] = pg(svc, key2, call2, op={"ServiceId": o["ServiceId"]}, **kw)
        assets[key][f"arn:aws:{svc}:{region}:{id}:vpc-endpoint-service/{o['ServiceId']}"] = o
        svc, key2, call2 = svc, key, "describe_vpc_endpoint_service_configurations"
        for c in pg(svc, key2, call2, op={"ServiceIds": [o["ServiceId"]]}, **kw):
            assets[key][f"arn:aws:{svc}:{region}:{id}:vpc-endpoint-service/{o['ServiceId']}"].update(c)
    svc, key, call = "ec2", "clientvpnendpoint", "describe_client_vpn_endpoints"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{key}:{region}:{id}:{o['ClientVpnEndpointId']}"] = o
    svc, key, call = "ec2", "vpngateway", "describe_vpn_gateways"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{key}:{region}:{id}:{o['VpnGatewayId']}"] = o
    svc, key, call = "ec2", "vpnconnection", "describe_vpn_connections"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{key}:{region}:{id}:{o['VpnConnectionId']}"] = o
    svc, key, call = "ec2", "vpcx", "describe_vpc_peering_connections"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{svc}:{region}:{id}:vpc-peering-connection/{o['VpcPeeringConnectionId']}"] = o
    svc, key, call = "ec2", "subnet", "describe_subnets"
    for o in pg(svc, key, call, **kw):
        assets[key][o["SubnetArn"]] = o
    svc, key, call = "ec2", "eni", "describe_network_interfaces"
    for o in pg(svc, key, call, **kw):
        farn = f"arn:aws:ec2:{region}:{o['OwnerId']}:network-interface/{o['NetworkInterfaceId']}"
        if assets[key].get(farn):
            assets[key][farn].update(o)
        else:
            assets[key][farn] = o
    svc, key, call = "ec2", "nacl", "describe_network_acls"
    for o in pg(svc, key, call, **kw):
        assets[key][f"arn:aws:ec2:{region}:{o['OwnerId']}:nacl/{o['NetworkAclId']}"] = o
    svc, key, call = "ec2", "flowlog", "describe_flow_logs"
    for o in pg(svc, key, call, **kw):
        assets[key][f"arn:aws:ec2:{region}:{id}:flow-log/{o['FlowLogId']}"] = o
    svc, key, call = "ec2", "tgwattachment", "describe_transit_gateway_attachments"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{svc}:{region}:{id}:transit-gateway-attachment/{o['TransitGatewayAttachmentId']}"] = o
    svc, key, call = "ec2", "tgwconnect", "describe_transit_gateway_connects"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{key}:{region}:{id}:transit-gateway/{o.get('TransitGatewayId')}"] = o
        # assert False, key  # FIXME: ARN collision with TGW?
    svc, key, call = "ec2", "tgwpeeringattachment", "describe_transit_gateway_peering_attachments"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{key}:{region}:{id}:{o['TransitGatewayAttachmentId']}"] = o
    svc, key, call = "ec2", "tgwroutetable", "describe_transit_gateway_route_tables"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "search_transit_gateway_routes"
        op = {
            "TransitGatewayRouteTableId": o["TransitGatewayRouteTableId"],
            "Filters": [{"Name": "type", "Values": ["static"]}],
        }
        o["routes"] = pg(svc, key2, call2, op=op, **kw)
        assets[key][f"arn:aws:{svc}:{region}:{id}:transit-gateway-route-table/{o['TransitGatewayRouteTableId']}"] = o
    svc, key, call = "ec2", "routetable", "describe_route_tables"
    for o in pg(svc, key, call, **kw):
        assets[key][f"arn:aws:{svc}:{region}:{id}:route-table/{o['RouteTableId']}"] = o
    svc, key, call = "ec2", "sg", "describe_security_groups"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{key}:{region}:{id}:{o['GroupId']}"] = o
    # Must run after the SSM parameter inventory
    svc, key, call = "ec2", "ami", "describe_images"
    for o in pg(svc, key, call, op={"Owners": ["self"]}, **kw):
        assets[key][f"::{key}:{region}:{id}:{o['ImageId']}"] = [o][0]  # To dereference a dict
        if o["ImageId"] in assets.get("SSMAMI", {}):  # AMZ ami; skip permissions checks
            logging.debug(f"{id} {region} Skipping ami permissions check for {o['ImageId']}")
            continue
        svc, key2, call2 = svc, "ramresourceingress", "describe_image_attribute"
        # if COMPREHENSIVE and not "AwsBackup" in o["Name"]:
        if not "AwsBackup" in o["Name"]:
            op = {"Attribute": "launchPermission", "ImageId": o["ImageId"]}
            o["LaunchPermission"] = pg(svc, key2, call2, op=op, **kw)
            for o2 in o["LaunchPermission"]:
                if type(o2) == str:
                    continue
                elif o2.get("UserId"):
                    from_to = f"::ram:{region}:{o2['UserId']}:from/{id}"
                    if not from_to in assets[key2]:
                        assets[key2][from_to] = {}
                    o["type"] = f"ami:{o['PlatformDetails']}"
                    o["resourcesharearn"] = f"::{key}:{region}:{o['OwnerId']}:{o['ImageId']}"
                    assets[key2][from_to].update({o["resourcesharearn"]: o})

                    ami_share = f"::ram:{region}:{id}:resource-share/ami"
                    o["arn"] = f"::{key}:{region}:{o['OwnerId']}:{o['ImageId']}"
                    o["resourcesharearn"] = f"::{key}:{region}:{o['OwnerId']}:{ami_share}"
                    if not "ram" in assets:
                        assets["ram"] = {}
                    if not ami_share in assets["ram"]:
                        assets["ram"][ami_share] = []
                    assets["ram"][ami_share].append(o)  # FIXME: multi-shared AMIs
        else:
            if not "AWSBACKUP" in assets:
                assets["AWSBACKUP"] = {}
            for b in o["BlockDeviceMappings"]:
                if not b.get("Ebs"):
                    continue
                assets["AWSBACKUP"].update({b["Ebs"].get("SnapshotId"): o["ImageId"]})

    svc, key, call = "ec2", "ramresourceingress", "describe_images"
    for o in pg(svc, key, call, op={"ExecutableUsers": ["self"]}, **kw):
        farn = f"::ram:{region}:{id}:from/{o['OwnerId']}"
        if not farn in assets[key]:
            assets[key][farn] = {}
        o["type"] = f"ami:{o['PlatformDetails']}"
        o["resourcesharearn"] = f"::ami:{region}:{o['OwnerId']}:{o['ImageId']}"
        assets[key][farn][o["resourcesharearn"]] = o
    svc, key, call = "ec2", "ebs", "describe_volumes"
    for o in pg(svc, key, call, **kw):
        assets[key][f"arn:aws:ec2:{region}:{id}:volume/{o['VolumeId']}"] = o
    svc, key, call = "ec2", "ebssnapshot", "describe_snapshots"
    for o in pg(svc, key, call, op={"OwnerIds": ["self"]}, **kw):
        # if COMPREHENSIVE:
        if o["SnapshotId"] in assets.get("AWSBACKUP", {}):  # FIXME: shouldn't skip
            logging.debug(f"{id} {region} Skipping snapshot permissions check for {o['SnapshotId']}")
        else:
            svc, key2, call2 = svc, "ramresourceingress", "describe_snapshot_attribute"
            op = {"Attribute": "createVolumePermission", "SnapshotId": o["SnapshotId"]}
            o["createVolumePermission"] = pg(svc, key2, call2, op=op, **kw)
            for o2 in o["createVolumePermission"]:
                if type(o2) == str:
                    continue
                elif o2.get("Group"):
                    logging.warning(f"[      ] {id}:{region}:{call2}: Group {o2}")
                elif o2.get("UserId"):
                    from_to = f"::ram:{region}:{o2['UserId']}:from/{id}"
                    if not from_to in assets[key2]:
                        assets[key2][from_to] = {}
                    o2["type"] = "ebs:snapshot"
                    o2["resourcesharearn"] = f"arn:aws:{svc}:{region}:{o['OwnerId']}:snapshot/{o['SnapshotId']}"
                    assets[key2][from_to].update({o2["resourcesharearn"]: o2})
        assets[key][f"arn:aws:{svc}:{region}:{id}:snapshot/{o['SnapshotId']}"] = o

    svc, key, call = "ecr", "ecr", "describe_repositories"
    for o in pg(svc, key, call, **kw):
        assets[key][o["repositoryArn"]] = o

    # if COMPREHENSIVE:  # Nothing yet
    svc, key, call = "ecs", "ecs", "list_tasks"
    for o in pg(svc, key, call, **kw):
        assets[key][o["taskArns"]] = o
    hits = False
    svc, key, call = "ecs", "ecs", "list_clusters"
    for o in pg(svc, key, call, **kw):
        hits = True
        svc, key2, call2 = svc, key, "describe_clusters"
        for c in pg(svc, key2, call2, op={"clusters": [o]}, **kw):
            assets[key][c["clusterArn"]] = c
    if hits:
        svc, key, call = "ecs", "ecs", "list_container_instances"
        for o in pg(svc, key, call, **kw):
            assets[key][o] = o
        # except:
        #     # Exception has occurred: ClusterNotFoundException (note: full exception trace is shown but execution is paused at: do_job)
        #     # An error occurred (ClusterNotFoundException) when calling the ListContainerInstances operation: Cluster not found.
        #     logging.warning(f"[x] {id}:{region} {svc}:{call} call failed")

    svc, key, call = "efs", "efs", "describe_file_systems"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = "efs", "mounttargets", "describe_mount_targets"
        o[key2] = pg(svc, key2, call2, op={"FileSystemId": o["FileSystemId"]}, **kw)
        svc, key2, call2 = "efs", "filesystempolicy", "describe_file_system_policy"
        for o2 in pg(svc, key2, call2, op={"FileSystemId": o["FileSystemId"]}, **kw):
            o[key2] = o2
        assets[key][o["FileSystemArn"]] = o

    svc, key, call = "eks", "eks", "list_clusters"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "describe_cluster"
        for o2 in pg(svc, key2, call2, op={"name": o}, **kw):
            assets[key2][o2["arn"]] = o2
        svc, key2, call2 = svc, "fargate", "list_fargate_profiles"
        for o2 in pg(svc, key2, call2, op={"clusterName": o}, **kw):
            assets[key2][o2["arn"]] = o2

    svc, key, call = "elasticache", "elasticache", "describe_cache_clusters"
    for o in pg(svc, key, call, **kw):
        assets[key][o["ARN"]] = o

    svc, key, call = "elasticbeanstalk", "elasticbeanstalk", "describe_applications"
    for o in pg(svc, key, call, **kw):
        assets[key][o["ApplicationArn"]] = o

    svc, key, call = "elb", "elb", "describe_load_balancers"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, "loadbalancerattributes", "describe_load_balancer_attributes"
        op = {"LoadBalancerName": o["LoadBalancerName"]}
        o[key2] = pg(svc, key2, call2, op=op, **kw)
        svc, key2, call2 = svc, "loadbalancerpolicies", "describe_load_balancer_policies"
        op = {"LoadBalancerName": o["LoadBalancerName"]}
        o[key2] = pg(svc, key2, call2, op=op, **kw)
        svc, key2, call2 = svc, "tags", "describe_tags"
        op = {"LoadBalancerNames": [o["LoadBalancerName"]]}
        o[key2] = pg(svc, key2, call2, op=op, **kw)  # Superfluous nesting
        assets[key][f"arn:aws:elasticloadbalancing:{region}:{id}:loadbalancer/{o['LoadBalancerName']}"] = o

    svc, key, call = "elbv2", "elbv2", "describe_load_balancers"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, "loadbalancerattributes", "describe_load_balancer_attributes"
        op = {"LoadBalancerArn": o["LoadBalancerArn"]}
        o[key2] = pg(svc, key2, call2, op=op, **kw)
        svc, key2, call2 = svc, "Listeners", "describe_listeners"
        o[key2] = pg(svc, key2, call2, op=op, **kw)
        if not "TargetGroups" in o:
            o["TargetGroups"] = []
        svc, key2, call2 = svc, "targetgroup", "describe_target_groups"
        for o2 in pg(svc, key2, call2, op=op, **kw):
            svc, key3, call3 = svc, "targethealth", "describe_target_health"
            o2["TargetHealth"] = [
                o3["Target"]["Id"] for o3 in pg(svc, key3, call3, op={"TargetGroupArn": o2["TargetGroupArn"]}, **kw)
            ]
            o["TargetGroups"].append(o2)
        assets[key][o["LoadBalancerArn"]] = o

    svc, key, call = "emr", "emr", "list_clusters"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "describe_cluster"
        op = {"ClusterId": o["Id"]}
        o["config"] = pg(svc, key2, call2, op=op, **kw)
        svc, key2, call2 = svc, "instancefleet", "list_instance_fleets"
        o[key2] = pg(svc, key2, call2, op=op, **kw)
        svc, key2, call2 = svc, "instancegroup", "list_instance_groups"
        o[key2] = pg(svc, key2, call2, op=op, **kw)
        svc, key2, call2 = svc, "instance", "list_instances"
        o[key2] = pg(svc, key2, call2, op=op, **kw)
        svc, key2, call2 = svc, "bootstrap", "list_bootstrap_actions"
        o[key2] = pg(svc, key2, call2, op=op, **kw)
        assets[key][o["ClusterArn"]] = o

    svc, key, call = "emr-serverless", "emr-serverless", "list_applications"
    for o in pg(svc, key, call, **kw):
        assets[key][o["arn"]] = o

    svc, key, call = "events", "event", "list_rules"
    for o in pg(svc, key, call, **kw):
        assets[key][o["Arn"]] = o

    svc, key, call = "firehose", "firehose", "list_delivery_streams"
    for o in pg(svc, key, call, **kw):
        assets[key][o["Arn"]] = o

    svc, key, call = ("fsx", "fsx", "describe_file_systems")
    for o in pg(svc, key, call, **kw):
        assets[key][o["ResourceARN"]] = o
    # svc, key, call = ("fsx", "fsxvol", "describe_volumes")
    # for o in pg(svc, key, call, **kw):
    #     assets[key][o["ResourceARN"]] = o
    # svc, key, call = ("fsx", "fsxassn", "describe_data_repository_associations")
    # for o in pg(svc, key, call, **kw):
    #     assets[key][o["ResourceARN"]] = o
    if COMPREHENSIVE:
        svc, key, call = ("fsx", "fsxvm", "describe_storage_virtual_machines")
        for o in pg(svc, key, call, **kw):
            assets[key][o["ResourceARN"]] = o

    if region == "us-west-2":  # Managed through us-west-2 only
        svc, key, call = "globalaccelerator", "gax", "list_accelerators"
        for o in pg(svc, key, call, **kw):
            assets[key][o["AcceleratorArn"]] = o

    svc, key, call = "kafka", "kafka", "list_clusters"
    for o in pg(svc, key, call, **kw):
        assets[key][o["ClusterArn"]] = o
    svc, key, call = "kafka", "kafka", "list_clusters_v2"  # Serverless
    for o in pg(svc, key, call, **kw):
        assets[key][o["ClusterArn"]] = o

    svc, key, call = "kms", "kms", "list_keys"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "describe_key"
        op = {"KeyId": o["KeyId"]}
        for o2 in pg(svc, key2, call2, op=op, **kw):
            if not o2.get("KeyManager") == "CUSTOMER":
                continue
            if o2.get("KeyState") in ["PendingDeletion", "PendingReplicaDeletion"]:
                continue
            svc, key3, call3 = svc, key, "list_key_policies"
            for o3 in pg(svc, key3, call3, op=op, **kw):
                o2["Policy"] = {}
                svc, key4, call4 = svc, key, "get_key_policy"
                o4 = pg(svc, key4, call4, op={"KeyId": o["KeyId"], "PolicyName": o3}, **kw)
                if bool(o4):
                    o2.update({"Policy": o4[0]})
            svc, key3, call3 = svc, key, "get_key_rotation_status"
            o2["KeyRotationStatus"] = (
                session.client(svc, region_name=region).get_key_rotation_status(op=op).get("KeyRotationEnabled")
            )
            assets[key][o2["Arn"]] = o2

    svc, key, call = "lambda", "lambda", "list_functions"
    for o in pg(svc, key, call, **kw):
        if not re.search(lambda_filter, o["FunctionArn"]):
            assets[key][o["FunctionArn"]] = o

    svc, key, call = "mq", "mq", "list_brokers"
    for o in pg(svc, key, call, **kw):
        assets[key][o] = o

    svc, key, call = "network-firewall", "networkfirewall", "list_firewalls"
    for o in pg(svc, key, call, **kw):
        assets[key][o["FirewallArn"]] = o

    svc, key, call = "opensearch", "opensearch", "list_domain_names"
    for o in pg(svc, key, call, **kw):
        assets[key][o] = o

    ram = False
    svc, key, call = "ram", "ram", "list_resources"
    for o in pg(svc, key, call, op={"resourceOwner": "SELF"}, **kw):
        if not assets[key].get(o["resourceShareArn"]):
            assets[key][o["resourceShareArn"]] = []
        assets[key][o["resourceShareArn"]].append(o)
        ram = True
    if ram:
        svc, key, call = "ram", "ramshareegress", "get_resource_shares"
        for o in pg(svc, key, call, op={"resourceOwner": "SELF"}, **kw):
            assets[key][o["resourceShareArn"]] = o
    svc, key, call = "ram", "ramresourceingress", "list_resources"
    for o in pg(svc, key, call, op={"resourceOwner": "OTHER-ACCOUNTS"}, **kw):
        farn = f"::{svc}:{region}:{id}:from/{o['arn'].split(':')[4]}"
        if not farn in assets[key]:
            assets[key][farn] = {}
        assets[key][farn].update({o["arn"]: o})  # Is resourceShareArn a better key?
    # svc, key, call = "ram", "ramprincipalingress", "list_principals"
    # for o in pg(svc, key, call, op={"resourceOwner": "OTHER-ACCOUNTS"}, **kw):
    #     assets[key][f"::{svc}:{region}:{id}:{key}/{o['id']}"] = o
    # svc, key, call = "ram", "ramprincipalegress", "list_principals"
    # for o in pg(svc, key, call, op={"resourceOwner": "SELF"}, **kw):
    #     assets[key][f"::{svc}:{region}:{id}:{key}/{o['id']}"] = o

    svc, key, call = "rds", "rds", "describe_db_instances"
    for o in pg(svc, key, call, **kw):
        assets[key][f"arn:aws:{key}:{region}:{id}:db:{o['DBInstanceIdentifier']}"] = o

    svc, key, call = "rds", "rdssnapshot", "describe_db_snapshots"
    for o in pg(svc, key, call, **kw):
        assets[key][o["DBSnapshotArn"]] = o

    svc, key, call = "redshift", "redshift", "describe_clusters"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{key}:{region}:{id}:{o['ClusterIdentifier']}"] = o

    svc, key, call = "route53", "route53", "list_hosted_zones"
    for o in pg(svc, key, call, **kw):
        assets[key][f"::{svc}:{region}:{id}:{o['Id']}"] = o

    svc, key, call = "route53resolver", "route53resolver", "list_resolver_endpoints"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "list_resolver_endpoint_ip_addresses"
        o["addresses"] = pg(
            svc, key2, call2, op={"ResolverEndpointId": o["Id"]}, **kw
        )  # + get_resolver_query_log_config
        assets[key][o["Arn"]] = o

    svc, key, call = "secretsmanager", "secretsmanager", "list_secrets"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "get_resource_policy"
        try:
            res = session.client(svc, region_name=region).get_resource_policy(SecretId=o["ARN"]).get("ResourcePolicy")
            if bool(res):
                o["resourcepolicy"] = res
        except:
            pass
        assets[key][o["ARN"]] = o

    svc, key, call = "servicediscovery", "servicediscovery", "list_namespaces"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "list_services"
        op = {"Filters": [{"Name": "NAMESPACE_ID", "Values": [o["Id"]], "Condition": "EQ"}]}
        for o2 in pg(svc, key2, call2, op=op, **kw):
            if not "services" in o:
                o["services"] = {}
            svc, key3, call3 = svc, key, "list_instances"  # Have no discovered services to test against
            op3 = {"ServiceId": o2["ServiceId"]}
            o2["instances"] = pg(svc, key3, call3, op=op3, **kw)
            o["services"][o2["ServiceId"]] = o2
        assets[key][o["Arn"]] = o

    svc, key, call = "sns", "sns", "list_topics"
    for o in pg(svc, key, call, **kw):
        if re.search("|".join(sns_skip), o["TopicArn"]):
            continue
        svc, key2, call2 = svc, key, "get_topic_attributes"
        for atr in pg(svc, key2, call2, op={"TopicArn": o["TopicArn"]}, **kw):
            o.update(atr)
        assets[key][o["TopicArn"]] = o

    svc, key, call = "sqs", "sqs", "list_queues"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "get_queue_attributes"
        for o2 in pg(svc, key2, call2, op={"QueueUrl": o, "AttributeNames": ["All"]}, **kw):
            assets[key][o2["QueueArn"]] = o2

    svc, key, call = "transfer", "transfer", "list_servers"
    for o in pg(svc, key, call, **kw):
        svc, key2, call2 = svc, key, "list_users"
        o["users"] = pg(svc, key2, call2, op={"ServerId": o["ServerId"]}, **kw)
        assets[key][o["Arn"]] = o

    svc, key, call = "wafv2", "wafv2webacl", "list_web_acls"
    for o in pg(svc, key, call, op={"Scope": "REGIONAL"}, **kw):
        svc, key2, call2 = svc, key, "list_resources_for_web_acl"
        o["attachments"] = pg(svc, key2, call2, op={"WebACLArn": o["ARN"]}, **kw)
        assets[key][o["ARN"]] = o

    if region == main_region and not cred_report:
        cred_report = get_credential_report(session=session)
    if cred_report:  # Should only fire for main region
        content = cred_report.decode("utf-8")
        content_lines = content.split("\n")
        creds_reader = csv.DictReader(content_lines, delimiter=",")
        o = dict(enumerate(list(creds_reader)))
        if not "creds" in assets:
            assets["creds"] = {}
        assets["creds"][f"::creds:{region}:{id}:"] = list(o.values())


def config_results(k):
    PAGE = 100
    return_results = {}
    query_expression = config_q[k]
    client = account_session(sso, access_token, sec_account_id, main_region).client("config")
    logging.info(f"AWS Config: {query_expression}")
    restypes = []
    for attempt in range(3):
        try:
            for c in client.describe_configuration_aggregators()["ConfigurationAggregators"]:
                aggr = {"ConfigurationAggregatorName": c["ConfigurationAggregatorName"]}
                paginator = client.get_paginator("select_aggregate_resource_config")
                page_iterator = paginator.paginate(Expression=query_expression, **aggr, Limit=PAGE)
                results = [acct for page in page_iterator for acct in page["Results"]]
                cis = []
                if os.path.exists("./data/resourcetypes.txt"):
                    restypes = open("data/resourcetypes.txt", "r").read().split()
                for result in results:
                    r = json.loads(result)
                    if not "resourceId" in r:
                        if r["resourceType"] in restypes:
                            continue
                        logging.warning(f"[*] New resource type detected: {r['resourceType']}")
                        if not bool(cis):
                            open("data/resourcetypes.txt", "a").write(r["resourceType"] + "\n")
                        continue
                    cis.append(
                        {
                            "SourceAccountId": r["accountId"],
                            "SourceRegion": "us-east-1" if r["awsRegion"] == "global" else r["awsRegion"],
                            "ResourceId": r["resourceId"],
                            "ResourceType": r["resourceType"],
                        }
                    )
                batches = [cis[x : x + PAGE] for x in range(0, len(cis), PAGE)]
                for batch in batches:
                    i = 0
                    try:
                        response = client.batch_get_aggregate_resource_config(ResourceIdentifiers=batch, **aggr)
                    except ClientError as e:
                        i += 1
                        if i > 3:
                            logging.warning(f"... #{i} Throttled {k} calls too many times. ({e})")
                            exit(1)
                        if i > 1:
                            logging.warning(f"... #{i} Getting throttled for {k} ({e})")
                        sleep(4**i)
                        response = client.batch_get_aggregate_resource_config(ResourceIdentifiers=batch, **aggr)
                    for item in response["BaseConfigurationItems"]:
                        if not k in config:
                            config[k] = {}
                        o = json.loads(item["configuration"])
                        for p, v in item.get("supplementaryConfiguration", {}).items():
                            o.update({p: json.loads(v) if type(v) == str else v})

                        if not "arn" in item:
                            if not item["resourceType"] in alerttypes + [
                                "AWS::Config::ConfigurationRecorder",
                                "AWS::Glue::Classifier",
                                "AWS::Glue::Job",
                                "AWS::S3::AccountPublicAccessBlock",
                            ]:
                                alerttypes.append(item["resourceType"])
                                logging.warning(f"*** No ARN property found for {k} CI: {item}")
                            item["arn"] = f"arn:aws:{k}:{item['awsRegion']}:{item['accountId']}:{item['resourceId']}"

                        if not re.search(r"\d{12}", item["arn"]):
                            ap = item["arn"].split(":")
                            ap[3] = item["awsRegion"] if item["awsRegion"] != "global" else main_region
                            ap[4] = item["accountId"]
                            item["arn"] = ":".join(ap)
                        elif item["resourceType"] == "AWS::IAM::Role":
                            pass
                        elif not (
                            len(item["arn"].split(":")) > 3
                            and item["arn"].split(":")[3]
                            and item["arn"].split(":")[3] != "global"
                        ):  # Has to be after Role
                            ap = item["arn"].split(":")
                            ap[3] = item["awsRegion"] if item["awsRegion"] != "global" else main_region
                            ap[4] = item["accountId"]
                            item["arn"] = ":".join(ap)

                        if item["resourceType"] == "AWS::S3::Bucket":
                            item["arn"] = f"arn:aws:{k}:{item['awsRegion']}:{item['accountId']}:{o['name']}"
                        elif item["resourceType"] == "AWS::S3::AccountPublicAccessBlock":
                            item[
                                "arn"
                            ] = f"arn:aws:{k}:{item['awsRegion']}:{item['accountId']}:AccountPublicAccessBlock"
                        elif item["resourceType"] == "AWS::Config::ConfigurationRecorder" and o["Recording"]:
                            item["arn"] = f"arn:aws:{k}:{item['awsRegion']}:{item['accountId']}:{o['Name']}"

                        r_r = {item["arn"]: o}
                        if not item["accountId"] in config[k]:
                            config[k][item["accountId"]] = {}
                        if not item["awsRegion"] in config[k][item["accountId"]]:
                            config[k][item["accountId"]][item["awsRegion"]] = {}
                        config[k][item["accountId"]][item["awsRegion"]].update(r_r)
                        return_results.update(r_r)
            if not os.path.exists("./data"):
                os.makedirs("./data")
            fn = f"data/config_{k}.json"
            if bool(return_results):
                with open(fn, "w") as fout:
                    text = ",\n".join(
                        ['"' + s + '": ' + json.dumps(return_results[s], default=str) for s in sorted(return_results)]
                    )
                    fout.write("{\n" + text + "\n}")

            else:
                os.remove(fn) if os.path.exists(fn) else None
            return
        except:
            sleep(2**attempt)


def get_credential_report(session):
    """
    Gets the most recently generated credentials report about the current account.

    :return: The credentials report.
    """
    try:
        response = session.client("iam").get_credential_report()
    except ClientError as e:
        logging.debug(f"Couldn't get credentials report: {e}")
        return False
    else:
        return response["Content"]


def generate_credential_report(session):
    """
    Starts generation of a credentials report about the current account. After
    calling this function to generate the report, call get_credential_report
    to get the latest report. A new report can be generated a minimum of four hours
    after the last one was generated.
    """
    try:
        response = session.client("iam").generate_credential_report()
        logging.debug("Generating credentials report for your account")
    except ClientError as e:
        if e.response["Error"]["Code"] in ["LimitExceeded"]:
            logging.debug(f"{e}")
        else:
            logging.warning(f"Couldn't generate a credentials report for your account: {e}")
        raise
    else:
        return response


def get_oidc_token(start_url: str, session: Session) -> str:
    token = {}
    sso_oidc = session.client("sso-oidc")
    client_creds = sso_oidc.register_client(clientName="pz", clientType="public")
    kw = {"clientId": client_creds["clientId"], "clientSecret": client_creds["clientSecret"]}
    device_authorization = sso_oidc.start_device_authorization(startUrl=start_url, **kw)
    url = device_authorization["verificationUriComplete"]
    expires_in, interval = device_authorization["expiresIn"], device_authorization["interval"]
    kw["deviceCode"] = device_authorization["deviceCode"]
    kw["grantType"] = "urn:ietf:params:oauth:grant-type:device_code"
    webbrowser.open(url, autoraise=True)
    for _ in range(1, expires_in // interval + 1):
        sleep(interval)
        try:
            token = sso_oidc.create_token(**kw)
            break
        except sso_oidc.exceptions.AuthorizationPendingException:
            pass
    logging.warning(f"Token expires in {token['expiresIn']//60} min")
    return token["accessToken"]


def region_is_available(session: Session, id: str):  # -> bool:
    r = False
    region = session.region_name
    if region in ["ap-northeast-3"]:
        return r
    try:
        # session.client("ec2", region_name=region).describe_internet_gateways(MaxResults=5)
        r = session.client("ec2", region_name=region).describe_vpcs(MaxResults=5)
        if bool(r.get("Vpcs")):
            return len(r)
        r = {id: region}
    except ClientError as e:
        if e.response["Error"]["Code"] in ["DryRunOperation"]:
            r = {id: region}
            return r
        r = False
        if not e.response["Error"]["Code"] in [
            "UnauthorizedOperation",
            "InvalidClientTokenId",
            "AccessDeniedException",
            "AuthFailure",
        ]:
            logging.warning(f"::error:{id}:{region}:{e.response['Error']['Code']} ClientError {e}")
            add_record("error", f"::error:{id}:{region}:ec2:describe_vpcs", e)
    except KeyError as e:
        r = {True: region}
        logging.warning(f"{id}:{region}: KeyError {e}. Defaulting to Proceed. Check multithreading")
    return r


def account_session(sso, access_token: str, id: str, region: str) -> Session:  # type: ignore
    # Takes sso client session object, access token, and returns a session object for a given account ID
    kw = {"accessToken": access_token, "accountId": id}
    credentials = {}
    account_roles = sso.list_account_roles(**kw)
    if not bool(account_roles):
        logging.warning(f"No account roles found for {id}")
    roles = [r for r in account_roles["roleList"] if re.search(role_name_pattern, r["roleName"])]
    if not bool(roles):
        if not DEBUG and region == main_region:
            logging.info(f"No suitable account roles found for {id}. Using what I got...")
        roles = [r for r in account_roles["roleList"]]
    role = roles[-1]  # simplifying here for demo purposes

    logging.debug(f"Assuming {role['roleName']} role in {id} account in {region}")
    try:
        role_creds = sso.get_role_credentials(roleName=role["roleName"], **kw)
        credentials = role_creds["roleCredentials"]
    except ClientError as ex:
        if "ForbiddenException" in f"{ex}":
            add_record("error", f"::error:{id}:{region}:sso:account_session", ex)
            return  # type: ignore
    try:
        session = Session(
            region_name=region,
            aws_access_key_id=credentials["accessKeyId"],
            aws_secret_access_key=credentials["secretAccessKey"],
            aws_session_token=credentials["sessionToken"],
        )
        got_region = region_is_available(session=session, id=id)
        if bool(got_region):  # response received
            if type(got_region) == int:  # there are vpcs in the region
                if not "vpc_present" in assets:
                    assets["vpc_present"] = {}
                if not id in assets["vpc_present"]:
                    assets["vpc_present"][id] = {}
                assets["vpc_present"][id][region] = True
            return session
        logging.debug(f"[ ] {id}:{region} failed to establish session")
    except:
        msg = f"Role Credentials not returned for {id}:{region}"
        logging.error(msg)
        assert False, msg


def enum_org(session, sso_account_ids) -> dict:
    active_accounts = {}
    if not session:
        return active_accounts
    org = session.client("organizations")
    page_iterator = org.get_paginator("list_accounts").paginate()
    # Enumerate all Org accounts
    org_accts = [acct for page in page_iterator for acct in page["Accounts"]]
    logging.info("--- Connecting to Org ---")
    for acct in org_accts:
        if acct["Status"] == "SUSPENDED":
            if acct["Id"] in sso_account_ids:
                logging.info(f"{acct['Id']}\t{acct['Name']}\t*** SSO REMOVE ***")
                continue
        else:
            active_accounts[acct["Id"]] = acct["Name"]
            if not acct["Id"] in sso_account_ids:
                logging.info(f"{acct['Id']}\t{acct['Name']}\t*** SSO ONBOARD ***")
                continue
    else:
        logging.info("---- No issues found ----")
    return active_accounts


def config_with_futures():
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(config_results, k) for k in config_q}
        for fut in concurrent.futures.as_completed(futures):
            if bool(fut.result()):
                logging.debug(f"The outcome is {fut.result()}")


def assets_with_futures(regions):
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {
            executor.submit(do_job, id, region["RegionName"]): id
            for id in sorted(sso_account_ids, reverse=REVERSE)
            for region in regions
        }
        start_time = time.time()
        for fut in concurrent.futures.as_completed(futures):
            account = futures[fut]
            try:
                if bool(fut.result()):
                    logging.debug(f"The outcome is {fut.result()}")
            except Exception as exc:
                logging.warning("%r generated an exception: %s" % (account, exc))
            logging.debug(f"Inventory completed in {time.time() - start_time:.2f} s")


def get_config_inventory():
    for f in sorted(glob.glob("data/config_*.json")) + sorted(glob.glob("data/FINDINGS_*.json")):
        os.remove(f)
    config_with_futures()


def save_assets(assets):
    if not os.path.exists("./data"):
        os.makedirs("./data")
    for f in sorted(glob.glob("data/assets_*.json")):
        os.remove(f)
    with open("data/assets_org.json", "w") as fout:
        fout.write(json.dumps(org_accounts, indent=0))
    for k in assets:
        fn = f"data/assets_{k}.json"
        if bool(assets[k]):
            with open(fn, "w") as fout:
                text = ",\n".join(['"' + s + '": ' + json.dumps(assets[k][s], default=str) for s in sorted(assets[k])])
                fout.write("{\n" + text + "\n}")
        else:
            os.remove(fn) if os.path.exists(fn) else None
    if bool(assets.get("contact")):
        contactlist = []
        for a, v in assets["contact"].items():
            contactlist.append(
                "{},{},{},{}".format(a.split(":")[4], v.get("PhoneNumber"), v.get("emailaddress"), v.get("FullName"))
            )
        # Add missing account records from old file
        if os.path.exists("./data/accounts.csv"):
            with open("./data/accounts.csv", "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if f"::account::{row['Account']}:contact" in assets["contact"]:
                        continue
                    contactlist.append("{},{},{},{}".format(row["Account"], row["Phone"], row["Email"], row["Name"]))

        if bool(contactlist):
            with open(f"data/accounts.csv", "w") as fout:
                fout.write(f"Account,Phone,Email,Name\n")
                fout.write("\n".join(contactlist))

    if bool(stats):
        with open(f"data/stats.csv", "w") as fout:
            fout.write(f"Account,Region,Service,Call,Type,Items,Time\n")
            fout.write("\n".join(stats))


def pg(svc: str, key: str, call: str, op=dict(), **kw) -> list:
    start, r, id, session = time.time(), [], kw["id"], kw["session"]
    callid = f"::{svc}:{kw.get('region_name')}:{id}:{call}"
    if key in vpc_resource:  # VPC-reliant resources won't be found in regions without VPCs
        if not bool(assets.get("vpc_present", {}).get(id, {}).get(kw.get("region_name"))):
            logging.debug(f"{callid} skipped due to no VPC")
            return r
    if not COMPREHENSIVE and id in config.get("config", []):  # Config data exists for given account
        if key in config:  # Config records resources of this type
            if kw["region_name"] in config["config"][id]:  # Config data exists for given region in this account
                return r
        elif key.upper() in config:  # Config data for this resource type exists, but not quite usable
            if not kw["region_name"] in config[key.upper()].get(id, {}):
                # Config does not contain data for this resource in this region
                # Go through all config resource types and see if any data exists for this account/ region
                for k in config:
                    if kw["region_name"] in config[k].get(id, {}).keys():
                        # config data exists for other resource types in this account region, skipping
                        return r
        # WONTFIX: config data may be partial due to resource policies
    del kw["id"]
    del kw["session"]
    try:
        r = []
        kw["config"] = Config(connect_timeout=3, retries={"max_attempts": 2})
        for page in session.client(svc, **kw).get_paginator(call).paginate(**op):
            datakeys = list(filter(lambda o: not o in META, page))
            if not bool(datakeys):  # Check if list or keys?
                continue
            if not type(datakeys) in [list]:
                msg = f"{callid} results returned {type(datakeys)} type"
                logging.warning(msg)
                logging.warning(f"{datakeys}")
                assert False, msg
            for s in datakeys:
                if type(page[s]) in [list, dict]:
                    if bool(page[s]):
                        if len(datakeys) > 1 > bool(r) and not call in [
                            "get_account_authorization_details",
                            "list_streams",
                        ]:
                            msg = f"{callid} data set: {datakeys}"
                            logging.warning(msg)
                            assert False, msg
                        if svc == "cloudfront":
                            if page[s].get("Quantity", -1) == 0:
                                break
                            assert False, f"Positive Quantity: {callid}"  # Check data structure
                        if type(page[s]) == dict:
                            logging.warning(f"{callid} result is {type(page[s])}")
                        r.extend(page[s] if type(page[s]) == list else [{k: v} for k, v in page[s].items()])
                else:
                    logging.warning(f"{callid} result is {type(page[s])}")
    except OperationNotPageableError as e:
        r = []
        func = getattr(session.client(svc, **kw), call)
        try:
            f = func(**op)
            sus_keys = [k for k in f.keys() if not k in META]
            for page in f:
                if page in META:
                    continue
                if page in ["nextToken", "NextToken", "Marker"]:
                    logging.info(f"Paging operation suggested for {callid}\n{f}")
                    continue
                if page in ["NextMarker"]:
                    continue  # Handled below
                if f[page] is None or not bool(f[page]):
                    continue
                if len(sus_keys) > 4:
                    r.append({k: f[k] for k in sus_keys})
                    break
                elif type(f[page]) in (str, dict, bool):
                    r.append(f[page])
                else:
                    r.extend(f[page])
            token = "NextMarker"
            while token in f:
                op[token] = f[token]
                f = func(**op)
                for page in f:
                    if page in [token] + META:
                        continue
                    if type(f[page]) == str:
                        r.append(f[page])
                    else:
                        r.extend(f[page])

        except AttributeError as ex:
            logging.warning(f"{callid} 2nd attempt AttributeError: {ex}")
        except ClientError as ex:
            # print(f"{ex}") # [s3policy when there's no policy returned] AttributeError: 'ClientError' object has no attribute 'get'
            if (
                hasattr(ex, "response")
                or ex.get("Response", {}).get("Error", {}).get("Code") == "AccessDeniedException"  # type: ignore
            ):
                logging.debug(f"{callid} 2nd attempt Exception: {ex}")
                add_record("error", f"::error:{id}:{kw['region_name']}:{svc}:{call}", ex)
            else:
                logging.warning(f"{callid} 2nd attempt Exception: {ex}")
    except ConnectTimeoutError as e:  # FIXME: apply to non-paged calls too
        if call in [
            "list_identities",
            "list_projects",  # Codestar
            "describe_direct_connect_gateways",
            "describe_direct_connect_gateway_associations",
        ]:
            logging.debug(f"[-] {callid}: {e}")
        else:
            logging.warning(f"[-] {callid}: {e}")
    except AttributeError as e:
        logging.warning(f"{callid} AttributeError: {e}")
    except ClientError as e:
        if e.response["Error"]["Code"] in [
            "UnauthorizedOperation",
            "InvalidClientTokenId",
            "ClusterNotFoundException",
            "503",
        ]:
            logging.debug(f"{callid} ClientError: {e}")
            add_record("error", f"::error:{id}:{kw['region_name']}:{svc}:{call}", e)
        elif svc in [
            "athena",
            "emr",
            "emr-serverless",
            "glue",
            "identitystore",
            "lakeformation",
            "organizations",
            "quicksight",
            "secretsmanager",
            "ssm",
            "sso-admin",
        ] and e.response["Error"]["Code"] in [
            "AccessDeniedException",
            "InvalidRequestException",
            "MetadataException",
            "ResourceNotFoundException",
        ]:
            logging.debug(f"{callid} ClientError: {e}")
            add_record("error", f"::error:{id}:{kw['region_name']}:{svc}:{call}", e)
        else:
            logging.warning(f"{callid} ClientError: {e}")
    except Exception as e:
        if str(e).startswith("Could not connect to the endpoint URL:"):
            logging.debug(f"{callid} Exception: {e}")  # Quicksight
        else:
            logging.warning(f"{callid} Exception: {e}")
    except:
        logging.warning(f"{callid} Unknown Exception")

    if bool(r) and not assets.get(key):
        assets[key] = {}
    stats.append(",".join([id, kw["region_name"], svc, call, "API", str(len(r)), f"{time.time() - start:.2f}"]))
    if time.time() - start > 4:
        logging.debug(f"[{len(r) if bool(r) else ' '}] {id} {kw['region_name']}\t{key}\t{time.time() - start:.2f}")
    return r


def add_record(category, arn, o):
    if not category in assets:
        assets[category] = {}
    assets[category][arn] = o


REVERSE = False
THREADS = 10
DEBUG = os.environ.get("debug", "").lower() == "true"
COMPREHENSIVE = False  # Inventory assets even if config data exists
META = [
    "AdditionalRoutesAvailable",
    "HasMoreDeliveryStreams",
    "HasMoreStreams",
    "IsTruncated",
    "Marker",
    "MaxItems",
    "MaxResults",
    "NextMarker",
    "nextToken",
    "NextToken",
    "Owner",  # list_buckets
    "RequestId",  # quicksight
    "ResponseMetadata",
    "ServerId",
    "ServiceNames",  # vpces
    "Status",  # quicksight
    "Truncated",
]  # Why so inconsistent, AMZ?

start_url = os.environ.get("start_url")
if not start_url:
    print("StartUrl is not set. Run:")
    print("  export start_url=https://<app>.awsapps.com/start && python3 extract.py")
    exit(0)

main_region = os.environ.get("main_region", "us-east-1")
role_name_pattern = "Full|^Audit"
lambda_skip = [
    "aws-controltower-NotificationForwarder",
    "lambda_asg_instance_refresh",
]
sns_skip = [
    "aws-controltower-SecurityNotifications",
    "aws-controltower-AllConfigNotifications",
    "aws-controltower-AggregateSecurityNotifications",
]
lambda_filter = "|".join(lambda_skip)
logging.basicConfig(
    format="%(asctime)s %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
    handlers=[logging.FileHandler(os.path.splitext(__file__)[0] + ".log", mode="w"), logging.StreamHandler()],
)
warnings.filterwarnings("ignore", category=FutureWarning, module="botocore.client")
started = time.time()
assets, config, stats, alerttypes = {}, {}, [], []
session = Session()
access_token = get_oidc_token(start_url, session)
sso = session.client("sso")
page_iterator = sso.get_paginator("list_accounts").paginate(accessToken=access_token)
sso_accounts = [acct for page in page_iterator for acct in page["accountList"]]
if not len(sso_accounts):
    logging.warning("No SSO accounts found")
sso_account_ids = sorted([sso_account["accountId"] for sso_account in sso_accounts])

# Connecting to a specific account to enumerate Org
sec_account_id = os.environ.get("sec_account_id", sso_account_ids[-1])
# WONTDO: iterate through org to find Security account
sec_account_session = account_session(sso, access_token, sec_account_id, main_region)
org_accounts = enum_org(sec_account_session, sso_account_ids)
if os.environ.get("id") and os.environ["id"] in sso_account_ids:
    sso_account_ids = [k for k in sso_account_ids if k == os.environ.get("id")]
if sec_account_session:
    regions = sorted(sec_account_session.client("ec2").describe_regions()["Regions"], key=lambda k: k["RegionName"])
    # + sec_account_session.client("ec2").describe_regions(RegionNames=["ap-east-1"])["Regions"]
else:
    regions = []
vpc_resource = {  # Skips inventory if no VPCs in region
    "ami",  # ?
    "autoscaling",
    "codebuild",
    "ds",
    "ebs",  # ?
    "ebssnapshot",  # ?
    "ec2",
    "eks",
    "elb",
    "elbv2",
    "eni",
    "flowlog",
    "fsx",
    "fsxvm",
    "igw",
    "listeners",  # elbv2
    "mounttargets",  # for efs
    "nacl",
    "natgw",
    "rds",
    "rdssnapshot",
    "route53resolver",
    "routetable",  # tgwroutetable
    "s3ap",
    "sg",
    "ssmec2",
    "subnet",
    "targetgroup",  # elbv2
    "targethealth",  # elbv2
    "tgwattachment",
    "vpce",
    "vpces",
    "vpcx",
    # "sagemaker", # some
}
config_q = {
    # When KEY is capitalized, then config data will not be used (due to missing vital attributes)
    # But the existence of config data will tell API inventory to query for resources in a given region
    # When key is not capitalized, then API inventory will not be performed in a given region if it reported some config
    # AND if resources of this type are present in config data. This may not work well in cases where config data is partial due to resource policies
    "PUBLICIP": "SELECT configuration.association.publicIp, accountId, * WHERE resourceType = 'AWS::EC2::NetworkInterface' AND configuration.association.publicIp = '0.0.0.0/0' AND configuration.description NOT LIKE 'Interface for NAT Gateway %'",  # Ad-hoc report
    "RESOURCES": "SELECT resourceType GROUP BY resourceType",  # Ad-hoc report
    "1ELBV2LISTENER": "SELECT * WHERE ResourceType='AWS::ElasticLoadBalancingV2::Listener'",
    # "1efsap": "SELECT * WHERE ResourceType='AWS::EFS::AccessPoint'",
    # "1nmtgwreg": "SELECT * WHERE ResourceType='AWS::NetworkManager::TransitGatewayRegistration'",  # Useless
    # "0emrsc": "SELECT * WHERE ResourceType='AWS::EMR::SecurityConfiguration'",
    "0appconfig": "SELECT * WHERE ResourceType='AWS::AppConfig::Application'",
    "0pl": "SELECT * WHERE ResourceType='AWS::EC2::PrefixList'",
    "ses": "SELECT * WHERE ResourceType LIKE 'AWS::SES::%'",
    "0kinesis": "SELECT * WHERE ResourceType='AWS::KinesisAnalyticsV2::Application'",
    "0transfer": "SELECT * WHERE ResourceType='AWS::Transfer::Workflow'",
    "ACCESSANALYZER": "SELECT * WHERE ResourceType='AWS::AccessAnalyzer::Analyzer'",
    "0CFN": "SELECT * WHERE ResourceType='AWS::CloudFormation::Stack'",
    "role": "SELECT * WHERE ResourceType='AWS::IAM::Role' AND configuration.path NOT LIKE '/aws-reserved/%' AND configuration.path NOT LIKE '/aws-service-role/%'",
    "VPCES": "SELECT * WHERE ResourceType='AWS::EC2::VPCEndpointService'",  # + vpcespermissions, VpcEndpointPolicySupported - baseEndpointDnsNames, networkLoadBalancerArns
    "apigateway": "SELECT * WHERE ResourceType LIKE 'AWS::ApiGateway%'",
    "athena": "SELECT * WHERE ResourceType='AWS::Athena::DataCatalog'",
    "autoscaling": "SELECT * WHERE ResourceType='AWS::AutoScaling::AutoScalingGroup'",
    "backup": "SELECT * WHERE ResourceType IN ('AWS::Backup::BackupVault', 'AWS::Backup::BackupPlan')",
    "batch": "SELECT * WHERE ResourceType IN ('AWS::Batch::JobQueue', 'AWS::Batch::ComputeEnvironment')",
    "certificate": "SELECT * WHERE ResourceType='AWS::ACM::Certificate'",  # + SubjectAlternativeNameSummaries - certificateAuthorityArn
    "cloudfront": "SELECT * WHERE ResourceType='AWS::CloudFront::Distribution'",
    "codeartifact": "SELECT * WHERE ResourceType='AWS::CodeArtifact::Repository'",
    "codebuild": "SELECT * WHERE ResourceType='AWS::CodeBuild::Project'",
    "codedeploy": "SELECT * WHERE ResourceType='AWS::CodeDeploy::DeploymentConfig' and not resourceName like 'CodeDeployDefault.%'",
    "codepipeline": "SELECT * WHERE ResourceType='AWS::CodePipeline::Pipeline'",
    "config": "SELECT * WHERE ResourceType='AWS::Config::ConfigurationRecorder'",
    "customergateway": "SELECT * WHERE ResourceType='AWS::EC2::CustomerGateway'",
    "datasync": "SELECT * WHERE ResourceType LIKE 'AWS::DataSync::%'",
    "dynamodb": "SELECT * WHERE ResourceType='AWS::DynamoDB::Table'",
    "ebs": "SELECT * WHERE ResourceType='AWS::EC2::Volume'",
    "ec2": "SELECT * WHERE ResourceType='AWS::EC2::Instance'",
    "ecr": "SELECT * WHERE ResourceType='AWS::ECR::Repository'",
    "ECS": "SELECT * WHERE ResourceType LIKE 'AWS::ECS::%'",
    "EFS": "SELECT * WHERE ResourceType='AWS::EFS::FileSystem'",
    "EKS": "SELECT * WHERE ResourceType LIKE 'AWS::EKS::%'",
    "elasticbeanstalk": "SELECT * WHERE ResourceType='AWS::ElasticBeanstalk::Application'",
    "elb": "SELECT * WHERE ResourceType='AWS::ElasticLoadBalancing::LoadBalancer'",
    "ELBV2": "SELECT * WHERE ResourceType='AWS::ElasticLoadBalancingV2::LoadBalancer'",  # - targetgroups, listeners, IPs
    "eni": "SELECT * WHERE ResourceType='AWS::EC2::NetworkInterface' AND configuration.status='in-use'",
    "event": "SELECT * WHERE ResourceType='AWS::Events::Rule' AND NOT (configuration.Name IN ('aws-controltower-ConfigComplianceChangeEventRule') OR configuration.Name LIKE 'DO-NOT-DELETE-AmazonInspector%' OR configuration.Description LIKE 'Rule for SSM OpsCenter%' OR configuration.Description LIKE 'Refresh schedule for %')",  # FIXME: use it!
    "flowlog": "SELECT * WHERE ResourceType='AWS::EC2::FlowLog'",
    "gax": "SELECT * WHERE ResourceType LIKE 'AWS::GlobalAccelerator::%'",
    "glue": "SELECT * WHERE ResourceType IN ('AWS::Glue::Job', 'AWS::Glue::Classifier')",
    "igw": "SELECT * WHERE ResourceType='AWS::EC2::InternetGateway'",
    "kafka": "SELECT * WHERE ResourceType='AWS::MSK::Cluster'",
    "kms": "SELECT * WHERE ResourceType='AWS::KMS::Key' AND configuration.keyManager = 'CUSTOMER'",
    "lambda": "SELECT * WHERE ResourceType='AWS::Lambda::Function' AND resourceName NOT IN ('{}')".format(
        "','".join(lambda_skip)
    ),
    "mq": "SELECT * WHERE ResourceType='AWS::AmazonMQ::Broker'",
    "nacl": "SELECT * WHERE ResourceType='AWS::EC2::NetworkAcl'",
    "natgw": "SELECT * WHERE ResourceType='AWS::EC2::NatGateway'",
    "networkfirewall": "SELECT * WHERE ResourceType IN ('AWS::NetworkFirewall::Firewall', 'AWS::NetworkFirewall::FirewallPolicy')",
    "opensearch": "SELECT * WHERE ResourceType='AWS::OpenSearch::Domain'",
    "rds": "SELECT * WHERE ResourceType='AWS::RDS::DBInstance'",
    "rdssg": "SELECT * WHERE ResourceType='AWS::RDS::DBSecurityGroup'",  # useless
    "rdssnapshot": "SELECT * WHERE ResourceType='AWS::RDS::DBSnapshot'",
    "redshift": "SELECT * WHERE ResourceType='AWS::Redshift::Cluster'",
    "route53": "SELECT * WHERE ResourceType='AWS::Route53::HostedZone'",
    "ROUTE53RESOLVER": "SELECT * WHERE ResourceType='AWS::Route53Resolver::ResolverRule' and resourceId != 'rslvr-autodefined-rr-internet-resolver'",
    "routetable": "SELECT * WHERE ResourceType='AWS::EC2::RouteTable'",
    "S3": "SELECT * WHERE ResourceType='AWS::S3::Bucket'",
    "s3blockpublic": "SELECT * WHERE ResourceType='AWS::S3::AccountPublicAccessBlock'",  # FIXME: use
    "sagemaker": "SELECT * WHERE ResourceType LIKE 'AWS::SageMaker::%'",
    "SECRETSMANAGER": "SELECT * WHERE ResourceType='AWS::SecretsManager::Secret'",  # FIXME: does not have policies
    "SERVICEDISCOVERY": "SELECT * WHERE ResourceType LIKE 'AWS::ServiceDiscovery::%'",  # TODO
    "sg": "SELECT * WHERE ResourceType='AWS::EC2::SecurityGroup'",
    "sns": "SELECT * WHERE ResourceType='AWS::SNS::Topic' AND resourceName NOT IN ('{}')".format("','".join(sns_skip)),
    "SQS": "SELECT * WHERE ResourceType='AWS::SQS::Queue'",
    "ssmec2": "SELECT * WHERE ResourceType='AWS::SSM::ManagedInstanceInventory'",
    "subnet": "SELECT * WHERE ResourceType='AWS::EC2::Subnet'",
    "TGW": "SELECT * WHERE ResourceType='AWS::EC2::TransitGateway'",
    "TGWATTACHMENT": "SELECT * WHERE ResourceType='AWS::EC2::TransitGatewayAttachment'",
    "TGWROUTETABLE": "SELECT * WHERE ResourceType='AWS::EC2::TransitGatewayRouteTable'",
    "user": "SELECT * WHERE ResourceType='AWS::IAM::User'",
    "vpc": "SELECT * WHERE ResourceType='AWS::EC2::VPC'",
    "vpce": "SELECT * WHERE ResourceType='AWS::EC2::VPCEndpoint'",
    "vpcx": "SELECT * WHERE ResourceType='AWS::EC2::VPCPeeringConnection'",
    "vpnconnection": "SELECT * WHERE ResourceType='AWS::EC2::VPNConnection'",
    "vpngateway": "SELECT * WHERE ResourceType='AWS::EC2::VPNGateway'",
    "WAFV2WEBACL": "SELECT * WHERE ResourceType IN ('AWS::WAFv2::WebACL', 'AWS::WAF::WebACL', 'AWS::WAFRegional::WebACL')",  # config does not return: relationships/"Is Associated With"
    "workspaces": "SELECT * WHERE ResourceType='AWS::WorkSpaces::Workspace'",
}

get_config_inventory()
logging.warning(f"Config done: {time.time() - started:.2f}\n")
assets_with_futures(regions=regions)
save_assets(assets)
transform.regenerate_data()
logging.warning(f"Completed: {time.time() - started:.2f} s\n")
exit(0)
