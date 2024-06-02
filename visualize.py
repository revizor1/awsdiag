# TODO: css: click on edge => zoom to object connections
# TODO: FINDINGS:
# * External Access Network (Ingress/ Egress)
# WONTDO: Account OU
# WONTDO: Crash stack log
# WONTDO: transfer > Role | User
# WONTDO: kafka serverless resides in subnets
# Post-processing: https://stackoverflow.com/questions/10841135/newline-in-node-label-in-dot-graphviz-language
# https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-intro.html#block-public-access-to-amis

import datetime
import glob
import ipaddress
import json
import logging
import os
import re
import shutil
from pathlib import Path
import subprocess
import time
from urllib.parse import unquote
from urllib.request import urlretrieve

from diagrams import Cluster, Diagram, Edge, Node
from diagrams.aws.analytics import EMR, Athena, Glue, LakeFormation, ManagedStreamingForKafka
from diagrams.aws.compute import EC2, ECR, ECS, EC2Ami, EKS, ElasticBeanstalk, Lambda
from diagrams.aws.database import DDB, RDS, Elasticache, DatabaseMigrationServiceDatabaseMigrationWorkflow
from diagrams.aws.devtools import Codebuild, Codecommit, Codedeploy, Codepipeline, Codestar
from diagrams.aws.engagement import SES
from diagrams.aws.general import GenericFirewall, InternetAlt1, Marketplace, User, Users
from diagrams.aws.integration import SNS, SQS
from diagrams.aws.management import Organizations, OrganizationsAccount
from diagrams.aws.migration import TransferForSftp
from diagrams.aws.ml import Sagemaker, AugmentedAi
from diagrams.aws.mobile import APIGateway
from diagrams.aws.network import (
    ALB,
    APIGatewayEndpoint,
    CLB,
    NLB,
    DirectConnect,
    Endpoint,
    GAX,
    InternetGateway,
    NATGateway,
    Privatelink,
    Route53,
    Route53HostedZone,
    TransitGateway,
    VPCElasticNetworkAdapter,
    VPCElasticNetworkInterface,
    VPCPeering,
)
from diagrams.aws.security import Artifact, DS, IAM, RAM, Cognito, IAMRole, SecretsManager, SingleSignOn, KMS
from diagrams.aws.storage import (
    Backup,
    EBS,
    EFS,
    ElasticBlockStoreEBSSnapshot,
    Fsx,
    S3,
    SimpleStorageServiceS3Bucket,
    SimpleStorageServiceS3BucketWithObjects,
)
from diagrams.azure.integration import SoftwareAsAService
from diagrams.generic.place import Datacenter
from diagrams.generic.network import Firewall
from diagrams.generic.os import IOS, LinuxGeneral, Windows
from diagrams.oci.network import SecurityLists, SecurityListsWhite
from diagrams.oci.monitoring import EmailWhite, Email
from diagrams.onprem.client import Client
from diagrams.onprem.network import Internet
from policyuniverse.arn import ARN
from policyuniverse.policy import Policy
from PyPDF2 import PdfFileMerger

DEBUG = os.environ.get("debug", "").lower() == "true"
# Better chances of displaying
FORCE = 0
COLUMN_MAX = 20
SKIP_DNS = True
KNOWN_IDS = []  # Ignore role trust referencing these accounts
if os.path.exists("./ids.txt"):
    with open("./ids.txt", "r") as f:
        KNOWN_IDS = f.read().split("\n")

output = "pdf"
icon = {
    "amazon-elb": "https://www.shareicon.net/download/2015/08/28/92268_copy_512x512.png",
    "aws_codestar_connections_managed": "aws_codestar_connections_managed",
    "efs": "https://www.shareicon.net/download/2017/03/07/880851_media_512x512.png",
    "global_accelerator_managed": "https://www.shareicon.net/download/2016/07/24/801021_internet_512x512.png",
    "lambda": "https://www.shareicon.net/data/128x128/2015/03/23/11863_key_48x48.png",
    "nacl": "https://cloudiofy.com/wp-content/uploads/2022/07/network-acl.png",
    "nat_gateway": "https://www.shareicon.net/download/2015/08/28/92242_network_512x512.png",
    "network_load_balancer": "https://www.shareicon.net/download/2015/08/28/92244_copy_512x512.png",
    "root": "https://image.pngaaa.com/894/5565894-middle.png",
    "router": "https://www.shareicon.net/download/2015/08/28/92249_copy_512x512.png",
    "transit_gateway": "https://www.shareicon.net/download/2015/09/23/106054_switch_512x512.png",
}
color = {
    "broken": "#ffffff",  # "white",
    "directconnect": "#006400",  # "darkgreen",
    "ds": "#0000ff",  # "blue",
    "dns": "#c0c0c0",  # "gray"
    "ebs": "#c0c0c0",  # "gray"
    "ec2": "#c0c0c0",  # "gray"
    "efs": "#00ff00",  # "green",
    "eks": "#c0c0c0",  # "gray"
    "elasticache": "#c0c0c0",  # "gray"
    "elbv2": "#c0c0c0",  # "gray"
    "emr": "#0000ff80",  # "blue",
    "eni": "#1A5276a0",  # used in routing
    "external": "#0000ff80",  # "blue",
    "fsx": "#00ff00",  # "green",
    "gax": "#0000ff",  # "blue",
    "igw": "#C0392Ba0",
    "internal": "#808080",  # "webgray",
    "internet": "#ff000080",  # "red",
    "lambda": "#d3d3d3",  # "lightgray",
    "local": "#d3d3d3",  # "lightgray",
    "nic": "#808080",  # "webgray",
    "public": "#F39C12a0",
    "rds": "#556b2f",  # "purple",
    "role": "#c0c0c0",  # "gray"
    "route53resolver": "#006400",  # "darkgreen",
    "routetable": "#eeee00",  # "yellow",
    "sagemaker": "#8b0000",  # "darkred",
    "service": "#808080",  # "webgray",
    "stale": "#d2b48c",  # "tan",
    "tgw": "#1A5276a0",
    "unknown": "#0000ff80",  # "blue",
    "user": "#c0c0c0",  # "gray"
    "vpce": "#0E6655a0",
    "vpces": "#008080",  # "teal",
    "vpcx": "#00008b",  # "darkblue",
    "waf": "#32cd32",  # "limegreen",
}
service_types = {
    "ami": EC2Ami,
    "apigateway": APIGateway,
    "athena": Athena,
    "backup": Backup,
    "bedrock": AugmentedAi,  # wrong service
    "codeartifact": Artifact,  # wrong service
    "codebuild": Codebuild,
    "codecommit": Codecommit,
    "codestar": Codestar,
    "codedeploy": Codedeploy,
    "codepipeline": Codepipeline,
    "cognito": Cognito,
    "ds": DS,
    "dxgw": DirectConnect,
    "dynamodb": DDB,
    "ecr": ECR,
    "ebs": EBS,
    "ebssnapshot": ElasticBlockStoreEBSSnapshot,
    "ecs": ECS,
    "efs": EFS,
    "eks": EKS,
    "elasticache": Elasticache,
    "elasticbeanstalk": ElasticBeanstalk,
    "emr": EMR,
    "fsx": Fsx,
    "gax": GAX,
    "glue": Glue,
    "igw": InternetGateway,
    "instanceprofile": IAM,
    "kafka": ManagedStreamingForKafka,
    "kms": KMS,
    "lakeformation": LakeFormation,
    "lambda": Lambda,
    "natgw": NATGateway,
    "networkfirewall": Firewall,
    "organizations": Organizations,
    "rds": RDS,
    "rdssnapshot": DatabaseMigrationServiceDatabaseMigrationWorkflow,
    "role": IAMRole,
    "route53": Route53HostedZone,
    "route53resolver": Route53,
    "s3": S3,
    "s3ap": SimpleStorageServiceS3Bucket,
    "s3bucket": SimpleStorageServiceS3BucketWithObjects,
    "sagemaker": Sagemaker,
    "secretsmanager": SecretsManager,
    "ses": SES,
    "sns": SNS,
    "sqs": SQS,
    "sso": SingleSignOn,
    "tgw": TransitGateway,
    "transfer": TransferForSftp,
    "elb:application": ALB,
    "elb:classic": CLB,
    "elb:gateway": GenericFirewall,
    "elb:network": NLB,
    "nic:amazon-elb": Node,
    "nic:aws_codestar_connections_managed": Codestar,
    "nic:efs": Node,
    "nic:gateway_load_balancer_endpoint": SecurityListsWhite,
    "nic:gateway_load_balancer": SecurityLists,
    "nic:global_accelerator_managed": Node,
    "nic:interface": VPCElasticNetworkInterface,
    "nic:lambda": Node,
    "nic:load_balancer": Node,  # = amazon-elb
    "nic:nat_gateway": Node,
    "nic:network_load_balancer": Node,  # = amazon-elb
    "nic:transit_gateway": Node,
    "nic:vpc_endpoint": VPCElasticNetworkAdapter,
    # api_gateway_managed | branch | efa | iot_rules_managed | quicksight | trunk
}
account_services = ["ds", "gax", "organizations", "sso"]  # These services auto-connect to their parent enis
eni_services = [
    "ds",
    "ebs",
    "efs",
    "elasticache",
    "emr",
    "fsx",
    "gax",
    "rds",
    "route53resolver",
    "sagemaker",
]  # Services auto-connecting to their parent ENIs
regional_services = [  # Those show in regional services clusters (set definition filter for types)
    "ami",
    "apigateway",
    "athena",
    "backup",
    "codeartifact",
    "codebuild",
    "codecommit",
    "codestar",
    "codepipeline",
    "cognito",
    "dynamodb",
    "ebs",
    "ebssnapshot",
    "ecr",
    "ecs",
    "eks",
    "elasticbeanstalk",
    "emr",
    "glue",
    "kafka",
    "kms",
    "lakeformation",
    "lambda",
    "networkfirewall",
    "rdssnapshot",
    "route53",
    "s3",
    "secretsmanager",
    "ses",
    "sns",
    "sqs",
    "transfer",
    "efs",
    "elasticache",
    "sagemaker",
    "route53resolver",
]
vpc_services = ["fsx", "rds", "s3ap"]
types = {  # Dictionary of regex to help identify resource types
    "account": r".*:.*:account::[0-9]{12}::|^[0-9]{12}$",
    "ami": r".*:.*:ami:.+:[0-9]{12}:ami-.+",
    "apigateway": r".*:.*:apigateway:.+:[0-9]{12}:.+|.*:.*:apigatewayv2:.+:[0-9]{12}:.+",
    "athena": r".*:.*:athena:.+:[0-9]{12}:.+",
    "autoscaling": r"arn:aws:autoscaling:.+:[0-9]{12}:autoscalinggroup:.+",
    "backup": r"arn:aws:backup:.+:[0-9]{12}:backup-.+:.+",
    "codeartifact": r"arn:aws:codeartifact:.+:[0-9]{12}:.+",
    "codebuild": r".*:.*:codebuild:.+:[0-9]{12}:.+",
    "codecommit": r".*:.*:codecommit:.+:[0-9]{12}:.+",
    "codedeploy": r".*:.*:codedeploy:.+:[0-9]{12}:.+",
    "codepipeline": r".*:.*:codepipeline:.+:[0-9]{12}:.+",
    "codestar": r".*:.*:codestar:.+:[0-9]{12}:.+",
    "cognito": r".*:.*:cognito:.+:[0-9]{12}:.+",
    "dxgw": r".*:.*:dxgw:.+:[0-9]{12}:.+",
    "ds": r".*:.*:ds:.+:[0-9]{12}:.+",
    "dxcon": r".*:.*:directconnect:.+:[0-9]{12}:dxcon-.+",
    "dynamodb": r"arn:aws:dynamodb:.+:[0-9]{12}:table/.+",
    "ebs": r"arn:aws:ec2:.+:[0-9]{12}:volume/vol-.+",
    "ebssnapshot": r"arn:aws:ec2:.+:[0-9]{12}:snapshot/snap-.+|arn:aws:ec2:.+::snapshot/snap-.+",  # Real arn missing Account ID
    "ec2": r"arn:aws:ec2:.+:[0-9]{12}:instance/i-.+|^i-[a-f0-9]{8}(?:[a-f0-9]{9})?$",
    "ecr": r"arn:aws:ecr:.+:[0-9]{12}:repository/.+",
    "ecs": r"arn:aws:ecs:.+:[0-9]{12}:cluster/.+",
    "efs": r"arn:aws:elasticfilesystem:.+:[0-9]{12}:file-system/fs-.+",
    "efsaccesspoint": r"arn:aws:elasticfilesystem:.+:[0-9]{12}:access-point/fsap-.+",
    "eks": r"arn:aws:eks:.+:[0-9]{12}:cluster/.+",
    "elasticbeanstalk": r".*:.*:elasticbeanstalk:.+:[0-9]{12}:application/.+",
    "elasticache": r"arn:aws:elasticache:.+:[0-9]{12}:cluster:.+",
    "elb": r"arn:aws:elasticloadbalancing:.+:[0-9]{12}:loadbalancer/[0-9a-f]+$",
    "elbv2": r"arn:aws:elasticloadbalancing:.+:[0-9]{12}:loadbalancer/app/.+|arn:aws:elasticloadbalancing:.+:[0-9]{12}:loadbalancer/net/.+|arn:aws:elasticloadbalancing:.+:[0-9]{12}:loadbalancer/gwy/.+",
    "emr": r"arn:aws:elasticmapreduce:.+:[0-9]{12}:cluster/j-.+",
    "eni": r".*:.*:e..:.+:[0-9]{12}:network.interface/eni.+",
    "fsx": r"arn:aws:fsx:.+:[0-9]{12}:.+",
    "gax": r".*:.*:globalaccelerator::[0-9]{12}:accelerator/.+",
    "glue": r".*:.*:glue:.+:[0-9]{12}:.+",
    "igw": r"arn:aws:ec2:.+:[0-9]{12}:internet-gateway/igw-.+",
    "instanceprofile": r"arn:aws:iam::[0-9]{12}:instance-profile/.+",
    "ip": r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$",
    "kafka": r"arn:aws:kafka:.+:[0-9]{12}:cluster/.+",
    "kms": r"arn:aws:kms:.+:[0-9]{12}:key/.+",
    "lakeformation": r"arn:aws:lakeformation:.+:[0-9]{12}:.+",
    "lambda": r"arn:aws:lambda:.+:[0-9]{12}:function:.+",
    "nacl": r"arn:aws:ec2:.+:[0-9]{12}:nacl/acl-.+",
    "natgw": r"arn:aws:ec2:.+:[0-9]{12}:natgateway/nat-.+",
    "networkfirewall": r"arn:aws:network-firewall:.+:[0-9]{12}:firewall-policy/.+",
    "organizations": r"arn:aws:organizations:.+:[0-9]{12}:account/o-.+",
    "ram": r".*:.*:ram:.+:[0-9]{12}:resource-share/.*",
    "ramresourceingress": r".*:.*:ram:.+:[0-9]{12}:from/.*",
    "rds": r"arn:aws:rds:.+:[0-9]{12}:db:.+",
    "rdssnapshot": r"arn:aws:rds:.+:[0-9]{12}:snapshot:.+",
    "region": r".*:.*:region:.+:[0-9]{12}:.*",
    "role": r"arn:aws:iam:.*:[0-9]{12}:role/.+",
    "route53": r".*:.*:route53:.+:[0-9]{12}:/*hostedzone/.*",
    "route53resolver": r".*:.*:route53resolver:.+:[0-9]{12}:resolver-endpoint/.*",
    "route53resolverlog": r".*:.*:route53resolver:.+:[0-9]{12}:resolver-query-log-config/.*",
    "routetable": r"arn:aws:ec2:.+:[0-9]{12}:route-table/rtb-.*",
    "routetableassociationid": r"rtbassoc-.*",
    "s3ap": r"arn:aws:s3:.+:[0-9]{12}:accesspoint/.+",  # Has to be before S3
    "s3": r"arn:aws:s3:.+:[0-9]{12}:.+|^arn:aws:s3:::.+",
    "sagemaker": r"arn:aws:sagemaker:.+:[0-9]{12}:.+/.+",
    "secretsmanager": r"arn:aws:secretsmanager:.+:[0-9]{12}:secret:.+",
    "ses": r".*:.*:ses:.+:[0-9]{12}:.+",
    "sns": r"arn:aws:sns:.+:[0-9]{12}:.+",
    "sqs": r"arn:aws:sqs:.+:[0-9]{12}:.+",
    "ssm": r"arn:aws:ssm:.*:[0-9]{12}:.+",
    "sso": r".*:.*:sso.*:.+:[0-9]{12}:d-.+",
    "stsrole": r"arn:aws:sts:.*:[0-9]{12}:assumed-role/.+",  # There's more to that
    "subnet": r".*:.*:.+:.+:[0-9]{12}:subnet/.+|^subnet-[a-f0-9]{8}(?:[a-f0-9]{9})?$",
    "targetgroup": r"arn:aws:elasticloadbalancing:.+:[0-9]{12}:targetgroup/.+",
    "transfer": r"arn:aws:transfer:.+:[0-9]{12}:server/s-.+",
    "tgw": r"arn:aws:ec2:.+:[0-9]{12}:transit-gateway/tgw-.+",
    "tgwattachment": r".*:.*:ec2:.+:[0-9]{12}:transit-gateway-attachment/tgw-attach-.+",
    "unknown": f"\*",  #  some wide open access
    "user": r"arn:aws:iam:.*:[0-9]{12}:user\/.+|arn:aws:iam:.*:[0-9]{12}:root",
    "vpc": r"arn:aws:ec2:.+:[0-9]{12}:vpc/.+",
    "vpce": r".*:.*:ec2:.+:[0-9]{12}:vpc-endpoint/vpce-.+",
    "vpces": r"arn:aws:ec2:.+:[0-9]{12}:vpc-endpoint-service/vpce-svc-.+",
    "vpcx": r".*:.*:ec2:.+:[0-9]{12}:vpc-peering-connection/pcx-.+",
    "dnsname": r"^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$",  # Catches more than needed
}
g_attr = {  # Attrs of the main diagram
    "TBbalance": "max",
    "compound": "true",
    "concentrate": "true",
    # "outputorder": "edgesfirst",
    # "splines": "ortho", "curved", "line", "spline"
    "splines": "ortho",
    "layout": "fdp",
    # "layout": "neato",
    # "graph": "strict",
    "fontsize": "40",
    "rankdir": "TB",
    "labelloc": "t",
    "newrank": "true",
    "tooltip": " ",
}
arn_pattern_account = r"[0-9]{12}"
shared_subnet_label = "Shared Subnet"
shared_vpc_label = "Shared VPC"
VPCE_TO_SERVICE = {
    "autoscaling": "",  # "autoscaling",
    "bedrock": "bedrock",
    "cloudformation": "",  # "cloudformation",
    "cloudtrail": "",  # "cloudtrail",
    "codestar-connections": "codestar",
    "console": "",  # "sso/console/iam",
    "ec2messages": "",  # "ec2",
    "elasticmapreduce": "emr",
    "events": "",  # "logs"
    "emr-serverless": "emr",
    "git-codecommit": "codecommit",
    "guardduty-data": "",  # "gd",
    "logs": "",  # "logs"
    "monitoring": "",  # "cloudwatch/ logs/ events/ cloudtrail?",
    "servicecatalog": "",  # "servicecatalog"
    "signin": "",  # "sso/console/iam",
    "ssm": "",  # "ssm"
    "ssmmessages": "",  # "ssm",
    "states": "lambda",
    "sts": "",  # "sts"
}
AA_TYPES = [
    "aws::s3::bucket",
    "aws::iam::role",
    # "aws::sqs::queue",
    # "aws::lambda::function",
    # "aws::lambda::layerversion",
    "aws::kms::key",
    "aws::secretsmanager::secret",
    "aws::efs::filesystem",
    "aws::ec2::snapshot",
    # "aws::ecr::repository",
    # "aws::rds::dbsnapshot",
    # "aws::rds::dbclustersnapshot",
    # "aws::sns::topic",
]
PROTOCOLS = {
    "*": "-1",
    "HOPOPT": "0",
    "ICMP": "1",
    "IGMP": "2",
    "GGP": "3",
    "IPv4": "4",
    "ST": "5",
    "TCP": "6",
    "CBT": "7",
    "EGP": "8",
    "IGP": "9",
    "BBN-RCC-MON": "10",
    "NVP-II": "11",
    "PUP": "12",
    "ARGUS": "13",
    "EMCON": "14",
    "XNET": "15",
    "CHAOS": "16",
    "UDP": "17",
    "MUX": "18",
    "DCN-MEAS": "19",
    "HMP": "20",
    "PRM": "21",
    "XNS-IDP": "22",
    "TRUNK-1": "23",
    "TRUNK-2": "24",
    "LEAF-1": "25",
    "LEAF-2": "26",
    "RDP": "27",
    "IRTP": "28",
    "ISO-TP4": "29",
    "NETBLT": "30",
    "MFE-NSP": "31",
    "MERIT-INP": "32",
    "DCCP": "33",
    "3PC": "34",
    "IDPR": "35",
    "XTP": "36",
    "DDP": "37",
    "IDPR-CMTP": "38",
    "TP++": "39",
    "IL": "40",
    "IPv6": "41",
    "SDRP": "42",
    "IPv6-Route": "43",
    "IPv6-Frag": "44",
    "IDRP": "45",
    "RSVP": "46",
    "GRE": "47",
    "DSR": "48",
    "BNA": "49",
    "ESP": "50",
    "AH": "51",
    "I-NLSP": "52",
    "SWIPE": "53",
    "NARP": "54",
    "MOBILE": "55",
    "TLSP": "56",
    "IPv6-ICMP": "58",
    "IPv6-NoNxt": "59",
    "IPv6-Opts": "60",
    "CFTP": "62",
    "SAT-EXPAK": "64",
    "KRYPTOLAN": "65",
    "RVD": "66",
    "IPPC": "67",
    "SAT-MON": "69",
    "VISA": "70",
    "IPCV": "71",
    "CPNX": "72",
    "CPHB": "73",
    "WSN": "74",
    "PVP": "75",
    "BR-SAT-MON": "76",
    "SUN-ND": "77",
    "WB-MON": "78",
    "WB-EXPAK": "79",
    "ISO-IP": "80",
    "VMTP": "81",
    "SECURE-VMTP": "82",
    "VINES": "83",
    "IPTM": "84",
    "TTP": "84",
    "NSFNET-IGP": "85",
    "DGP": "86",
    "TCF": "87",
    "EIGRP": "88",
    "OSPFIGP": "89",
    "Sprite-RPC": "90",
    "LARP": "91",
    "MTP": "92",
    "AX.25": "93",
    "IPIP": "94",
    "MICP": "95",
    "SCC-SP": "96",
    "ETHERIP": "97",
    "ENCAP": "98",
    "GMTP": "100",
    "IFMP": "101",
    "PNNI": "102",
    "PIM": "103",
    "ARIS": "104",
    "SCPS": "105",
    "QNX": "106",
    "A/N": "107",
    "IPComp": "108",
    "SNP": "109",
    "Compaq-Peer": "110",
    "IPX-in-IP": "111",
    "VRRP": "112",
    "PGM": "113",
    "L2TP": "115",
    "DDX": "116",
    "IATP": "117",
    "STP": "118",
    "SRP": "119",
    "UTI": "120",
    "SMP": "121",
    "SM": "122",
    "PTP": "123",
    "ISIS over IPv4": "124",
    "FIRE": "125",
    "CRTP": "126",
    "CRUDP": "127",
    "SSCOPMCE": "128",
    "IPLT": "129",
    "SPS": "130",
    "PIPE": "131",
    "SCTP": "132",
    "FC": "133",
    "RSVP-E2E-IGNORE": "134",
    "Mobility Header": "135",
    "UDPLite": "136",
    "MPLS-in-IP": "137",
    "manet": "138",
    "HIP": "139",
    "Shim6": "140",
    "WESP": "141",
    "ROHC": "142",
}
STYLING = """
/* the lines within the edges */
.edge:active path,
.edge:hover path {
    stroke: violet;
    stroke-width: 3;
    stroke-opacity: 1;
}

/* arrows are typically drawn with a polygon */
.edge:active polygon,
.edge:hover polygon {
    stroke: violet;
    stroke-width: 3;
    fill: violet;
    stroke-opacity: 1;
    fill-opacity: 1;
}

.edge:active text,
.edge:hover text {
    fill: purple;
    fill-opacity: 1;
}

.edge {
    stroke: #ccc;
    stroke-width: 1px;
    transition: stroke 0.3s ease;
    fill-opacity: 1;
    opacity: 1;
}

.edge.flash {
    animation: flash 1s infinite;
    fill-opacity: 1;
    opacity: 1;
}

.flash path {
    animation: flash 1s infinite;
    fill-opacity: 1;
    opacity: 1;
}

.flash polygon {
    animation: flash 1s infinite;
    fill-opacity: 1;
    opacity: 1;
}

@keyframes flash {
    0% {
        fill-opacity: 1;
        opacity: 1;
        stroke-width: 4px;
        stroke-opacity: 1;
        stroke-dasharray: 1;
    }

    50% {
        fill-opacity: 0;
        opacity: 0;
    }

    100% {
        fill-opacity: 1;
        opacity: 1;
        stroke-width: 4px;
        stroke-opacity: 1;
        stroke-dasharray: 1;
    }
}

.node:active text,
.node:hover text {
    fill: purple;
    stroke-width: 3;
    fill-opacity: 1;
    text-shadow: 1px 1px 2px white, 0 0 25px white, 0 0 5px white;
}

.node:hover path {
    stroke: violet;
    stroke-width: 3;
    stroke-opacity: 1;
}

.cluster:active text,
.cluster:hover text {
    fill: purple;
    stroke-width: 3;
    fill-opacity: 1;
    text-shadow: 1px 1px 2px white, 0 0 25px white, 0 0 5px white;
}

.cluster:hover path {
    stroke: violet;
    stroke-width: 3;
    stroke-opacity: 1;
}

image:hover {
    opacity: 1
}

image {
    opacity: 0.85;
}
"""
SCRIPT = """const nodes = document.querySelectorAll('.node');
const edges = document.querySelectorAll('.edge');

nodes.forEach((node) => {
    node.addEventListener('mouseout', () => {
        const title = "node" + node.querySelector('title').innerHTML;
        edges.forEach((edge) => {
            if (edge.classList.contains(title))
                edge.classList.remove('flash');
        });
    });
    node.addEventListener('mouseover', () => {
        const title = "node" + node.querySelector('title').innerHTML;
        edges.forEach((edge) => {
            if (edge.classList.contains(title))
                edge.classList.add('flash');
        });
    });

    node.addEventListener('click', () => {
        const a = node.querySelector('a');
        if (a) {
            const title = a.getAttribute('xlink:title');
            const w = window.open('', '_blank');
            w.document.write(`<pre>${title}</pre>`);
            w.document.close();
        }
    });
});
"""
SVGHEADER = '<!DOCTYPE html><html><head><link rel="stylesheet" href="styles.css"></head><body>'
SVGFOOTER = '<script src="script.js"></script></body></html>'

lkw = {
    "format": "%(asctime)s %(message)s",
    "datefmt": "%H:%M:%S",
    "handlers": [
        logging.FileHandler(os.path.splitext(__file__)[0] + ".log", mode="a" if DEBUG else "w"),
        logging.StreamHandler(),
    ],
    "level": logging.DEBUG if DEBUG else logging.WARN,
}
logging.basicConfig(**lkw)
counter = 0

inv_t = {  # Helper dictionary to translate route key ids into inventory key ids
    "tgw": {"i": "transitgatewayid", "r": "transitgatewayid"},
    "igw": {"i": "internetgatewayid", "r": "gatewayid"},
    "natgw": {"i": "natgatewayid", "r": "natgatewayid"},
    "vpce": {"i": "vpcendpointid", "r": "gatewayid"},
    "vpcx": {"i": "vpcpeeringconnectionid", "r": "vpcpeeringconnectionid"},
    "eni": {"i": "networkinterfaceid", "r": "networkinterfaceid"},
}


def parent(o: str, same_account=False) -> list:
    lo = []
    if type(o) == list:
        lo = list(set(o))
    if type(o) == str:
        lo = [o]
    ret = []
    assets = act if same_account else inventory
    for o in lo:
        r = False
        if parents.get(o):  # Cache for repeated calls
            r = parents[o]
        ### to ec2 ###
        elif is_instance(o, "targetgroup"):
            r = [
                j
                for v in act.get("elbv2", {}).values()
                for i in v.get("targetgroups", [])
                for j in i.get("targethealth", [])
                if bool(i.get("targethealth")) and i.get("targetgrouparn") == o
            ]
        ### to targetgroup ###
        elif is_instance(o, "elbv2"):
            r = [v["targetgrouparn"] for v in get_object(o).get("targetgroups", [])]  #
        elif is_instance(o, "vpces"):
            arns = get_object(o).get("gatewayloadbalancerarns", []) + get_object(o).get("networkloadbalancerarns", [])
            if not bool(arns):
                logging.warning(f"No attachments for {o}")
                return []
            r = [
                i.get("targetgrouparn")
                for arn in arns
                for i in inventory.get("elbv2", {}).get(arn, {}).get("targetgroups", [])
            ]
        ### to nic ###
        elif is_instance(o, "ec2"):
            a = [n["networkinterfaceid"] for n in assets["ec2"][o]["networkinterfaces"]]
            r = [c for c, v in assets["eni"].items() if v["networkinterfaceid"] in a if v["ownerid"] == get_account(c)]
            if not assets["ec2"][o]["state"]["name"] in ["terminated", "shutting-down"]:
                assert bool(r)
        elif is_instance(o, "vpce"):
            a = [n for n in assets["vpce"][o]["networkinterfaceids"]]
            r = [
                c for c, v in assets["eni"].items() if v["networkinterfaceid"] in a and get_account(c) == get_account(o)
            ]
            if bool(a) and not bool(r):
                r = [c for c, v in assets["eni"].items() if v["networkinterfaceid"] in a]
                if not bool(r):
                    if assets["vpce"][o].get("state") == "available":
                        logging.warning(f"Expected enis for {o}")
                    else:
                        logging.debug(f"        VPCE eni not in use: {o}")
        elif is_instance(o, "elb"):
            r = [c for c, v in assets["eni"].items() if get_id(o) in v["description"]]
        elif is_instance(o, "ebs"):
            # r = [c for c, v in assets["eni"].items() if get_id(o) in v["description"]]
            a = [
                i["instanceid"]
                for k, v in assets.get("ebs", {}).items()
                for i in v["attachments"]
                if get_region_arn(k) == get_region_arn(o)
            ]
            if bool(a):
                r = [
                    k
                    for k, v in assets.get("eni", {}).items()
                    if (
                        v["interfacetype"] == "interface"
                        and bool(v.get("attachment"))
                        and v.get("attachments", [{}])[0].get("instanceid") in a
                    )
                ]
        elif is_instance(o, "sagemaker"):
            r = [c for c, v in assets["eni"].items() if o in v["description"]]
        elif is_instance(o, "efs"):
            a = [i.get("networkinterfaceid") for i in get_object(o).get("mounttargets", [])]
            if not len(a):
                logging.debug(f"No mount targets for {o}")
            else:
                r = [c for c, v in assets["eni"].items() if v["networkinterfaceid"] in a]
                if not bool(r):
                    logging.info(f"No EFS mount ENIs for {o}")
        elif is_instance(o, "ds"):
            r = [
                c
                for c, v in assets["eni"].items()
                if v.get("description") and (v["description"].endswith(get_id(o.split(":")[-1])))
            ]
            if not bool(r):
                logging.info(f"No EMR ENIs for {o}")
        elif is_instance(o, "emr"):
            r = [
                c
                for c, v in assets["eni"].items()
                if v.get("description")
                and get_region_arn(c) == get_region_arn(o)
                and (v["description"].endswith(get_id(o)) or ("eni for attaching editor " in v["description"]))
            ]
            if not bool(r):
                logging.info(f"No EMR ENIs for {o}")
        elif is_instance(o, "elasticache"):
            r = [
                n
                for n, v in assets["eni"].items()
                if v.get("requesterid") == "amazon-elasticache" and get_region_arn(o) == get_region_arn(n)
            ]
        elif is_instance(o, "fsx"):
            a = get_object(o).get("networkinterfaceids", [])
            if not bool(a):
                logging.debug(f"No ENIs for {o}")
            else:
                r = [c for c, v in assets["eni"].items() if v["networkinterfaceid"] in a]
                if not bool(r):
                    logging.info(f"No ENIs for {o}")
        elif is_instance(o, "gax"):
            r = [n for n, v in assets["eni"].items() if v.get("interfacetype") == "global_accelerator_managed"]

        elif is_instance(o, "route53resolver"):
            a = [
                n
                for w in inventory["route53resolver"].values()
                for n in w["addresses"]
                if get_region_arn(o) == get_region_arn(w["arn"])
            ]  # addresses for resolvers in the region
            if bool(a):
                r = [
                    k
                    for k, v in inventory.get("eni", {}).items()
                    if v["subnetid"] in [s["subnetid"] for s in a]
                    and (
                        v["privateipaddress"] in [s["ip"] for s in a]
                        or v["association"].get("publicip") in [s["ip"] for s in a]
                    )
                ]  # Not happy about this logic
        elif is_instance(o, "rds"):
            r = [
                n
                for n, v in assets["eni"].items()
                if (v.get("requesterid") == "amazon-rds" or v.get("description") == "rdsnetworkinterface")
                and get_vpc(o) == get_vpc(n)
            ]
            if not len(r):
                logging.debug(f"Expected to see eni for {o}")
        ### to subnet ###
        elif is_instance(o, "eni"):
            r = [k for k, v in assets["subnet"].items() if v["subnetid"] == assets["eni"][o]["subnetid"]]
            if not bool([x for x in r if assets["subnet"][x]["ownerid"] == get_object(o).get("ownerid")]):
                ap = o.split(":")
                if ap[4] != act["id"]:  # Most likely shared vpc
                    ap[5] = f"subnet/{shared_subnet_label}"
                    sn = ":".join(ap)
                else:
                    ap[5] = f"subnet/{get_object(o).get('subnetid')}"
                    sn = ":".join(ap)
                    vpc_id = assets["eni"].get(o, {}).get("vpcid", [])
                    if not bool(vpc_id):
                        continue
                    vpc_arn = vpcid_to_vpc(vpc_id[0])
                    if bool(vpc_arn):
                        vpc_arn = vpc_arn[0]
                    else:  # Most likely incomplete decom
                        ap[-1] = "vpc/" + vpc_id
                        vpc_arn = ":".join(ap)

                    vpc_owner = assets.get("vpc", {}).get(vpc_arn, {}).get("ownerid", act["id"])
                    assets["subnet"][sn] = {
                        "subnetid": sn,
                        "ownerid": vpc_owner,
                        "vpcid": inventory["eni"][o]["vpcid"],
                    }
                r.append(sn)
            assert bool(r)
        ### to vpc ###
        elif is_instance(o, "subnet"):
            r = [
                k
                for k, v in assets.get("vpc", {}).items()
                if v["vpcid"] == assets["subnet"].get(o, {}).get("vpcid")
                and assets["subnet"].get(o, {}).get("ownerid") == act["id"]
            ]
            ap = o.split(":")
            if not bool(r):  # Make up a VPC
                if ap[4] != act["id"]:
                    ap[5] = f"vpc/{shared_vpc_label}"
                    r = ":".join(ap)
            elif not bool([x for x in r if assets["vpc"][x].get("ownerid") == get_account(x)]):
                # VPC not owned by our subnet account - assume shared VPC
                if ap[4] != act["id"]:
                    ap[5] = f"vpc/{shared_vpc_label}"
                    r = ":".join(ap)
                else:
                    r = [x for x in r if get_account(x) == act["id"]]
            else:  # WONTDO: not every possible scenario covered here
                r = [x for x in r if get_account(x) == act["id"]]
        elif is_instance(o, "natgw"):
            r = [z for z, v in assets["vpc"].items() if v["vpcid"] == assets["natgw"][o]["vpcid"]]
        elif is_instance(o, "igw"):
            a = [z["vpcid"] for z in assets["igw"][o]["attachments"]]
            if not bool(a):
                logging.debug(f"igw detached: {o}")
            else:
                r = [k for k, v in assets["vpc"].items() if v["vpcid"] in a]
                if not bool(r):
                    logging.warning(f"[     ] Connection to unknown vpc {o} > {a}")
                    r = o.split(":")
                    r = f"arn:aws:ec2:{r[3]}:{r[4]}:vpc/{a[0]}"
        #### to region ###
        elif is_instance(o, ["tgw", "dxgw", "vpc", "ramresourceingress"] + regional_services):
            r = o.split(":")
            r = f"::region:{r[3]}:{r[4]}:{r[3]}"
        ### to account ###
        elif is_instance(o, "region"):
            r = f"::account::{o.split(':')[4]}::"
        elif is_instance(o, "user"):
            r = f"::account::{o.split(':')[4]}::"

        if type(r) == list:
            ret.extend(r)
            parents[o] = r
        else:
            ret.append(r)
            parents[o] = [r]
    return ret


def in_account(account, lo) -> bool:
    if bool(lo):
        if type(lo) == str:
            lo = [lo]
        for o in lo:
            if re.findall(arn_pattern_account, o) == re.findall(arn_pattern_account, account):
                return True
    return False


def get_account(o: str) -> str:
    if o == "*":
        return "*"
    if re.search(arn_pattern_account, o):
        return re.findall(arn_pattern_account, o)[0]
    return ""


def get_region(o) -> str:
    return o.split(":")[3]


def get_region_arn(o: str) -> str:
    if not ":" in o:
        return ""
    x = o.split(":")
    return f"::region:{x[3]}:{x[4]}:{x[3]}"


def get_account_arn(o: str) -> str:
    if not ":" in o:
        return ""
    x = o.split(":")
    return f"::account::{x[4]}::"


def get_type(o: str) -> str:
    for t in types:
        if is_instance(o, t):
            return t
    else:
        logging.warning(f"Unknown resource type: {o}")
        assert False, f"Unknown resource type: {o}"
        return o.split(":")[2]


def get_object(o: str) -> dict:
    t = get_type(o)
    r = inventory.get(t, {}).get(o, {})
    if bool(r):
        return r
    elif t == "ec2":
        r = [i for i in inventory.get(t, {}) if i.get("instanceid") == o]
        if bool(r):
            return r[0]
    return dict(r)


def to_arn(o):
    if o in inventory.get("ec2", {}).keys():
        return o
    for i, v in inventory.get("ec2", {}).items():
        if v.get("instanceid") == o:
            return i


def is_instance(o, res_type) -> str:
    if type(res_type) == str:
        res_type = [res_type]
    for t in res_type:
        if not t in types:
            logging.warning(f"Unknown resource type: {t}")
            return ""
        r = re.search(types[t], o)
        if r:
            return r
    return ""


def get_global_inventory() -> dict:
    inventory = {}
    for fn in sorted(glob.glob("data/*_*.json")):  # WONTDO: Should reverse sort to have assets override config
        if not fn == fn.lower():
            continue
        with open(fn) as file:
            key = fn.split("_")[-1].split(".")[0]
            if not key in inventory:
                inventory[key] = {}
            for k, v in json.loads(file.read().lower()).items():
                inventory[key].update({k: v})
    inventory["instanceprofile"] = get_instance_profiles(inventory)
    return inventory


def get_account_inventory(f):
    for fn in sorted(glob.glob(f"{f}*.json")):
        if not fn == fn.lower():
            continue
        with open(fn) as file:
            act[fn.split(os.sep)[-1].split(".")[0]] = json.loads(file.read().lower())

    act["kms"] = {k: v for k, v in act.get("kms", {}).items() if v.get("keymanager") == "customer"}
    act["usercreds"] = {uc["arn"]: uc for v in act.get("creds", {}).values() for uc in v}
    get_autoscaling_instances()
    if FORCE or sum([len(v) for v in act.values()]) > 500:
        graph_attr["concentrate"] = "false"
        graph_attr["splines"] = "curved"


def get_autoscaling_instances():
    if not act.get("autoscalinginstances"):
        act["autoscalinginstances"] = {}
    for l in act.get("autoscaling", {}).values():
        for v in l.get("instances", []):
            act["autoscalinginstances"][v["instanceid"]] = v["instanceid"]


def add_orphan(k, v):
    if not g.get("orphan"):
        g["orphan"] = {}
    if not k in g["orphan"]:
        g["orphan"][k] = []
    g["orphan"][k].append(v)


def classify_access(arn: str):
    r = None
    # if type(arn) == dict:
    #     if "aws" in arn:
    #         arn = arn["aws"]
    #     elif "service" in arn:
    #         return "private"
    o_t = get_type(arn)
    if o_t in ["s3"]:
        arn = by_id(o_t, arn)
    p_id = get_account(arn)
    in_org = bool(inventory.get("org")) and p_id in inventory["org"]
    if p_id == "*":
        r = "public"
    elif in_org and p_id != act["id"]:
        r = "external"
    elif not in_org:
        r = "public"
    else:
        r = "private"
    return r


def get_external_policy_principals(arn, policy_document) -> dict:
    entities = {"external": [], "public": [], "private": [], "broken": []}
    if not bool(policy_document):
        return entities
    if type(policy_document) == str:
        policy_document = unquote(policy_document)
        policy_document = json.loads(policy_document)
    if not type(policy_document) in [list, dict]:
        assert False, f"Policy document type: {type(policy_document)}"
    access = "private"
    for statement in policy_document["statement"]:
        if statement.get("effect") != "allow":  # Gets too complex otherwise
            continue
        p_o = statement.get("principal", {})
        if type(p_o) == dict:
            if "aws" in p_o:
                p_o = p_o["aws"]
            elif "service" in p_o:
                del p_o["service"]
        # if not bool(p_o):
        #     continue
        if bool(p_o) and type(p_o) in [str, dict]:
            p_o = [p_o]
        principal_access = {classify_access(p) for p in p_o}
        if "public" in principal_access:
            principal_access = "public"
        elif "external" in principal_access:
            principal_access = "external"
        else:
            principal_access = "private"
        condition = condition_external(statement)
        # Getting common deonominator
        if "private" in [principal_access, condition["principal"]]:
            principal_access = "private"
        elif "external" in [principal_access, condition["principal"]]:
            principal_access = "external"
        else:
            principal_access = "public"

        r_o = statement.get("resource")
        if not bool(r_o):  # Resource policies
            resource_access = "private"
        else:
            if type(r_o) == str:
                r_o = [r_o]
            r_access = {classify_access(o) for o in r_o}
            if "public" in r_access:
                resource_access = condition["resource"]
            elif "external" in r_access:
                resource_access = "external" if condition["resource"] in ["public"] else condition["resource"]
            else:
                resource_access = "private"
        # if not (principal_access in ["public", "external"] or resource_access in ["public", "external"]):
        #     continue
        if principal_access in ["public"]:
            access = "public"
            entities[access].append(arn)
            break
        elif principal_access in ["external"]:
            if not access in ["public"]:
                access = "external"
        else:
            if resource_access in ["public", "external"]:
                access = "external"
            else:
                if access not in ["public", "external"]:
                    access = "private"
    else:
        entities[access].append(arn)
        return entities

    return entities


def condition_external(statement: dict) -> dict:
    p_external, r_external = None, None
    for ck in statement.get("condition", {}):
        if ck in ["bool"]:
            continue  # FIXME
        if not ck in [
            "arnequals",
            "arnlike",
            "stringequals",
            "stringlike",
            "foranyvalue:arnequals",
            "foranyvalue:stringlike",
        ]:
            assert False, f"Unexpected conditional operator: {ck}"
            continue
        for cck, ccv in statement["condition"][ck].items():
            if cck in [
                "cloudwatch:namespace",
                "ec2:createaction",
                "ec2:resourcetag/awsrdscustom",
                "s3:x-amz-acl",
                "ssm:resourcetag/aws:cloudformation:stack-name",
            ]:
                continue
            if cck in ["sts:externalid", "kms:encryptioncontext:aws:cloudtrail:arn"]:
                continue
            if cck in ["kms:viaservice", "iam:awsservicename"]:
                p_external = "private" if not p_external in ["public", "external"] else p_external
                continue  # should be external at the very least
            if cck in ["aws:principalorgid"]:
                if not ccv in {aid.split("/")[1] for aid in inventory.get("organizations", {})}:
                    p_external = "public"
                    break
                else:
                    p_external = "external" if not p_external in ["public"] else p_external
            elif cck in ["aws:resourceorgid"]:
                if not ccv in {aid.split("/")[1] for aid in inventory.get("organizations", {})}:
                    r_external = "public"
                else:
                    r_external = "external"
            elif cck in [
                "aws:principalaccount",
                "aws:principalarn",
                "kms:calleraccount",
                "aws:sourceaccount",
                "aws:sourceowner",
                "aws:sourcearn",
            ]:
                ccvs = [ccv] if type(ccv) == str else ccv
                for cccv in ccvs:
                    if get_account(cccv) == act["id"]:
                        p_external = "private" if not p_external in ["public", "external"] else p_external
                        continue
                    if get_account(cccv) in inventory.get("org", {}):
                        p_external = "external" if not p_external or p_external == "private" else p_external
                    else:
                        p_external = "public"
                        break
            elif cck in ["aws:resourceaccount", "s3:resourceaccount", "secretsmanager:secretid"]:
                ccvs = [ccv] if type(ccv) == str else ccv
                for cccv in ccvs:
                    if get_account(cccv) == act["id"]:
                        r_external = "private" if not r_external in ["public", "external"] else r_external
                        continue
                    if get_account(cccv) in inventory.get("org", {}):
                        # r_external = "external"
                        r_external = "external" if r_external == "private" else r_external
                    else:
                        r_external = "public"
                        break
            else:
                assert False, f"Unexpected conditional attr: {cck}"
    if not p_external:
        p_external = "public"
    if not r_external:
        r_external = "public"
    return {"principal": p_external, "resource": r_external}


def add_finding(category, key, o):
    if not category in findings:
        findings[category] = {}
    findings[category][key] = o


def public_elbs():
    return [
        x
        for v in inventory.get("elbv2", {}).values()
        for w in v["targetgroups"]
        for x in w["targethealth"]
        if v["type"] != "gateway" and v["scheme"] != "internal"
    ]


def get_encryption(arns) -> dict:
    arns = arns if type(arns) in [list, dict] else [arns]
    r = {"encrypted": [], "unencrypted": []}
    for arn in arns:
        o_t, o_o = get_type(arn), get_object(arn)
        if o_t == "ami":
            for c in o_o.get("blockdevicemappings", []):
                if not c.get("ebs"):
                    continue
                if c["ebs"].get("encrypted"):
                    r["encrypted"].append(arn)
                else:
                    r["unencrypted"].append(arn)
        elif o_t in ["backup"]:
            if not ":backup-vault:" in arn:
                continue  # Encryption is set at vault level
            if o_o.get("encryptionkeyarn"):
                r["encrypted"].append(arn)
            else:
                r["unencrypted"].append(arn)
        elif o_t in ["dxcon"]:
            if o_o.get("portencryptionstatus") == "encryption down":
                r["unencrypted"].append(arn)
            else:
                r["encrypted"].append(arn)
        elif o_t == "dynamodb":
            if type(o_o) != list:
                o_o = [o_o]
            for o2 in o_o:
                if o2.get("ssedescription") and o2["ssedescription"].get("status") == "enabled":
                    r["encrypted"].append(arn)
                else:
                    r["unencrypted"].append(arn)
        elif o_t in ["ebs", "ebssnapshot", "efs", "rdssnapshot"]:
            if o_o.get("encrypted"):
                r["encrypted"].append(arn)
            else:
                r["unencrypted"].append(arn)
        elif o_t == "ec2":  # FIXME: EC2 get_encryption: should be checking IMDSV2 or EBS volume or Nitro?
            if (
                o_o.get("metadataoptions", {}).get("httptokens") == "required"
                and o_o.get("metadataoptions", {}).get("httpendpoint") == "enabled"
                and o_o.get("metadataoptions", {}).get("httpputresponsehoplimit") == 2
            ):
                r["encrypted"].append(arn)
            else:
                r["unencrypted"].append(arn)
        elif o_t == "ecr":
            if o_o.get("encryptionconfiguration", {}).get("encryptiontype"):
                r["encrypted"].append(arn)
            else:
                r["unencrypted"].append(arn)
        elif o_t == "elasticache":
            if (
                o_o.get("transitencryptionmode") == "required"
                and o_o.get("transitencryptionenabled")
                and o_o.get("atrestencryptionenabled")
            ):
                r["encrypted"].append(arn)
            else:
                r["unencrypted"].append(arn)
        elif o_t == "elbv2":
            for v in o_o.get("listeners", []):
                if not (
                    v.get("protocol") in ["https", "tls", "geneve"]
                    and v.get("sslpolicy")
                    and v.get("certificates")
                    and bool(v["certificates"])
                ):
                    r["unencrypted"].append(arn)
                    break
            else:
                r["encrypted"].append(arn)
        elif o_t == "fsx":
            r["encrypted"].append(arn)
        elif o_t == "kms":
            r["encrypted"].append(arn)
            # if o_o.get("keyrotationstatus"):
            #     r["encrypted"].append(arn)
            # else:
            #     r["unencrypted"].append(arn)
        elif o_t == "rds":
            if o_o.get("storageencrypted") and o_o.get("kmskeyid"):
                r["encrypted"].append(arn)
            else:
                r["unencrypted"].append(arn)
        elif o_t in ("route53"):
            r["unencrypted"].append(arn)
        elif o_t == "s3":
            for c in o_o.get("serversideencryptionconfiguration", {}).get("rules", {}):
                if c.get("bucketkeyenabled"):
                    r["encrypted"].append(arn)
                    break
                if bool([cc for cc in c.get("applyserversideencryptionbydefault", {})]):
                    r["encrypted"].append(arn)
                    break
            else:
                r["unencrypted"].append(arn)
        elif o_t == "secretsmanager":
            r["encrypted"].append(arn)
        elif o_t == "sns":
            if o_o.get("kmsmasterkeyid"):
                r["encrypted"].append(arn)
            else:
                r["unencrypted"].append(arn)
        elif o_t == "sqs":
            if o_o.get("sqsmanagedsseenabled"):
                r["encrypted"].append(arn)
            elif o_o.get("kmsmasterkeyid"):
                r["encrypted"].append(arn)
            else:
                r["unencrypted"].append(arn)
        elif o_t == "targetgroup":
            o_o = [
                i
                for v in inventory.get("elbv2", {}).values()
                for i in v.get("targetgroups", [])
                if i.get("targetgrouparn") == arn
            ][0]
            if o_o.get("protocol") in ["https", "tls", "geneve"]:
                r["encrypted"].append(arn)
            else:
                r["unencrypted"].append(arn)
        elif o_t == "user":
            if bool(act.get("usercreds")):
                uc = act["usercreds"].get(arn, {})
                if uc.get("mfa_active") != "true":
                    r["unencrypted"].append(arn)
                else:
                    r["encrypted"].append(arn)
        else:
            if not o_t in [
                "account",
                "ecs",
                "elasticbeanstalk",
                "elb",
                "igw",
                "lambda",
                "lakeformation",
                "natgw",
                "role",
                "ses",
                "transfer",
                "vpc",
                "vpce",
                "vpcx",
            ]:
                logging.debug(f"Unable to determine encryption for {arn}")
    for i in r["unencrypted"]:
        if get_type(i) in ["ec2", "dxcon", "s3", "route53", "user", "targetgroup", "elbv2"]:  # S3 != S3Bucket
            continue
        add_finding("unencrypted", i, {"type": get_type(i)})
    return r


def get_public(arns) -> dict:
    arns = arns if type(arns) in [list, dict] else [arns]
    r = {"private": [], "public": [], "external": []}  # , "broken": []
    for arn in arns:
        o_t, o_o = get_type(arn), get_object(arn)
        if o_t == "account":
            r[classify_access(arn)].append(arn)
            continue
        elif o_t == "ami":
            if o_o.get("public"):
                r["public"].append(arn)
            elif o_o.get("launchpermission") and not o_o.get("launchpermission") == [o_o.get("imageid")]:
                r["external"].append(arn)
            else:
                r["private"].append(arn)
            continue
        elif o_t == "backup":
            policy_document = o_o.get("accesspolicy")
            ext = get_external_policy_principals(arn, policy_document)
            for access in ["public", "external", "private"]:
                if arn in ext[access]:
                    r[access].append(arn)
                    break
            continue
        elif o_t == "ebssnapshot":
            if o_o.get("createvolumepermission") and o_o["createvolumepermission"] != [o_o.get("snapshotid")]:
                if "group" in o_o["createvolumepermission"]:
                    r["public"].append(arn)
                else:
                    r["external"].append(arn)
            else:
                r["private"].append(arn)
            continue
        elif o_t == "ec2":
            for ni in o_o.get("networkinterfaces", []):
                if ni.get("association"):
                    r["public"].append(arn)
                    continue
            else:
                exposed_ec2 = [
                    i
                    for v in public_elbs()
                    for tg in inventory.get("elbv2", {})[v]["targetgroups"]
                    for i in tg["targethealth"]
                    if get_type(i) == "ec2"
                    and o_o["instanceid"] == i  # via ec2 instance
                    or i in [o_o["privateipaddress"], o_o.get("publicipaddress")]  # via ip
                ]
                if bool(exposed_ec2):
                    r["external"].append(arn)
                    continue
                r["private"].append(arn)
            continue
        elif o_t == "eni":
            access = "private"
            requester = o_o.get("requesterid")
            if bool(o_o.get("association")):
                access = "public"
            elif o_o["interfacetype"] in ["gateway_load_balancer_endpoint"]:
                access = "public"
            elif bool(requester):
                if not requester in ["amazon-elb"]:
                    if classify_access(get_account(requester)) in ["public"]:
                        access = "external"
            r[access].append(arn)
            continue
        elif o_t in ["elb", "elbv2"]:
            if o_o.get("scheme") == "internal":
                r["private"].append(arn)
            else:
                r["public"].append(arn)
            continue
        elif o_t == "emr":
            r[classify_access(o_o.get("servicerole", act["id"]))].append(arn)
            continue
        elif o_t in ["gax", "igw"]:
            r["public"].append(arn)
            continue
        elif o_t == "kms":
            policy_document = o_o.get("policy")
            ext = get_external_policy_principals(arn, policy_document)
            for access in ["public", "external", "private"]:
                if arn in ext[access]:
                    r[access].append(arn)
                    break
            continue
        elif o_t == "lambda":
            laccess = classify_access(o_o.get("role", act["id"]))
            if laccess in ["private", "external"]:
                if bool(o_o.get("vpcconfig")):
                    laccess = "external"
            else:
                laccess = "public"
                r[laccess].append(arn)
                continue
            policy_document = o_o.get("policy")
            ext = get_external_policy_principals(arn, policy_document)
            for access in ["public", "external"]:  # "private", "broken"
                if arn in ext[access]:
                    r[access].append(arn)
                    break
            else:
                r[laccess].append(arn)
            continue
        elif o_t == "natgw":
            if o_o.get("connectivitytype") == "public":
                r["external"].append(arn)
            else:
                r["public"].append(arn)
                assert False, f"{o_t} without public connectivity: {o_o}"
            continue
        elif o_t == "rds":
            if o_o.get("publiclyaccessible"):
                r["public"].append(arn)
            else:
                r["private"].append(arn)
            continue
        elif o_t in ["role", "instanceprofile"]:
            laccess = "private"
            if o_t == "instanceprofile":
                if not bool(o_o.get("roles")):
                    continue  # Profile lost association with a role
                # Assuming 1:1 relationships between instance profiles and roles
                o_o = inventory.get("role", {}).get(o_o["roles"][0]["arn"])
            policy_document = o_o["assumerolepolicydocument"]
            ext = get_external_policy_principals(arn, policy_document)
            for access in ["public", "external", "private"]:  # , "broken"
                if arn in ext[access]:
                    if access == "public":
                        laccess = access
                        break
                    if laccess == "external":
                        continue
            else:
                policy_document = o_o["rolepolicylist"]
                if type(policy_document) != list:
                    policy_document = [policy_document]
                for pd in policy_document:
                    ext = get_external_policy_principals(arn, pd.get("policydocument"))
                    for access in ["public", "external", "private"]:  # , "broken"
                        if arn in ext[access]:
                            if access in ["public", "external"]:
                                laccess = "external"
                                break
            r[laccess].append(arn)  # TODO: attachedmanagedpolicies
            continue
        elif o_t == "s3ap":
            laccess = "private"
            pabc = o_o.get("publicaccessblockconfiguration")
            if pabc and {p for p in pabc.values()} == {1}:  # Makes no difference
                laccess = "private"
            laccess = classify_access(o_o.get("bucketaccountid", act["id"]))
            if not laccess in ["public"]:
                policy_document = o_o.get("bucketpolicy", {}).get("policytext")
                ext = get_external_policy_principals(arn, policy_document)
                for access in ["public", "external"]:
                    if arn in ext[access]:
                        laccess = access
                        break
            r[laccess].append(arn)
            continue
        elif o_t == "s3":
            laccess = "private"
            if o_o.get("ispublic"):
                laccess = "public"
            else:
                policy_document = o_o.get("bucketpolicy", {}).get("policytext")
                if bool(policy_document):
                    ext = get_external_policy_principals(arn, policy_document)
                    for access in ["public", "external", "private"]:
                        if arn in ext[access]:
                            laccess = access
                            break
                # for k, apab in inventory.get("s3blockpublic", {}).items():
                #     if get_region_arn(k) != get_region_arn(arn):
                #         continue
                #     if set(apab.values()) == {True}:
                #         r["external"].append(arn)
                #         break
            r[laccess].append(arn)
            continue
        elif o_t == "secretsmanager":
            policy_document = o_o.get("resourcepolicy")
            ext = get_external_policy_principals(arn, policy_document)
            for access in ["public", "external", "private"]:
                if arn in ext[access]:
                    r[access].append(arn)
                    break
            continue
        elif o_t in ["sns", "sqs"]:
            policy_document = o_o.get("policy")
            ext = get_external_policy_principals(arn, policy_document)
            for access in ["public", "external", "private"]:
                if arn in ext[access]:
                    r[access].append(arn)
                    break
            continue
        elif o_t == "targetgroup":
            o_o = [
                i
                for v in inventory.get("elbv2", {}).values()
                for i in v.get("targetgroups", [])
                if i.get("targetgrouparn") == arn
            ][0]
            for l in o_o["loadbalancerarns"]:
                if get_object(l).get("scheme") != "internal":
                    r["public"].append(arn)
                    break
            else:
                if arn in [
                    tg["targetgrouparn"] for v in public_elbs() for tg in inventory.get("elbv2", {})[v]["targetgroups"]
                ]:
                    r["public"].append(arn)
                    continue
                r["private"].append(arn)
            continue
        elif o_t == "unknown":
            r["public"].append(arn)
            continue
        elif o_t == "user":
            if bool(act.get("usercreds")):
                uc = act["usercreds"].get(arn, {})
                if arn.split(":")[-1] == "root":
                    if uc.get("mfa_active") == "true":
                        r["private"].append(arn)
                    elif (
                        uc.get("access_key_1_active")
                        == uc.get("access_key_2_active")
                        == uc.get("cert_1_active")
                        == uc.get("cert_2_active")
                        == "false"
                    ):
                        r["external"].append(arn)
                    else:
                        r["public"].append(arn)
                else:
                    if uc.get("mfa_active") == "true":
                        r["private"].append(arn)
                    elif set(
                        [
                            uc.get("access_key_1_active", "false"),
                            uc.get("access_key_2_active", "false"),
                            uc.get("cert_1_active", "false"),
                            uc.get("cert_2_active", "false"),
                        ]
                    ) != {"false"}:
                        r["external"].append(arn)
                    elif uc.get("password_enabled") != "false":
                        r["public"].append(arn)
                    else:
                        r["private"].append(arn)
            # else: # If no user creds generated (due to throttle limit)
            continue
        elif o_t == "vpc":
            if o_o.get("vpcid") and not o_o["vpcid"] in public_vpcs:
                r["private"].append(arn)
            else:
                r["public"].append(arn)
            continue
        elif o_t == "vpce":
            policy_document = o_o.get("policydocument")
            ext = get_external_policy_principals(arn, policy_document)
            for access in ["public", "external", "private"]:
                if arn in ext[access]:
                    r[access].append(arn)
                    break
            continue
        elif o_t == "vpces":
            access = "private"
            if o_o.get("owner") != get_account(arn):
                if not o_o["owner"] in inventory.get("org", {}):
                    access = "public"
                else:
                    if not o_o["owner"] == get_account(arn):
                        access = "external"
            for perm in o_o.get("vpcespermissions", []):
                if perm.get("principaltype") == "account":
                    if get_account(perm.get("principal")) in [get_account(arn), act["id"]]:
                        continue
                    elif not get_account(perm.get("principal")) in inventory.get("org", {}):
                        access = "public"
                        break
                    elif get_account(perm.get("principal")) != get_account(arn):
                        if access != "public":
                            access = "external"
                else:
                    assert False, f"Unexpected principal type in {o_o}"
            r[access].append(arn)
        else:
            if not o_t in [
                "ebs",
                "efs",
                "elasticbeanstalk",
                "lakeformation",
                "route53",
                "ses",
                "vpcx",
            ]:
                logging.debug(f"Unable to determine public for {arn}")
    return r


def get_available(arns) -> dict:
    arns = arns if type(arns) in [list, dict] else [arns]
    r = {"available": [], "unavailable": [], "inactive": []}
    for arn in arns:
        o_t, o_o = get_type(arn), get_object(arn)
        if o_t == "ec2":
            if o_o.get("state", {}).get("name") == "running":
                r["available"].append(arn)
            else:
                r["unavailable"].append(arn)
        elif o_t == "elbv2":
            if o_o.get("state", {}).get("code") == "active":
                r["available"].append(arn)
            else:
                r["unavailable"].append(arn)
        elif o_t == "emr":
            if o_o.get("status", {}).get("state") in ["waiting", "running"]:
                r["available"].append(arn)
            else:
                r["unavailable"].append(arn)
        elif o_t == "eni":
            if o_o.get("attachment", {}).get("status") == "attached":
                r["available"].append(arn)
            else:
                r["unavailable"].append(arn)
        elif o_t == "igw":
            if o_o.get("attachments", [])[0].get("state") == "available":
                r["available"].append(arn)
            else:
                r["unavailable"].append(arn)
        elif o_t == "kms":
            if bool(o_o.get("enabled", {})):
                r["available"].append(arn)
            # else:
            #     r["unavailable"].append(arn)
        elif o_t == "lambda":
            if o_o.get("state") == "active":
                r["available"].append(arn)
            else:
                r["unavailable"].append(arn)
        elif o_t == "rdssnapshot":
            if o_o.get("status") == "available":
                r["available"].append(arn)
            else:
                r["unavailable"].append(arn)
        elif o_t == "route53resolver":
            if o_o.get("status", "") == "operational":
                r["available"].append(arn)
            else:
                r["unavailable"].append(arn)
        elif o_t in ["vpc", "vpce", "natgw"]:
            if o_o.get("state") == "available":
                r["available"].append(arn)
            else:
                r["unavailable"].append(arn)
        elif o_t in ["vpcx"]:
            if o_o.get("status", {}).get("code") == "active":
                r["available"].append(arn)
            else:
                r["unavailable"].append(arn)
        else:
            if not o_t in [
                "account",
                "ami",
                "athena",
                "backup",
                "ebs",
                "ebssnapshot",
                "ecs",
                "efs",
                "elasticbeanstalk",
                "elb",
                "dynamodb",
                "glue",
                "lakeformation",
                "role",
                "route53",
                "s3",
                "sagemaker",
                "secretsmanager",
                "ses",
                "sns",
                "sqs",
                "targetgroup",
                "transfer",
                "user",
            ]:
                logging.debug(f"Unable to determine available for {arn}")
    return r


def get_xaccess_for_owner(owner):
    return [
        a for a in access_findings if owner == a["resourceowneraccount"] and not "federated" in a.get("principal", {})
    ]


def get_xaccount(arns) -> dict:
    arns = arns if type(arns) in [list, dict] else [arns]
    r = {"secured": [], "normal": []}
    for arn in arns:
        o_t = get_type(arn)
        a = arn.split(":")
        if o_t == "ebssnapshot":
            a[4] = ""  # Account ID
        elif o_t == "role":  # TODO: Check for it in Principal too
            a[3] = ""  # Region
        elif o_t == "s3":
            a[3] = a[4] = ""  # Region and Account ID
        arn = ":".join(a)
        access = [a for a in access_findings if arn == a["resource"]]
        if not bool(access):
            continue
        add_finding("access", arn, access)
        for entry in access:
            if not bool(entry.get("principal")):
                assert False, f"Principal not found: {entry}"
                continue
            if type(entry["principal"]) != dict:
                assert False, f"Unexpected principal type: {entry}"
            for principal in entry["principal"]:
                if not "aws" in principal:
                    assert False, f"Unexpected principal kind: {principal}"
                add_orphan(arn, {get_account(entry["principal"]["aws"]): {arn: entry}})
    return r


def get_managed(arns) -> dict:
    arns = arns if type(arns) in [list, dict] else [arns]
    r = {"managed": [], "unmanaged": []}
    for arn in arns:
        o_t, o_o = get_type(arn), get_object(arn)

        if o_t == "ec2":
            moids = {get_id(i) for i in act.get("ssmec2", {})}
            if get_id(arn) in moids:
                r["managed"].append(arn)
            else:
                r["unmanaged"].append(arn)
                if not "nossm" in inventory:
                    inventory["nossm"] = {}
                inventory["nossm"][arn] = o_o
        elif o_t == "elbv2":
            for w in act.get("wafv2webacl", {}).values():
                if not arn in w.get("attachments", {}):
                    continue
                r["managed"].append(arn)
                break
            else:
                r["unmanaged"].append(arn)
        elif o_t == "role":  # FIXME: or should we instead test if the role came out of CFN?
            # How many roles with this name we found
            role_len = len([i for i in inventory["role"].values() if i["rolename"] == o_o["rolename"]])
            # If more than half of accounts have similar role, then assume it's normal
            if role_len * 2 > len(inventory.get("org", "")) > 4:  # If role is common among accounts, skip
                r["managed"].append(arn)
            else:  # WONTDO: maybe our org is single account
                r["unmanaged"].append(arn)
    return r


def get_logs(arns) -> dict:
    if type(arns) != list and type(arns) != dict:
        arns = [arns]
    r = {"nologs": [], "logs": []}
    for arn in arns:
        o_t, o_o = get_type(arn), get_object(arn)
        if o_t == "account":
            if f"::account::{arn}:contact" in inventory.get("contact", []):
                r["logs"].append(arn)
            else:
                r["nologs"].append(arn)
        elif o_t == "elb":
            if bool(o_o.get("loadbalancerattributes", {}).get("accesslog", {}).get("enabled")):
                r["logs"].append(arn)
            else:
                r["nologs"].append(arn)
        elif o_t == "elbv2":
            if bool(o_o.get("loadbalancerattributes")):
                for v in o_o["loadbalancerattributes"]:
                    if v.get("key") == "access_logs.s3.enabled" and v["value"] == "true":
                        r["logs"].append(arn)
                        break
                else:
                    r["nologs"].append(arn)
        elif o_t == "emr":
            if bool(o_o.get("loguri")):
                r["logs"].append(arn)
            else:
                r["nologs"].append(arn)
        elif o_t == "kms":
            r["logs"].append(arn)
        elif o_t == "rds":
            if bool(o_o.get("enabledcloudwatchlogsexports")):
                r["logs"].append(arn)
            else:
                r["nologs"].append(arn)
        elif o_t == "role":
            if bool(o_o.get("rolelastused")):  # Not populated in AWS Config
                r["logs"].append(arn)
            else:
                r["nologs"].append(arn)
        elif o_t == "s3":
            if bool(o_o.get("bucketloggingconfiguration")):
                r["logs"].append(arn)
            else:
                r["nologs"].append(arn)
        elif o_t == "secretsmanager":
            r["logs"].append(arn)  # naive
        elif o_t == "targetgroup":
            o_o = [
                i
                for v in inventory.get("elbv2", {}).values()
                for i in v.get("targetgroups", [])
                if i.get("targetgrouparn") == arn
            ][0]
            a = [v for l in o_o["loadbalancerarns"] for v in get_object(l).get("loadbalancerattributes", [])]  #
            for v in a:
                if v.get("key") == "access_logs.s3.enabled" and v["value"] == "false":
                    r["nologs"].append(arn)
                    break
                elif v.get("key") == "access_logs.s3.enabled" and v["value"] == "true":
                    break
            else:
                r["logs"].append(arn)
        elif o_t == "user":
            if bool(act.get("usercreds")):
                uc = act["usercreds"].get(arn, {})
                if (
                    uc.get("password_last_used") in ["no_information", "n/a"]
                    and uc.get("access_key_1_active") == "false"
                    and uc.get("access_key_2_active") == "false"
                    and uc.get("cert_1_active") == "false"
                    and uc.get("cert_2_active") == "false"
                ):
                    r["nologs"].append(arn)
                else:
                    r["logs"].append(arn)
        elif o_t in ["eni", "vpc", "vpce"]:
            if bool(o_o.get("vpcid")) and o_o["vpcid"] in vpc_logging:
                r["logs"].append(arn)
            else:
                r["nologs"].append(arn)
        else:
            if not o_t in [
                "ami",
                "backup",
                "dynamodb",
                "ebs",
                "ebssnapshot",
                "ec2",
                "efs",
                "elasticbeanstalk",
                "igw",
                "lakeformation",
                "lambda",
                "natgw",
                "opensearch",
                "rdssnapshot",
                "route53",
                "ses",
                "sns",
                "sqs",
                "vpcx",
                "wafv2",
            ]:  # WONTDO: add get_logs support
                logging.debug(f"Unable to determine logging for {arn}")
    return r


def vpcs_with_logging():
    return [
        v["vpcid"]
        for v in inventory.get("flowlog", {}).values()
        if v.get("vpcid") and v.get("deliverlogsstatus") == "success" and v.get("flowlogstatus") == "active"
    ]


def get_vpc(arn: str) -> str:
    o = get_object(arn)
    if o.get("vpcid"):
        return o["vpcid"]
    elif o.get("dbsubnetgroup", {}).get("vpcid"):
        return o["dbsubnetgroup"]["vpcid"]
    elif o.get("vpcconfiguration", {}).get("vpcid"):
        return o["vpcconfiguration"]["vpcid"]
    return ""


def show_vpc_services(vpc_arn: str):
    r_services = [e for service in vpc_services for e in act.get(service, []) if get_vpc(e) == get_id(vpc_arn)]
    if not bool(r_services):
        return
    with Cluster(label=dup_label("Services", vpc_arn), graph_attr={"bgcolor": "transparent"}):
        for service_kind in vpc_services:
            services = [e for e in act.get(service_kind, []) if get_vpc(e) == get_id(vpc_arn)]
            if not len(services):
                continue
            kw = {"label": get_format(services).format(service_kind)}
            if service_kind == "rds":
                rds_o = [inventory.get(service_kind, {}).get(s, {}) for s in services]
                kw["tooltip"] = "\n".join([f"{o.get('engine')}/{o.get('dbinstanceidentifier')}" for o in rds_o])
            elif service_kind == "fsx":
                fsx_o = [inventory.get(service_kind, {}).get(s, {}) for s in services]
                kw["tooltip"] = "\n".join([f"{o.get('filesystemid')}" for o in fsx_o])
            elif service_kind == "s3ap":
                kw["label"] = get_format(services).format("S3 Access Point")
                s3ap_o = [inventory.get(service_kind, {}).get(s, {}) for s in services]
                kw["tooltip"] = "\n".join(
                    [f"{o.get('name')} => arn:aws:s3::{o.get('bucketaccountid')}:{o.get('bucket')}" for o in s3ap_o]
                )
            for service in services:
                g[service_kind][service] = service
            g[service_kind][services[0]] = service_types.get(service_kind, Node)(**kw)


def get_format(o):
    o_o = {"arn": o}
    o_o.update(get_available(o))  # available | unavailable
    o_o.update(get_encryption(o))  # encrypted | unencrypted
    o_o.update(get_logs(o))  # logs | nologs
    o_o.update(get_managed(o))  # managed | unmanaged
    o_o.update(get_public(o))  # public | external | private
    _ = get_xaccount(o)  # If arn shows in AccessAnalyser findings, connect to external account
    fm = "{}"
    if bool(o_o["unavailable"]):
        fm = "<s>{}</s>".format(fm)
    if bool(o_o["encrypted"]) and not bool(o_o["unencrypted"]):
        fm = "<u>{}</u>".format(fm)
    if bool(o_o["nologs"]):
        fm = "<i>{}</i>".format(fm)
        for i in o_o["nologs"]:
            add_finding("nologs", i, get_object(i))
    if bool(o_o["unmanaged"]):
        fm = "<B>{}</B>".format(fm)
    # if bool(o_o["inactive"]):  # vs unavailable
    #     fm = "<o>{}</o>".format(fm)
    for access in ["public", "external"]:
        if bool(o_o[access]):
            fm = "<FONT color='{}'>{}</FONT>".format(color[access], fm)
            for i in o_o[access]:
                add_finding(access, i, get_object(i))
            break
    return "<{}>".format(fm)


def show_regional_services(region_arn):
    show_regional_gateways(region_arn)
    r_ram = [
        e
        for service in ["ramresourceingress", "ram"]
        for e in inventory.get(service, [])
        if get_region_arn(e) == get_region_arn(region_arn)
    ]
    r_services = [
        e
        for service in regional_services
        for e in act.get(service, [])
        if get_region_arn(e) == get_region_arn(region_arn)
    ]
    if not bool(r_ram) and not bool(r_services):
        return
    with Cluster(label=dup_label("Services", region_arn), graph_attr={"bgcolor": "transparent"}):
        kw = {}
        for service in regional_services:
            resources = {
                e: v for e, v in act.get(service, {}).items() if get_region_arn(e) == get_region_arn(region_arn)
            }
            if not bool(resources):
                continue
            kw = {
                "color": color["service"],
                "fontcolor": color["service"],
                "label": get_format(list(resources.keys())).format(service),
                "tooltip": make_tip(resources),
            }
            for resource in resources:
                g[service][resource] = resource
            g[service][list(resources.keys())[0]] = service_types.get(service, Node)(**kw)

        if bool(r_ram):
            with Cluster(label=dup_label("Resource Sharing", region_arn), graph_attr={"bgcolor": "transparent"}):
                for service in ["ramresourceingress", "ram"]:
                    kw = {"shape": "record", "color": "transparent", "fontcolor": color["unknown"], "tooltip": ""}
                    tt = []
                    resources = [
                        e for e in inventory.get(service, []) if get_region_arn(e) == get_region_arn(region_arn)
                    ]
                    if service == "ram":
                        if not bool(resources):
                            continue
                        ea = ""
                        ext_access = []
                        ram_types = []
                        if act.get("ram"):
                            for ext in act.get("ram", {}).values():
                                for rs in ext:
                                    if get_region_arn(rs["arn"]) != get_region_arn(region_arn):
                                        continue
                                    ram_types.append(rs["type"])
                        if bool(ext_access):
                            ea = "|" + "|".join(ext_access)
                        if bool(ram_types):
                            ea = "|" + "|".join(set(ram_types))
                        d = {}
                        for item in resources:
                            it = get_type(item)
                            d[it] = d.get(it, 0) + 1
                            tt.extend(
                                ([i.get("arn") for i in inventory.get(it, {}).get(item, {})])
                                if not it in ["ami", "ebssnapshot"]
                                else item
                            )
                        kw["tooltip"] = "\n".join(sorted(list(set(tt))))
                        kw["label"] = "|{" + "|".join([f"{i}: {d[i]}" for i in d]) + ea + "}|"
                        kw["fontcolor"] = color["internet"]
                        with Cluster(label=dup_label("Out", region_arn), graph_attr={"bgcolor": color["public"]}):
                            g[service][resources[0]] = Node(**kw)
                    else:  # ram ingress
                        if not bool(resources):
                            continue
                        with Cluster(label=dup_label("In", region_arn), graph_attr={"bgcolor": "transparent"}):
                            for s in resources:
                                sr_types = [i["type"] for i in inventory["ramresourceingress"][s].values()]
                                kw = {
                                    "label": get_id(s) + "\n(" + ", ".join(set(sr_types)) + ")",
                                    "fontcolor": color["unknown"],
                                    "tooltip": "\n".join(inventory.get(service, {}).get(s, {}).keys()),
                                }
                                g["ramresourceingress"][s] = RAM(**kw)


def show_dnsnames(account_arn):
    shape = {}
    i = 0
    with Cluster(label=dup_label("DNS", account_arn), graph_attr={"bgcolor": "transparent"}):
        if g.get("rds"):
            with Cluster(label=dup_label("RDS DNS", account_arn), graph_attr={"bgcolor": "transparent"}):
                for e, v in g["rds"].items():
                    if get_account(account_arn) != get_account(e):
                        continue
                    if type(v) == str:
                        continue
                    for k, v in act["rds"].items():
                        if get_region_arn(e) != get_region_arn(k):
                            continue
                        if v.get("publiclyaccessible"):
                            kw = {"color": color["dns"], "constraint": "false"}
                            kw["color"] = kw["fontcolor"] = color["internet"]
                            fqdn = v.get("endpoint", {}).get("address") if v.get("endpoint") else False
                            if fqdn:
                                if not fqdn in g["dnsname"] or type(g["dnsname"][fqdn]) == str:
                                    label = fqdn.replace(".", ".\n")
                                    label, i = label if i % 2 else "\n" + label, i + 1
                                    g["dnsname"][fqdn] = Route53(label.replace(".", ".\n"), **shape, **kw)
                                kw["style"] = "dashed"
                                connect_nodes(g["dnsname"][fqdn], g["rds"][k], kw)

                    i += 1
        if g.get("vpce"):
            with Cluster(label=dup_label("VPC Endpoints DNS", account_arn), graph_attr={"bgcolor": "transparent"}):
                for e, v in g["vpce"].items():
                    kw = {"color": color["dns"], "constraint": "false"}
                    kw["color"] = kw["fontcolor"] = color["vpce"]
                    if get_account(account_arn) != get_account(e):
                        continue
                    vpce = inventory["vpce"][e]
                    label = fqdn = vpce["servicename"]
                    if not fqdn in g["dnsname"] or type(g["dnsname"][fqdn]) == str:
                        label, i = label if i % 2 else "\n" + label, i + 1
                        g["dnsname"][fqdn] = Route53(label.replace(".", ".\n"), **shape, **kw)
                        if type(v) == str:
                            continue
                        if not vpce.get("privatednsenabled"):
                            kw["color"] = kw["fontcolor"] = color["unknown"]
                    kw["style"] = "dashed"
                    connect_nodes(g["dnsname"][fqdn], v, kw)
                i += 1
        if bool(g.get("elbv2")):
            with Cluster(label=dup_label("Load Balancers DNS", account_arn), graph_attr={"bgcolor": "transparent"}):
                for e in g["elbv2"]:
                    if get_account(account_arn) != get_account(e):
                        continue
                    kw = {"constraint": "false"}
                    elbv2 = inventory["elbv2"][e]
                    if not elbv2.get("dnsname"):
                        continue
                    kw["fontcolor"] = kw["color"] = (
                        color["internal"] if elbv2.get("scheme") == "internal" else color["internet"]
                    )
                    fqdn = elbv2["dnsname"]
                    label = fqdn
                    label, i = label if i % 2 else "\n" + label, i + 1
                    if not fqdn in g["dnsname"] or type(g["dnsname"][fqdn]) == str:
                        g["dnsname"][fqdn] = Route53(label.replace(".", ".\n"), **shape, **kw)
                    for p in parent(e, same_account=True):
                        kw["style"] = "dashed"
                        connect_nodes(g["dnsname"][fqdn], g["targetgroup"][p], kw)
                i += 1
        if g.get("ec2"):
            with Cluster(label=dup_label("EC2 DNS", account_arn), graph_attr={"bgcolor": "transparent"}):
                for e in g["ec2"]:
                    if get_account(account_arn) != get_account(e):
                        continue
                    ec2 = inventory["ec2"][e]
                    if ec2.get("publicdnsname"):
                        kw = {"constraint": "false"}
                        kw["color"] = kw["fontcolor"] = color["internet"]
                        label = fqdn = ec2["publicdnsname"]
                        label, i = label if i % 2 else "\n" + label, i + 1
                        if not fqdn in g["dnsname"] or type(g["dnsname"][fqdn]) == str:
                            g["dnsname"][fqdn] = Route53(label.replace(".", ".\n"), **shape, **kw)
                        kw["style"] = "dashed"
                        connect_nodes(g["dnsname"][fqdn], g["ec2"][e], kw)


def add_node(o_t, o_arn, kw={}):
    if not g.get(o_t):
        g[o_t] = {}
    if o_arn in g[o_t]:  # Check if already exists
        o = g[o_t][o_arn]
    else:  # Create new node
        o = g[o_t][o_arn] = service_types.get(o_t, Node)(**kw)
    return o


def obj_to_instanceprofile(v, iparn):
    if not iparn:
        return
    iproles = [
        role
        for role in act.get("role", {}).values()
        for p in role["instanceprofilelist"]
        if role.get("instanceprofilelist") and p.get("arn") == iparn
    ]  # First, we find the roles representing Instance Profile
    kw = {
        "color": color["ec2"],
        "label": get_format(iparn).format(shorten_name(get_id(iparn))),
        "tooltip": make_tip({iparn: iproles}),
    }
    gip = add_node("instanceprofile", iparn, kw)
    kw = {"color": color["ec2"], "style": "dashed", "constraint": "false"}
    connect_nodes(gip, v, kw)


def show_account_services(account_arn):
    if get_account(account_arn) != act["id"]:
        return
    with Cluster(label=dup_label("Account Services", account_arn), graph_attr={"bgcolor": "transparent"}):
        if not SKIP_DNS:
            show_dnsnames(account_arn)
        kw = {"color": color["service"]}
        with Cluster(label=dup_label("IAM", account_arn), graph_attr={"bgcolor": "transparent"}):
            iparns = [
                v["iaminstanceprofile"].get("arn") for v in act.get("ec2", {}).values() if v.get("iaminstanceprofile")
            ]

            if bool(iparns):
                with Cluster(label=dup_label("Instance Profiles", account_arn), graph_attr={"bgcolor": "transparent"}):
                    for k, ec2 in g.get("ec2", {}).items():
                        iparn = (
                            act["ec2"][k]["iaminstanceprofile"].get("arn")
                            if act.get("ec2", {}).get(k, {}).get("iaminstanceprofile")
                            else False
                        )
                        obj_to_instanceprofile(ec2, iparn)

            if in_account(account_arn, act.get("role")):
                with Cluster(label=dup_label("Roles", account_arn), graph_attr={"bgcolor": "transparent"}):
                    arn_pattern_roles = "|".join(
                        [
                            "^aws-controltower-",
                            "^aws-quicksetup-",
                            "^awscontroltowerexecution$",
                            "^awsaftexecution$",
                            "^awsaftservice$",
                            "^organizationaccountaccessrole$",
                        ]
                    )
                    d, kw = {}, {}
                    for u in act.get("role", []):
                        if get_account(u) != get_account(account_arn):
                            continue
                        up = u.split("/")
                        if len(up) < 2:
                            continue
                        if up[1] in ["aws-reserved", "aws-service-role", "service-role"]:
                            continue
                        if re.findall(arn_pattern_roles, up[-1]):
                            continue

                        d[u] = up[-1]

                        policy = Policy(read_policy(act["role"][u].get("assumerolepolicydocument")))
                        trust_arns = []
                        for statement in policy.policy["statement"]:
                            for p, i in statement["principal"].items():
                                if type(i) != list:
                                    i = [i]
                                for j in i:
                                    if p in ["service"] or ARN(j).account_number in [awsid] + KNOWN_IDS:
                                        continue

                                    ext_principal = ARN(j).account_number if ARN(j).account_number else j
                                    trust_arns.append(ext_principal)
                                    add_orphan(u, {get_account(ext_principal): {u: policy.policy}})

                        if not (bool(trust_arns) or u in get_emr_role()):
                            continue
                        label = shorten_name(up[-1]) + "<BR/>" + ", ".join(set(trust_arns))
                        kw = {"label": get_format(u).format(label), "tooltip": make_tip(act["role"].get(u, {}))}
                        role_node = add_node("role", u, kw)
                        connect_emr_roles(u, role_node)

                    if bool(d):
                        kw["shape"] = "record"
                        kw["width"] = "4"
                        kw["label"] = "|{" + "|".join([shorten_name(d[i]) for i in d]) + "}|"
                        kw["height"] = f"{len(d) / 5}"
                        kw["tooltip"] = make_tip(d)
                        _ = add_node("role", "role", kw)

            with Cluster(label=dup_label("Users", account_arn), graph_attr={"bgcolor": "transparent"}):
                for u in act["usercreds"] if act.get("usercreds") else act.get("user", []):
                    username = get_id(u).split(":")[-1]
                    kw = {"label": get_format(u).format(username)}
                    kw["tooltip"] = "\n".join(
                        [
                            f"{u}: {v}"
                            for u, v in act.get("usercreds", {}).get(u, {}).items()
                            if not v in ["n/a", "false", "no_information", "not_supported"]
                        ]
                    )

                    pollist = act.get("user", {}).get(u, {}).get("userpolicylist")
                    if bool(pollist):
                        for pol in pollist:
                            if type(pol) != dict or not bool(pol.get("policydocument")):
                                continue
                            kw["tooltip"] += "\n" + make_tip(read_policy(pol["policydocument"]).get("statement"))
                    if username == "root":
                        kw.update({"image": get_icon("root")})
                    g["user"][u] = User(**kw)

        for service in account_services:
            services = [e for e in act.get(service, []) if get_account(e) == get_account(account_arn)]
            if not bool(services):
                continue
            org_domain = [
                v["email"] for v in inventory["organizations"].values() if v["id"] == act["id"]
            ]  # No need to run it every time, oh well...
            kw = {"color": color["service"], "label": service}
            if service == "sso":
                sso_email_domains = []
                for k, v in act[service].items():
                    kw["tooltip"] = make_tip(v)
                    kw["label"] = service + "\n" + v["identitystoreid"]
                    g[service][k] = service_types.get(service, Node)(**kw)
                    for u in v.get("users", []):
                        for e in u.get("emails", []):
                            sso_email_domains.append(e.get("value", "").split("@")[-1])
                    for d in set(sso_email_domains):
                        kw["label"] = d
                        kw["fontcolor"] = color["internet"]
                        if bool(org_domain):
                            if org_domain[0].split("@")[-1] == d:
                                kw["fontcolor"] = color["internal"]
                                connect_nodes(g[service][k], EmailWhite(**kw), kw)
                            else:
                                connect_nodes(g[service][k], Email(**kw), kw)
                        else:
                            connect_nodes(g[service][k], EmailWhite(**kw), kw)
            else:
                if service == "ds":
                    kw["label"] += "\n" + ", ".join(list({inventory[service][s]["type"] for s in services}))
                elif service in ["gax", "organizations"]:
                    kw["label"] += "\n" + ", ".join(list({s.split("/")[-2] for s in services}))
                kw["tooltip"] = make_tip({s: inventory[service][s] for s in services})
                g[service][services[0]] = service_types.get(service, Node)(**kw)

        if act.get("s3"):
            service = "s3bucket"
            if not g.get(service):
                g[service] = {}
            with Cluster(label=dup_label("S3 Buckets", account_arn), graph_attr={"bgcolor": "transparent"}):
                for k, v in act["s3"].items():
                    kw = {"tooltip": make_tip(v), "label": get_format(k).format(v["name"])}
                    g[service][k] = service_types.get(service, Node)(**kw)
                    for i, j in g["s3"].items():
                        if type(j) == str:
                            continue
                        if get_region_arn(i) != get_region_arn(k):
                            continue
                        kw = {"style": "dashed", "tooltip": f"S3 -> {k}"}
                        connect_nodes(j, g[service][k], kw)
                        break


def connect_emr_roles(u, role_node):
    for k, v in g.get("emr", {}).items():  # EMR jobs execute in context of a role
        rarns = [e["servicerole"] for e in act.get("emr", {}).get(k, {}).get("config", {}) if u == e.get("servicerole")]
        for rarn in rarns:
            if type(v) == str:
                continue
            kw = {"tooltip": f"{k} -> {rarn}"}
            connect_nodes(v, role_node, kw)


def get_emr_role():
    return [c.get("servicerole") for v in act.get("emr", {}).values() for c in v.get("config")]


def read_policy(policy_document):
    if type(policy_document) == str:
        policy_document = unquote(policy_document)
        policy_document = json.loads(policy_document)
    return policy_document


def shorten_name(u, max=34) -> str:
    label = get_id(u)
    if len(label) > max:
        label = f"{label[:max-10-2]}..{label[-10:]}"
    return label


def get_sgs(o):
    r = []
    SGLABELS = ["securitygroups", "vpcconfig", "securitygroupids", "groups", "vpcsecuritygroups", "vpcsettings"]
    SGVALUES = ["groupid", "securitygroupid", "vpcsecuritygroupid", "securitygroupids"]
    sgs = o.get("serverless", {}).get("vpcconfigs")  # Kafka
    if not bool(sgs):
        for sgl in SGLABELS:
            sgs = o.get(sgl)
            if sgs:
                break
        else:
            return " "  # r
    for sg in sgs:
        if type(sg) == str:
            r.append(sg)
        else:
            for sgv in SGVALUES:
                v = sg.get(sgv)
                if v:
                    if type(v) == str:
                        r.append(v)
                    elif type(v) == list:
                        r.extend(v)
                    break
    return [show_sg(sg) for sg in r] if bool(r) else " "


def show_sg(sg):
    f = ""
    fmt = "{}\t{}\t{}\t{}\n"
    for k, s in inventory.get("sg", {}).items():
        if not (s.get("groupid") and sg == s["groupid"] and s.get("ownerid") in k):
            continue
        f = s["description"] + "\n" if s.get("description") else ""
        for w, v in {"ippermissions": "in", "ippermissionsegress": "out"}.items():
            pft = "*"
            ent = s.get(w, [])
            if not bool(ent):
                continue
            for e in ent:
                proto = e.get("ipprotocol")
                if proto == "-1":
                    proto = "*"
                else:
                    pf = e.get("fromport")
                    pt = e.get("toport")
                    if pf:
                        if pf != pt:
                            pft = f"{pf}-{pt}"
                        else:
                            pft = pf
                r = e.get("ipranges")
                if bool(r):
                    for i in r:
                        if type(i) == str:  # Came out of Config
                            c = i
                        else:
                            c = i.get("cidrip")
                        f += fmt.format(v, proto, pft, c)
                r = e.get("useridgrouppairs")
                if bool(r):
                    for i in r:
                        c = i.get("groupid")
                        f += fmt.format(v, proto, pft, c)
                r = e.get("prefixlistids")
                if bool(r):
                    for i in r:
                        c = i.get("prefixlistid")
                        f += fmt.format(v, proto, pft, c)
    return f


def get_sg_props(sg):
    return [s for k, s in inventory.get("sg", {}).items() if sg == s.get("groupid") and s.get("ownerid") in k]


def show_ec2(vpc_arn):
    r_ec2 = [
        e
        for e, v in act.get("ec2", {}).items()
        if v.get("vpcid") == get_id(vpc_arn)
        and get_id(vpc_arn) != shared_vpc_label
        and get_region_arn(vpc_arn) == get_region_arn(e)
    ]
    if not bool(r_ec2):
        return
    with Cluster(label=dup_label("EC2", vpc_arn), graph_attr={"bgcolor": "transparent"}):
        for e in r_ec2:
            ec2_o = inventory["ec2"][e]
            label = "<BR/>".join([z for z in [get_id(e), get_name(e), ec2_o.get("privateipaddress")] if z])
            kw = {"tooltip": make_tip(ec2_o), "label": get_format(e).format(label)}
            if act.get("autoscalinginstances") and ec2_o["instanceid"] in act["autoscalinginstances"]:
                kw.update({"style": "dashed", "shape": "box"})
            os = get_os(ec2_o)
            if ec2_o.get("architecture") in ("arm64_mac", "x86_64_mac"):
                g["ec2"][e] = IOS(**kw)
            else:
                if os in ("linux/unix", "red hat enterprise linux", "linux"):
                    g["ec2"][e] = LinuxGeneral(**kw)
                elif os == "windows":
                    g["ec2"][e] = Windows(**kw)
                elif os == "marketplace":
                    g["ec2"][e] = Marketplace(**kw)
                else:
                    g["ec2"][e] = EC2(**kw)


def get_os(ec2_o):
    r = ec2_o.get("platformdetails")
    if not r:
        r = [
            v["aws:instanceinformation"]["content"][k]
            for v in act.get("ssmec2", {}).values()
            for k in v.get("aws:instanceinformation", {}).get("content", {})
            if k == ec2_o["instanceid"]
        ]
        if bool(r):
            r = r[0].get("platformtype")
        else:
            r = [v for v in inventory.get("ami", {}).values() if ec2_o["imageid"] == v["imageid"]]
            if bool(r):
                r = r[0].get("platformdetails")
            elif bool(ec2_o.get("productcodes")):
                r = "marketplace"
    return r


def show_nats(vpc_arn):
    service = "natgw"
    for gw in act.get(service, {}):
        vpc_w_gw = parent(gw)
        if vpc_arn in vpc_w_gw or vpc_arn in [w.split("/")[0] + "/" + shared_vpc_label for w in vpc_w_gw]:
            label = "<BR/>".join(
                [
                    x
                    for x in [
                        get_id(gw),
                        get_name(gw),
                        get_object(gw).get("natgatewayaddresses", [{}])[0].get("publicip"),
                    ]
                    if x
                ]
            )
            kw = {"label": get_format(gw).format(label)}
            kw["tooltip"] = make_tip(inventory.get(service, {}).get(gw, {}))
            g[service][gw] = service_types.get(service, Node)(**kw)


def show_igws(vpc_arn):
    service = "igw"
    for gw in act.get(service, {}):
        vpc_w_gw = parent(gw)
        if vpc_w_gw and vpc_arn in vpc_w_gw:
            label = "<BR/>".join(sorted(set([get_id(gw), get_name(gw)]), reverse=True))
            kw = {"label": get_format(gw).format(label)}
            kw["tooltip"] = make_tip(inventory.get(service, {}).get(gw, {}))
            g[service][gw] = service_types.get(service, Node)(**kw)
            show_igw_routes(gw)


def show_dcs(dcs):
    for dc_arn, v in dcs.items():
        kw = {"fontcolor": color["directconnect"]}
        kw["label"] = "\n".join([v.get("directconnectgatewayid"), v.get("directconnectgatewayname")])
        kw["tooltip"] = make_tip(v)
        service = "dxgw"
        g[service][dc_arn] = service_types.get(service, Node)(**kw)


def show_tgws(tgws):
    service = "tgw"
    for tgw_arn in tgws:
        kw = {"fontcolor": color[service]}
        kw["label"] = "\n".join([get_id(tgw_arn), get_name(tgw_arn)])
        kw["tooltip"] = make_tip(get_object(tgw_arn))
        g[service][tgw_arn] = service_types.get(service, Node)(**kw)
        show_tgw_routes(tgw_arn)


def show_tgw_routes(tgw_arn):
    if not g.get("tgwroutetable"):
        g["tgwroutetable"] = {}
    with Cluster(label=dup_label("", tgw_arn), graph_attr={"bgcolor": color["routetable"]}):
        kw = {"color": "transparent", "fontcolor": color["unknown"], "width": "3.5"}
        tt, recs, height, label, tgw = [], [], 1.0, "<<table border='0' cellspacing='0'>", get_id(tgw_arn)
        for k, v in inventory["tgwroutetable"].items():
            if v.get("transitgatewayid") and v["transitgatewayid"] != tgw:
                continue
            height += 1.1
            label += "{}{}{}{}{}".format(
                '<tr><td fixedsize="true" width="90" height="90"><img src="',
                get_icon("router"),
                '" /></td><td>',
                v["transitgatewayroutetableid"],
                "</td></tr>",
            )
            rec = {"tgwrt": get_id(k)}
            tt.append(v)
            for r in v.get("routes", []):
                rec["to"] = r.get("destinationcidrblock")
                for t in r.get("transitgatewayattachments", []):
                    if t.get("resourcetype") == "vpc":  # WONTDO: "peering" type
                        continue
                    rec["via"] = t.get("resourceid")
                    label += f"<tr><td port='port0'>{rec['to']}</td><td>{rec['via']}</td></tr>"
                    recs.append(rec)
        label += "</table>>"
        kw["label"] = label
        kw["tooltip"] = make_tip(tt)
        kw["height"] = str(height + len(recs) / 3)
        g["tgwroutetable"][tgw_arn] = Node(**kw)


def show_vpce(vpc_arn):
    vpce_all = {e: get_object(e) for e in g.get("vpce", {})}
    vpce_vpc = {e: v for e, v in vpce_all.items() if v.get("vpcid") == get_id(vpc_arn)}
    if not bool(vpce_vpc):
        return
    with Cluster(label=dup_label("VPC Endpoints", vpc_arn), graph_attr={"bgcolor": "transparent"}):
        for arn, vpce_o in vpce_vpc.items():
            kw = {"fontcolor": color["vpce"] if vpce_o.get("vpcendpointtype") == "gateway" else color["vpces"]}
            kw["tooltip"] = make_tip(vpce_o)
            label = "<BR/>".join(
                sorted(
                    [x for x in {get_id(arn), vpce_o["servicename"].split(".")[-1], get_name(arn)} if x],
                    reverse=True,
                )
            )
            kw["label"] = get_format(arn).format(label)
            g["vpce"][arn] = (
                Endpoint(**kw) if vpce_o.get("vpcendpointtype") != "gateway" else APIGatewayEndpoint(**kw)
            )  # wrong icon
            g["dnsname"][vpce_o["servicename"]] = vpce_o["servicename"]


def show_loadbalancers(vpc_arn):
    r_elbv2 = {
        e: v
        for e, v in act.get("elbv2", {}).items()
        if (
            (get_region_arn(vpc_arn) == get_region_arn(e) and vpc_arn.endswith(shared_vpc_label))
            or v.get("vpcid") == get_id(vpc_arn)
        )
        and not (g.get("elbv2", {}).get(e) and type(g["elbv2"][e]) != str)
    }
    r_elb = {
        e: v
        for e, v in act.get("elb", {}).items()
        if (
            (get_region_arn(vpc_arn) == get_region_arn(e) and vpc_arn.endswith(shared_vpc_label))
            or v.get("vpcid") == get_id(vpc_arn)
        )
        and not (g.get("elb", {}).get(e) and type(g["elb"][e]) != str)
    }
    if not (bool(r_elbv2) or bool(r_elb)):
        return
    with Cluster(label=dup_label("Load Balancers", vpc_arn), graph_attr={"bgcolor": "transparent"}):
        for e, v in r_elbv2.items():
            label = get_format(e).format(v["loadbalancername"])
            kw = {"graph_attr": {"bgcolor": "transparent", "tooltip": make_tip(v)}}
            label = label[1:-1] if label.startswith("<") and label.endswith(">") else label
            kw["label"] = "<{}<BR /><FONT color='invis'>{}<BR />{}</FONT>>".format(label, get_lb_ips(v), v["vpcid"])
            with Cluster(**kw) as g["elbv2"][e]:
                logging.debug(f"       |{e}")
                kw = {}
                if bool(get_managed(e)["managed"]):
                    kw.update({"shape": "box", "color": color["waf"]})
                for p in parent(e, same_account=True):
                    kw["label"] = get_format(p).format(p.split("/")[-2])
                    kw["tooltip"] = make_tip(v)  # ELB tip instead of TG
                    g["targetgroup"][p] = service_types.get("elb:" + v["type"], Node)(**kw)

        for e, v in r_elb.items():
            label = get_format(e).format(v["loadbalancername"])
            kw = {"tooltip": make_tip(v)}
            label = label[1:-1] if label.startswith("<") and label.endswith(">") else label
            kw["label"] = "<{} <FONT color='invis'><BR />{}<BR />{}</FONT>>".format(label, get_lb_ips(v), v["vpcid"])
            logging.debug(f"       |{e}")
            g["elb"][e] = service_types.get("elb:classic", Node)(**kw)


def get_lb_ips(v):  # NLB IPs
    lb_ips = [
        i.get("ipaddress")
        for a in v.get("availabilityzones")
        if "loadbalanceraddresses" in a
        for i in a.get("loadbalanceraddresses")
    ]
    if bool(lb_ips):
        return lb_ips
    lb_ips = [
        e["association"].get("publicip")
        for e in inventory.get("eni", {}).values()
        if v.get("loadbalancername") in e.get("description") and e.get("association")
    ]
    lb_ips += [
        e.get("privateipaddress")
        for e in inventory.get("eni", {}).values()
        if v.get("loadbalancername") in e.get("description")
    ]
    return lb_ips


def show_regional_gateways(region_arn):
    # tgws = [tgw_arn for tgw_arn in (g.get("tgw", {})) if region_arn == get_region_arn(tgw_arn)]
    tgws = [tgw_arn for tgw_arn in act.get("tgw", {}) if region_arn == get_region_arn(tgw_arn)]
    dcs = {dc_arn: v for dc_arn, v in act.get("dxgw", {}).items() if region_arn == get_region_arn(dc_arn)}
    r_vpcess = {e: v for e, v in act.get("vpces", {}).items() if region_arn == get_region_arn(e)}
    if not (bool(tgws) or bool(dcs) or bool(r_vpcess)):
        return
    with Cluster(label=dup_label("Gateways", region_arn), graph_attr={"bgcolor": "transparent"}):
        show_tgws(tgws)
        show_dcs(dcs)
        show_vpces(region_arn)


def get_nacl_rule(i):
    r = {
        "cidrblock": i.get("cidrblock"),
        "egress": i.get("egress"),
        "protocol": i.get("protocol"),
        "ruleaction": i.get("ruleaction"),
        "rulenumber": i.get("rulenumber"),
    }
    return r


def show_subnet_nacl(sub_id):
    DEFAULT_NACL = [
        {"cidrblock": "0.0.0.0/0", "egress": True, "protocol": "-1", "ruleaction": "allow", "rulenumber": 100},
        {"cidrblock": "0.0.0.0/0", "egress": True, "protocol": "-1", "ruleaction": "deny", "rulenumber": 32767},
        {"cidrblock": "0.0.0.0/0", "egress": False, "protocol": "-1", "ruleaction": "allow", "rulenumber": 100},
        {"cidrblock": "0.0.0.0/0", "egress": False, "protocol": "-1", "ruleaction": "deny", "rulenumber": 32767},
    ]
    for k, v in inventory.get("nacl", {}).items():
        for a in v.get("associations", []):
            if a.get("subnetid") == sub_id:
                logging.debug(f"    [n]|{k}")
                break
        else:
            continue
        if not bool([i for i in v.get("entries", []) if get_nacl_rule(i) not in DEFAULT_NACL]):
            return
        fm = "<tr><td port='port0' fixedsize='true' width='50' height='50'><img src='{}' /></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"
        kw = {"color": "white", "fontcolor": color["unknown"], "width": "4.75"}
        kw["height"] = str(1 + len(v["entries"]) / 4)
        kw["label"] = f"<<table border='0' cellspacing='0'>"
        kw["label"] += fm.format(get_icon("nacl"), get_id(k), "Proto", "Action", "Rule")

        for e in sorted(sorted(v["entries"], key=lambda a: a["rulenumber"]), key=lambda a: a["egress"]):
            logging.debug(f"    [n] {e}")
            fm = "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"
            kw["label"] += fm.format(
                "Egress" if e.get("egress") else "Ingress",
                e.get("cidrblock"),
                get_proto(e),
                "<B>Deny</B>" if e.get("ruleaction") == "deny" else "Allow",
                e.get("rulenumber"),
            )

        kw["label"] += f"</table>>"
        g["nacl"][k] = Node(**kw)


def get_proto(e):
    pr = ""
    if type(e) == str:
        proto = e
    else:
        proto = e.get("protocol")
        pr = (
            list(set([e.get("portrange", {}).get("from", ""), e.get("portrange", {}).get("to", "")]))
            if e.get("portrange")
            else {}
        )
        if bool(pr):
            pr = "-".join([str(i) for i in pr if None != i])
        else:
            pr = ""

    for p, v in PROTOCOLS.items():
        if proto == v:
            proto = p
            break
    return ":".join([i for i in [proto, pr] if i])


def show_subnets(vpc_arn):
    if not bool(g.get("subnet")):
        return
    if not bool(act.get("eni")):
        return
    vpc_id = get_id(vpc_arn)
    if (
        shared_vpc_label != vpc_id
        and not bool([v for v in inventory["eni"].values() if v.get("vpcid") == vpc_id])
        and not bool([v for v in inventory["routetable"].values() if v.get("vpcid") == vpc_id])
    ):
        for rt in inventory.get("routetable", {}).values():
            if rt.get("vpcid") != vpc_id:
                continue
            for assn in rt.get("associations", {}):
                if not assn.get("main"):
                    break
            else:
                return
            break

    with Cluster(label=dup_label("Subnets", vpc_arn)):
        for sub_arn in g["subnet"]:
            vpc_containers = parent(sub_arn)
            if not (vpc_containers and vpc_arn in vpc_containers):
                continue
            if shared_subnet_label == get_id(sub_arn):
                continue
            logging.debug(f"   [s]  {sub_arn}")
            sub_id = get_id(sub_arn)
            sub_o = inventory["subnet"][sub_arn]
            sub_cidr = sub_o.get("cidrblock", "")
            kw = {
                "label": "\n".join([sub_id, get_name(sub_arn), sub_cidr]),
                "graph_attr": {"tooltip": make_tip(sub_o)},
            }
            if not bool(g["eni"]):
                continue
            if sub_arn in inventory.get("ram", []):
                kw["graph_attr"].update({"style": "dashed", "fontcolor": color["unknown"]})
            if sub_id in public_subnets:
                kw["graph_attr"]["bgcolor"] = color["public"]
            with Cluster(**kw) as g["subnet"][sub_arn]:
                show_subnet_nacl(sub_id)
                show_subnet_routes(sub_id)
                for eni_arn in g["eni"]:
                    eni_subnets = parent(eni_arn)
                    if not bool(eni_subnets):
                        continue
                    if not sub_arn in eni_subnets:
                        continue
                    kw, shape = create_shape(eni_arn)
                    g["eni"][eni_arn] = service_types.get("nic:" + shape, Node)(**kw)


def create_shape(arn):
    kw = {"width": "1.8"}
    eni_id, eni_o = get_id(arn), inventory["eni"][arn]
    eni_ip, requester = eni_o.get("privateipaddress"), get_eni_requester(eni_o)
    label_format = get_format(arn)
    shape = eni_o["interfacetype"]
    if shape == "interface":
        if requester == "amazon-elb":
            shape = requester
        else:
            if eni_o.get("description", "").startswith("efs mount target"):
                shape = "efs"
    if requester and not requester in inventory.get("org", {}) and requester not in ["amazon-elb"]:
        requester = f"({requester})"
    label = [
        x
        for x in [
            eni_id,
            eni_ip,
            requester,
            eni_o["association"].get("publicip") if eni_o.get("association") else "",
        ]
        if x
    ]
    kw["tooltip"] = make_tip(eni_o)
    if not shape in ["interface", "vpc_endpoint", "gateway_load_balancer_endpoint", "gateway_load_balancer"]:
        kw.update({"height": "2.1", "image": get_icon(shape)})
    kw["label"] = label_format.format("<BR/>".join(label))
    return kw, shape


def make_tip(o) -> str:
    if type(o) == str:  # We got arn instead of object
        o = {str(o): get_object(o)}
    return json.dumps(clean_nones(parse_json(o)), indent=2)


def is_json(myjson):
    try:
        if not ("{" in myjson or "}" in myjson):
            return False
        json.loads(myjson)
    except ValueError as e:
        return False
    return True


def parse_json(obj: dict):
    if isinstance(obj, dict):
        return {k: parse_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [parse_json(v) for v in obj]
    elif isinstance(obj, int):
        return datetime.datetime.utcfromtimestamp(obj / 1000).isoformat() if 10**13 > obj > 10**10 else obj
    elif isinstance(obj, str):
        unqobj = unquote(obj)
        return json.loads(unqobj) if is_json(unqobj) else unqobj
    else:
        return obj


def get_eni_requester(eni_o):
    eni_requester = eni_o.get("requesterid")
    if eni_requester:
        eni_requester = eni_requester.split(":")[-1]
        if not (
            eni_requester
            # "amazon-elb", "amazon-rds"
            and not eni_requester in ["amazon-elasticache"]
            and not eni_o.get("description") in ["rdsnetworkinterface"]
            and not eni_o.get("interfacetype") in ["network_load_balancer", "vpc_endpoint", "nat_gateway"]
        ):
            eni_requester = ""
    else:
        eni_requester = ""
    return eni_requester


def connect_services(account_arn):
    kw = {"style": "dashed", "color": color["vpce"], "constraint": "false"}
    for se in ["vpce"]:
        for k, v in g[se].items():
            if type(v) == str:
                if get_account(k) == get_account(account_arn) == act["id"]:
                    logging.warning(f"Not displayed yet: {k}")
                continue
            vpce_service = inventory[se][k].get("servicename")
            if not vpce_service:
                logging.warning(f"Unknown service name for: {k}")
                continue
            vpce_svc = vpce_service.split(".")
            assert len(vpce_svc) > 3
            vpce_service = vpce_svc[3]  # sub-service endpoints may exist
            if vpce_svc[2] == "vpce":
                continue
            if vpce_service in VPCE_TO_SERVICE:
                if not VPCE_TO_SERVICE[vpce_service]:  # skipping services of no interest
                    continue
            elif not vpce_service in g:
                assert False, f"Unexpected VPC Endpoint type: {vpce_service}"
            vpce_service = VPCE_TO_SERVICE.get(vpce_service, vpce_service)  # Translate some known services

            if not bool(g.get(vpce_service)):
                g[vpce_service] = {}
                arn = f"arn:aws:{vpce_service}:{get_region(k)}:{get_account(k)}:{vpce_service}"
                g[vpce_service][arn] = add_node(vpce_service, arn, kw={"label": vpce_service})
            for service_endpoints, sv in g.get(vpce_service, {}).items():
                if type(sv) == str or (
                    vpce_service in regional_services and get_region(service_endpoints) != get_region(k)
                ):  # Shared VPC don't match svc arn
                    continue
                kw["tooltip"] = make_tip(inventory.get("vpce", {}).get(k, {}))
                n1, n2 = g[se][k], g[vpce_service][service_endpoints]
                connect_nodes(n1, n2, kw)
    for se in ["emr"]:
        emr_act_ec2 = [
            to_arn(ec.get("ec2instanceid"))
            for k in g.get(se, {})
            for ec in act.get(se, {}).get(k, {}).get("instance", {})
        ]
        for k, v in g[se].items():
            if get_account(k) == act["id"] == get_account(account_arn):
                if type(v) == str:
                    # logging.warning(f"Not displayed yet: {k}")
                    continue
            else:
                continue
            for arn in emr_act_ec2:
                if (
                    not arn
                    or get_region_arn(arn) != get_region_arn(k)
                    or not g.get("ec2", {}).get(arn)
                    or type(g["ec2"][arn]) == str
                ):
                    continue
                kw = {"tooltip": f"EMR {k.split(':')[-1]} -> {arn}", "color": color["ec2"]}
                connect_nodes(v, g["ec2"][arn], kw)

    for se in ["dxgw"]:
        for k, v in g[se].items():
            if type(v) == str:
                if get_account(k) == get_account(account_arn):
                    logging.warning(f"Not displayed yet: {k}")
                continue
            for i, o in inventory.get("tgwattachment", {}).items():
                if (
                    inventory["dxgw"][k].get("directconnectgatewayid") != o.get("resourceid")
                    or get_account(k) != get_account(account_arn)
                    or get_region_arn(k) != get_region_arn(i)
                ):
                    continue
                tgw_id = o["transitgatewayid"]
                for tgw_k, tgw_v in inventory["tgw"].items():
                    if tgw_id != tgw_v["transitgatewayid"]:
                        continue
                    if type(g["tgw"].get(tgw_k)) == str:
                        continue
                    kw["tooltip"] = f"{k.split('/')[-1].split(':')[-1]} <-> {tgw_k.split('/')[-1].split(':')[-1]}"
                    kw["forward"] = True
                    kw["reverse"] = True
                    connect_nodes(v, g["tgw"][tgw_k], kw)
                    del kw["forward"]
                    del kw["reverse"]

    for se in ["vpces"]:
        for k, v in g[se].items():
            if type(v) == str:
                if get_account(k) == get_account(account_arn):
                    logging.warning(f"Not displayed yet: {k}")
                continue
            vpces_elbs = act[se][k].get("networkloadbalancerarns", []) + act[se][k].get("gatewayloadbalancerarns", [])
            vpces_tgs = {
                i.get("targetgrouparn"): i
                for arn in vpces_elbs
                for i in act.get("elbv2", {}).get(arn, {}).get("targetgroups", [])
            }
            for i, o in vpces_tgs.items():  #
                vpce_priv_dns = inventory[se][k].get("networkloadbalancerarns")
                kw["label"] = vpce_priv_dns if vpce_priv_dns else ""  # None  # WTH?
                if (
                    any([x in o["loadbalancerarns"] for x in vpces_elbs])
                    and get_account(k) == get_account(account_arn)
                    and get_region_arn(k) == get_region_arn(i)
                    and type(g["targetgroup"][i]) != str
                ):
                    kw = {"style": "bold", "color": color["internet"]}
                    kw["tooltip"] = f"{k.split('/')[-1].split(':')[-1]} <-> {i.split('/')[-2].split(':')[-1]}"
                    kw["forward"] = True
                    kw["reverse"] = True
                    connect_nodes(v, g["targetgroup"][i], kw)
                    del kw["forward"]
                    del kw["reverse"]

            # Attach VCPE to VPCES
            vpces_vpce = [
                e
                for e in g.get("vpce", {})
                if inventory.get("vpce", {}).get(e, {}).get("servicename")
                == inventory.get("vpces", {}).get(k, {}).get("servicename")
            ]
            if not bool(vpces_vpce):
                continue
            for n in vpces_vpce:
                if not g.get("vpce", {}).get(n) or type(g["vpce"][n]) == str:
                    if get_account(account_arn) == act["id"]:
                        logging.warning(f"*** {k} connection missing: {n}")
                    continue
                kw = {"color": color["external"]}
                kw["tooltip"] = f"{k.split('/')[-1].split(':')[-1]} <-> {n.split('/')[-1].split(':')[-1]}"
                connect_nodes(g["vpce"][n], g["vpces"][k], kw)


def connect_nodes(in1, in2, kw={}):  # if n2 is str, use kw['label'] property
    # https://graphviz.org/docs/attr-types/arrowType/
    # [-] labeltarget – Browser window to open labelURL links in
    # [-] label: n1.label > n2.label
    # [-] labeltooltip = sg/ policies
    # [.] (edge)tooltip = sg/ policies
    # [+] headtooltip = make_tips(n1)
    # [+] tailtooltip = make_tips(n2)
    # [+] edgetooltip = n1.label > n2.label

    if type(in1) != list:
        in1 = [in1]
    if type(in2) != list:
        in2 = [in2]
    for n1 in in1:
        if type(n1) == str:
            logging.warning(f"[*    ] Expecting an object: {n1}")
        for n2 in in2:
            nkw = kw.copy()
            if type(n2) == str:
                for anyk, anyo in g.get(get_type(n2), {}).items():
                    # Have to make exception for "*"
                    if (get_type(anyk) in regional_services and get_region_arn(anyk) == get_region_arn(n2)) and type(
                        anyo
                    ) != str:
                        n2 = anyo
                        break
                else:
                    logging.warning(f"[    *] Expecting an object: {n2}")
            if connected_nodes(n1, n2):
                continue
            if type(n2) == str and get_type(n2) in regional_services:
                for n, w in g[get_type(n2)].items():
                    if type(w) == str or get_region_arn(n) != get_region_arn(n2):
                        continue
                    n2 = w
                    break
            if type(n1) == str and get_type(n1) in regional_services:
                for n, w in g[get_type(n1)].items():
                    if type(w) == str or get_region_arn(n) != get_region_arn(n1):
                        continue
                    n1 = w
                    break
            nkw["color"] = (nkw["color"] if "color" in nkw else color["internal"])[:7] + "40"
            nkw["fontcolor"] = nkw.get("fontcolor", nkw["color"] if "color" in nkw else color["internal"])[:7] + "40"
            label = ""
            if not "label" in kw:
                l1, l2 = n1.label, n2.label
                l1 = l1[1 if l1[:1] == "<" else 0 : -1 if l1[-1:] == ">" else None]
                l2 = l2[1 if l2[:1] == "<" else 0 : -1 if l2[-1:] == ">" else None]
                l1, l2 = undo_html(l1), undo_html(l2)
                a1 = "<" if nkw.get("reverse") else "-"
                a2 = ">" if nkw.get("forward", True) else "-"
                label = "{} {}-{} {}".format(l1, a1, a2, l2)
            nkw["tooltip"] = nkw.get("tooltip", label)
            nkw["headtooltip"] = nkw.get("headtooltip", n1._attrs.get("tooltip", undo_html(n1.label)))
            nkw["tailtooltip"] = nkw.get("tailtooltip", n2._attrs.get("tooltip", undo_html(n2.label)))
            if nkw.get("forward", True):
                nkw["forward"] = True
                nkw["arrowhead"] = nkw.get("arrowhead", "open")
            if nkw.get("reverse"):
                nkw["arrowtail"] = nkw.get("arrowtail", "open")
            nkw["class"] = f"node{n1._id} node{n2._id}"
            n1 - Edge(**nkw) - n2


def undo_html(text):
    text = re.sub("<[^>]*>", " ", text) if not "<table" in text else ""
    if text and text[-1] == ">":
        text = text[:-1]
    return text


def get_eni_tips(eni_o, kw, eni_consumer, k=None):
    kw["color"] = color["internet" if bool(eni_o.get("association")) else eni_consumer]
    if k:
        kw["tooltip"] = ",".join(get_sgs(inventory[eni_consumer][k]))
        return
    kw["tooltip"] = ",".join(get_sgs(eni_o))


def connect_enis(eni_arn):
    eni_o = inventory.get("eni", {}).get(eni_arn)
    if not eni_o:
        logging.warning(f"[      ] ENI not found: {eni_arn}")
        return
    kw = {"style": "dashed", "forward": False}

    for eni_consumer in ["vpce", "ec2"] + eni_services:
        if eni_consumer == "ec2" and not eni_o["interfacetype"] in ["interface"]:
            continue
        if eni_consumer == "vpce" and not eni_o["interfacetype"] in ["vpc_endpoint", "gateway_load_balancer_endpoint"]:
            continue

        for k, v in g[eni_consumer].items():
            if eni_consumer == "vpce" and inventory[eni_consumer][k].get("vpcendpointtype") == "gateway":
                continue  # Doesn't present interfaces
            if type(v) == str:
                if eni_consumer not in eni_services and get_region_arn(eni_arn) == get_region_arn(v):
                    logging.warning(f"Not displayed yet: {k} (ENI={eni_o['networkinterfaceid']})")
                    continue  # EC2 and VPCE ENIs should be accounted for
                # elif eni_consumer in eni_services:
                #     continue
                if eni_consumer in eni_services:
                    vs = [
                        w
                        for c, w in g[eni_consumer].items()
                        if type(w) != str and get_region_arn(c) == get_region_arn(k)
                    ]
                    if bool(vs):
                        v = vs[0]
            connected_nics = parents[k] if bool(parents.get(k)) else parent(k)
            if bool(connected_nics):
                if not eni_arn in connected_nics:
                    continue
                get_eni_tips(eni_o, kw, eni_consumer)
                if eni_o["interfacetype"] == "gateway_load_balancer_endpoint":
                    kw["color"] = color["vpce"]
                elif get_eni_requester(eni_o):
                    kw["color"] = color["unknown"]
                connect_nodes(v, g["eni"][eni_arn], kw)
                return
            elif eni_consumer == "sagemaker":
                if not "({})".format(k.split("/")[-1]) in eni_o["description"]:
                    continue
                get_eni_tips(eni_o, kw, eni_consumer)
                connect_nodes(g["eni"][eni_arn], v, kw)
                return
            elif not eni_consumer in ["rds", "elasticache", "efs", "fsx"]:
                if inventory[eni_consumer][k].get("state") in ["deleting", "deleted"]:
                    continue
                logging.info(f"Unknown connections for {k}")
            elif eni_consumer == "elasticache":
                eni_desc = eni_o.get("description")
                if not eni_desc or eni_desc.split()[0] != eni_consumer:
                    continue
                if get_region_arn(eni_arn) != get_region_arn(k):
                    continue
                get_eni_tips(eni_o, kw, eni_consumer)
                connect_nodes(v, g["eni"][eni_arn], kw)
                return
    for eni_consumer in ["elbv2", "elb"]:
        for k, v in g[eni_consumer].items():
            if not (
                eni_o["interfacetype"] in ["network_load_balancer", "interface", "gateway_load_balancer"]
                and get_id(k) in get_id(eni_o["description"])
            ):
                continue
            get_eni_tips(eni_o, kw, eni_consumer, k)
            if eni_consumer == "elbv2":
                for tg in parent(k):
                    connect_nodes(g["targetgroup"][tg], g["eni"][eni_arn], kw)
            else:
                connect_nodes(v, g["eni"][eni_arn], kw)
            return
    eni_consumer = "natgw"
    for k, v in g[eni_consumer].items():
        if not (
            eni_o["interfacetype"] == "nat_gateway"
            and bool(eni_o.get("association"))
            and eni_o["association"].get("associationid")
            == inventory.get(eni_consumer, {}).get(k, {}).get("natgatewayaddresses", [{}])[0].get("associationid")
        ):
            continue
        get_eni_tips(eni_o, kw, eni_consumer)  # FIXME: does nothing
        kw["color"] = color["external"]  # Override
        connect_nodes(g["eni"][eni_arn], v, kw)
        return
    eni_consumer = "tgw"
    for k, v in g[eni_consumer].items():
        if eni_o["interfacetype"] != "transit_gateway" or get_region_arn(eni_arn) != get_region_arn(k):
            continue
        get_eni_tips(eni_o, kw, eni_consumer, k)  # No data
        connect_nodes(v, g["eni"][eni_arn], kw)
        return
    for eni_consumer in ["eks"]:
        for k, v in g.get(eni_consumer, {}).items():
            if not ":cluster/" in k:
                continue
            if not eni_o["description"] == "amazon eks " + k.split(":cluster/")[-1]:
                continue
            get_eni_tips(eni_o, kw, eni_consumer)
            connect_nodes(g["eni"][eni_arn], v, kw)
            return
    for eni_consumer in ["lambda"]:
        for k, v in g.get(eni_consumer, {}).items():
            if not get_region_arn(k) == get_region_arn(eni_arn):
                continue
            get_eni_tips(eni_o, kw, eni_consumer)
            connect_nodes(g["eni"][eni_arn], v, kw)
            if eni_o["requestermanaged"]:
                account_id = get_account(eni_o["requesterid"])
                if account_id == act["id"]:
                    continue
                add_orphan(eni_arn, {account_id: {k: inventory[eni_consumer][k]}})
            return
    else:
        if eni_o["description"] != "rdsnetworkinterface":
            logging.warning(f"Orphaned eni {eni_arn} description: {eni_o['description']}")
        elif eni_o["description"] == "rdsnetworkinterface":
            eni_consumer = "rds"
            for k, vv in act.get(eni_consumer, {}).items():
                if vv.get("dbsubnetgroup", {}).get("vpcid") != eni_o.get("vpcid"):
                    continue
                if type(g.get(eni_consumer, {}).get(k, "")) == str:
                    continue
                get_eni_tips(eni_o, kw, eni_consumer)
                connect_nodes(g[eni_consumer][k], g["eni"][eni_arn], kw)
                return
        assert False, f"Unexpected ENI type: {eni_o}"
        add_orphan(eni_arn, g["eni"][eni_arn])  # FIXME


def show_elbtargets():
    tgs = [i for v in act.get("elbv2", {}).values() for i in v.get("targetgroups", []) if bool(i.get("targethealth"))]
    if not bool(tgs):
        return
    for tg in tgs:
        tgarn = tg.get("targetgrouparn")
        target = parent(tgarn)
        if not bool(target):  # No targets defined
            continue
        # Check if TargetGroup object is displayed
        if not (bool(g["targetgroup"]) and g["targetgroup"].get(tgarn) and type(g["targetgroup"][tgarn]) != str):
            logging.debug(f"Target Group object {tgarn} not displayed yet")
            continue

        for to in target:
            kw = {"color": color["internal"]}
            to_t = get_type(to)
            to_arn = to
            if to_t == "ec2":  # should be able to locate instance by short notation
                ec2_arns = [i for i, v in act.get(to_t, {}).items() if v["instanceid"] == to]
                if not bool(ec2_arns):
                    continue
                public = get_public(ec2_arns)
                if bool(public.get("public")):
                    kw["color"] = color["internet"]
                if bool(public.get("external")):
                    kw["color"] = color["external"]
                to_arn = ec2_arns[0]
                kw["tooltip"] = ",".join(get_sgs(inventory[to_t][to_arn]))
                n1, n2 = g["targetgroup"][tgarn], g[to_t][to_arn]
                connect_nodes(n1, n2, kw)
            elif to_t == "ip":  # Output handled by connect_ext()
                if not to_t in g:
                    g[to_t] = {}
                if not g[to_t].get(to_arn):
                    g[to_t][to_arn] = []
                if type(g[to_t][to_arn]) == list:
                    g[to_t][to_arn].append(tgarn)
                continue
            elif to_t == "elbv2":  # WONTDO: what if target ELB outside the account? Add inventory to get_basics
                if g[to_t].get(to_arn) == str:
                    logging.warning(f"No Target Group shown yet for {to_arn}")
                    continue
                fwd = [
                    g["targetgroup"].get(t["targetgrouparn"])
                    for t in get_object(to_arn).get("targetgroups", [])
                    if g["targetgroup"].get(t["targetgrouparn"])
                ]
                kw.update(
                    {
                        "style": "solid",
                        "rank": "same",
                        "color": color["internet" if bool(get_public(to_arn).get("public")) else "unknown"],
                    }
                )
                for n2 in fwd:
                    kw["tooltip"] = ",".join(get_sgs(inventory[to_t][to_arn]))
                    n1 = g["targetgroup"][tgarn]
                    connect_nodes(n1, n2, kw)
                continue
            if g.get(to_t, {}).get(to_arn, "") in [str, list]:
                logging.debug(f"Target {to_arn} not displayed yet")


def get_basics() -> list:
    objs = []
    for t in ["elb", "ec2", "vpce"]:
        for e in act.get(t, []):
            logging.debug(f" .      {e}")
            obj = {t: [e]}
            enis = parent(obj[t])
            if not bool(enis):
                vpc_id = inventory[t][obj[t][0]].get("vpcid")
                if not vpc_id:
                    logging.debug(f"{inventory['ec2'][e]['state']['name']} ec2 instance {e} not associated with vpcs")
                    continue
                vpc_inv = [v for v in vpcid_to_vpc(vpc_id)]
                if not bool(vpc_inv):  # Incomplete decom
                    ap = e.split(":")
                    ap[0] = ap[1] = ""
                    ap[-1] = "vpc/" + vpc_id
                    vpc_arn = ":".join(ap)
                    mock_vpc(vpc_id, vpc_arn)
                    vpc_inv = [vpc_arn]
                if bool(vpc_inv) and type(vpc_inv) == list:
                    obj["vpc"] = [vpc_inv[0]]
                obj["region"] = parent(obj["vpc"])
                obj["account"] = parent(obj["region"])
                subnets = inventory[t][obj[t][0]]["subnetids"] if inventory[t][obj[t][0]].get("subnetids") else []
                if bool(subnets):
                    for s in subnets:
                        obj["subnet"] = subnetid_to_subnet(s)
                        objs.append(obj)
                else:  # VPCE gateway
                    objs.append(obj)
                continue
            for eni in enis:
                logging.debug(f"  .     {eni}")
                obj["eni"] = [eni]
                if not bool(obj["eni"]):  # vpc endpoint of type "gateway" does not have enis
                    continue
                eni_parent = parent(obj["eni"])
                for ep in eni_parent:
                    logging.debug(f"   .    {ep}")
                    obj["subnet"] = [ep]
                    obj["vpc"] = parent(obj["subnet"])
                    if not bool(obj["vpc"]):
                        ap = ep.split(":")
                        vpc_id = inventory["subnet"][ep]["vpcid"]
                        vpc_arn = f"arn:aws:ec2:{ap[3]}:{ap[4]}:vpc/{vpc_id}"
                        mock_vpc(vpc_id, vpc_arn)
                        obj["vpc"] = [vpc_arn]
                    if get_id(obj["vpc"][0]) == shared_vpc_label:
                        vpc_id = inventory["eni"].get(obj["eni"][0], {}).get("vpcid")

                        vpc_inv = [
                            v for v in vpcid_to_vpc(vpc_id) if get_account(v) != get_account(obj["eni"][0])
                        ]  # Shared VPCs
                        if bool(vpc_inv) and type(vpc_inv) == list:
                            obj["vpc"] = [vpc_inv[0]]
                            if not in_account(act["id"], vpc_inv):
                                ap = ep.split(":")
                                vpc_arn = f"arn:aws:ec2:{ap[3]}:{ap[4]}:vpc/{shared_vpc_label}"
                                obj["vpc"] = [vpc_arn]
                        else:
                            ap = eni.split(":")
                            vpc_arn = f"arn:aws:ec2:{ap[3]}:{ap[4]}:vpc/{inventory['eni'][eni]['vpcid']}"
                            obj["vpc"] = [vpc_arn]
                            mock_vpc(vpc_id, vpc_arn)
                            logging.warning(f"[*****] Orphaned VPC: {vpc_id}")  # WONTDO: suppress duplicate warnings
                    obj["region"] = parent(obj["vpc"])
                    obj["account"] = parent(obj["region"])
                    objs.append(obj.copy())
    for t in ["eni"]:
        for e in act.get(t, []):
            if act[t][e].get("status") != "in-use":
                continue
            obj = {get_type(e): [e]}
            eni_parent = parent(obj[t])
            for ep in eni_parent:
                if "ownerid" not in inventory["subnet"][ep] or inventory["subnet"][ep]["ownerid"] != get_account(ep):
                    continue
                if get_id(ep) == shared_subnet_label:
                    vpc_id = inventory[t][obj[t][0]]["vpcid"]
                    vpc_inv = [v for v in vpcid_to_vpc(vpc_id) if get_account(v) == get_account(obj[t][0])]
                else:
                    obj["subnet"] = [ep]
                obj["vpc"] = parent(obj["subnet"])
                if not bool(obj["vpc"]):
                    ap = ep.split(":")
                    vpc_id = inventory["subnet"][ep]["vpcid"]
                    vpc_arn = f"arn:aws:ec2:{ap[3]}:{ap[4]}:vpc/{vpc_id}"
                    mock_vpc(vpc_id, vpc_arn)
                    obj["vpc"] = [vpc_arn]

                obj["region"] = parent(obj["vpc"])
                obj["account"] = parent(obj["region"])
                objs.append(obj.copy())
    for t in ["igw"]:
        for e in act.get(t, []):
            obj = {t: [e]}
            obj["vpc"] = parent(obj[t])
            if not (bool(obj["vpc"]) and obj["vpc"][0]):  # [False] when igw detached
                logging.warning(f"VPC not found for {e}")
                continue
            obj["region"] = parent(obj["vpc"])
            obj["account"] = parent(obj["region"])
            objs.append(obj)
    for t in ["vpc"]:
        for e in act.get(t, []):
            obj = {t: [e]}
            obj["region"] = parent(obj[t])
            obj["account"] = parent(obj["region"])
            objs.append(obj)
    for t in ["elbv2"]:
        for e in act.get(t, []):
            obj = {t: [e]}
            for region in [
                get_region_arn(f)
                for tg in get_object(obj[t][0]).get("targetgroups", [])
                for f in tg.get("targethealth")
                if get_type(f) in [t] and get_account(f) != act["id"]
            ]:
                vpc_id = inventory[t][obj[t][0]].get("vpcid")
                if not vpc_id:
                    logging.debug(f"{e} not associated with a vpc")
                    continue
                for v in vpcid_to_vpc(vpc_id):
                    obj["vpc"] = [v]
                    obj["region"] = [region]
                    obj["account"] = parent(obj["region"])
                    objs.append(obj)
    for t in ["routetable"]:
        if not t in act:
            act[t] = {}
        # Scan inventory for incoming routes pointed at our gws
        igw_ids = [get_id(i) for i in act.get("igw", {})]
        natgw_ids = [get_id(i) for i in act.get("natgw", {})]
        vpce_ids = [get_id(i) for i in act.get("vpce", {})]
        vpcx_ids = {get_id(i) for i in act.get("vpcx", {})}
        tgw_ids = [get_id(i) for i in act.get("tgw", {})]
        eni_ids = [get_id(i) for i in act.get("eni", {})]
        subnet_ids = sorted(
            set(
                [v.get("subnetid") for v in act.get("ec2", {}).values()]
                + [z.get("subnetid") for v in act.get("elbv2", {}).values() for z in v.get("availabilityzones", {})]
                + [
                    z["subnetid"]
                    for v in act.get(t, {}).values()
                    for z in v.get("associations", {})
                    if bool(z.get("subnetid"))
                ]
            )
        )
        vpc_ids = sorted(
            set(
                [v.get("vpcid") for v in act.get(t, {}).values()]
                + [v.get("vpcid") for v in act.get("ec2", {}).values()]
                + [v.get("vpcid") for v in act.get("elbv2", {}).values()]
            )
        )
        # Let's go through global inventory to see if we have routes in other accounts using gateways in our account
        for k, e in inventory.get(t, {}).items():
            if e.get("ownerid") == act["id"]:
                continue

            if e.get("vpcid") in vpc_ids:
                if get_account(k) == e.get("ownerid"):
                    for a in e.get("associations", {}):
                        if a.get("main") or a.get("subnetid") in subnet_ids:
                            act[t][k] = e  # multi-shared subnets mess up route tables
                            break

            if not k in act.get(t):
                # Is this going to work for main routes?
                for r in e.get("routes", []):
                    if r.get("gatewayid"):
                        if r["gatewayid"] == "local":
                            pass
                        elif r["gatewayid"] in igw_ids + vpce_ids:
                            break
                    elif r.get("networkinterfaceid"):
                        if r["networkinterfaceid"] in eni_ids:
                            break
                    elif r.get("natgatewayid"):
                        if r["natgatewayid"] in natgw_ids:
                            break
                    elif r.get("vpcpeeringconnectionid"):
                        if r["vpcpeeringconnectionid"] in vpcx_ids:
                            break
                    elif r.get("transitgatewayid"):
                        if r["transitgatewayid"] in tgw_ids:
                            break
                    # if r.get("state") == "blackhole":
                    #     continue
                else:  # Other account does not have routes pointing to this account for gateways
                    continue
                logging.debug(f"*       {k}")
                act[t][k] = e  # Add this extraneous route table to the diag for display

        for rk, e in act.get(t, {}).items():
            for r in e.get("routes", []):
                if r.get("gatewayid") == "local":
                    continue
                if r.get("state") == "blackhole":
                    continue
                ot, gw_arn = get_route_gw(r)
                if not gw_arn:
                    continue
                obj = {ot: [gw_arn], "region": [get_region_arn(gw_arn)], "account": [get_account_arn(gw_arn)]}
                gwo = get_object(gw_arn)
                if not ot in act:
                    act[ot] = {}
                if not gw_arn in act[ot]:
                    act[ot][gw_arn] = gwo
                if ot == "vpce":
                    for k, v in inventory["vpces"].items():
                        if v.get("servicename") != gwo["servicename"]:
                            continue
                        if not act.get("vpces"):
                            act["vpces"] = {}
                        act["vpces"][k] = v
                    enis = parent(gw_arn)
                    if bool(enis):
                        for eni in enis:
                            logging.debug(f"  .     {eni}")
                            obj["eni"] = [eni]
                            if not bool(obj["eni"]):  # vpc endpoint of type "gateway" does not have enis
                                continue
                            eni_parent = parent(obj["eni"])
                            for ep in eni_parent:
                                logging.debug(f"   .    {ep}")
                                obj["subnet"] = [ep]
                elif ot == "vpcx":
                    ap = gw_arn.split(":")
                    if not act.get("vpcx"):
                        act["vpcx"] = {}
                    act["vpcx"][gw_arn] = gwo
                    for vpcxep in ["requestervpcinfo", "acceptervpcinfo"]:
                        if gwo.get(vpcxep, {}).get("ownerid") and gwo[vpcxep]["ownerid"] != act["id"]:
                            obj["vpc"] = [f"arn:aws:ec2:{ap[3]}:{ap[4]}:vpc/{shared_vpc_label}"]
                        else:
                            obj["vpc"] = [f"arn:aws:ec2:{ap[3]}:{ap[4]}:vpc/{gwo[vpcxep]['vpcid']}"]
                        objs.append(obj)
                    continue
                elif ot in ["natgw", "igw"]:  # TEST IGW
                    if e.get("ownerid") != act["id"]:
                        if not ot in act:
                            act[ot] = {}
                        act[ot][gw_arn] = gwo
                if gwo.get("vpcid"):
                    ap = gw_arn.split(":")
                    if gwo.get("ownerid") and gwo["ownerid"] != act["id"]:
                        obj["vpc"] = [f"arn:aws:ec2:{ap[3]}:{ap[4]}:vpc/{shared_vpc_label}"]
                    else:
                        obj["vpc"] = [f"arn:aws:ec2:{ap[3]}:{ap[4]}:vpc/{gwo['vpcid']}"]
                objs.append(obj)
            for r in e.get("associations", []):
                if r.get("main"):  # We are capturing VPC already through "routes"
                    continue
                if r.get("associationstate", {}).get("state") != "associated":
                    logging.warning(f"Route not associated: {r}")
                    continue
                for k, s in inventory.get("subnet", {}).items():
                    if s.get("subnetid") != r.get("subnetid"):
                        continue
                    obj = {
                        "routetable": [rk],
                        "subnet": [k],
                        "region": [get_region_arn(k)],
                        "account": [get_account_arn(k)],
                    }
                    objs.append(obj)
    for t in ["vpces"]:
        for e in act.get(t, []):
            obj = {t: [e]}
            obj["targetgroup"] = parent(obj[t])
            for k in obj["targetgroup"]:
                o = [
                    j
                    for v in inventory.get("elbv2", {}).values()
                    for i in v.get("targetgroups", [])
                    for j in i.get("loadbalancerarns", [])
                    if i.get("targetgrouparn") == k
                ]
                for elb in o:
                    obj["elbv2"] = [elb]
                    vpc_id = get_object(elb).get("vpcid")
                    vpc_arns = [v for v in vpcid_to_vpc(vpc_id)]
                    if len(vpc_arns) == 1 and get_account(vpc_arns[0]) != act["id"]:
                        ap = vpc_arns[0].split(":")
                        obj["vpc"] = [f"arn:aws:ec2:{ap[3]}:{ap[4]}:vpc/{shared_vpc_label}"]
                        if not act.get("elbv2"):
                            act["elbv2"] = {}
                        act["elbv2"][elb] = get_object(elb)
                        obj["region"] = [f"::region:{ap[3]}:{ap[4]}:{ap[3]}"]
                        obj["account"] = [f"::account::{ap[4]}::"]
                    objs.append(obj)
    for svc_regional in regional_services:
        if svc_regional in eni_services:
            continue
        for e in act.get(svc_regional, []):
            obj = {svc_regional: [e]}
            obj["region"] = parent(obj[svc_regional])
            obj["account"] = parent(obj["region"])
            objs.append(obj)

    for t in ["ramresourceingress"]:
        for e in act.get(t, []):
            obj = {t: [e]}
            for k in act[t][e]:
                obj["region"] = [get_region_arn(k)]
                obj["account"] = parent(obj["region"])
                objs.append(obj)
                if get_type(k) != "ami":
                    continue
                # Add correspondinng egress for another account for AMI
                if not bool(inventory.get("ram")):
                    inventory["ram"] = {}
                ami_arn = "::ram:{}:{}:resource-share/ami".format(get_region(k), get_account(k))
                if inventory["ram"].get(ami_arn):
                    continue
                inventory["ram"][ami_arn] = []

            for k, v in act[t][e].items():
                if v["type"] == "ec2:subnet":
                    continue
                obj = {"ramresourceegress": [v["resourcesharearn"]]}
                obj["region"] = [get_region_arn(k)]
                obj["account"] = parent(obj["region"])
                objs.append(obj)

        for e in inventory.get(t, []):
            if get_id(e) != act["id"]:
                continue
            for k, v in inventory[t][e].items():
                if v["type"] == "ec2:subnet":
                    continue
                obj = {t: [v["resourcesharearn"]]}
                obj["region"] = [get_region_arn(e)]
                obj["account"] = parent(obj["region"])
                objs.append(obj)

    return [i for n, i in enumerate(objs) if i not in objs[n + 1 :]]


def mock_vpc(vpc_id, vpc_arn):
    if not inventory.get("vpc"):
        inventory["vpc"] = {}
    if not act.get("vpc"):
        act["vpc"] = {}
    if not inventory["vpc"].get(vpc_arn):
        if by_id("vpc", vpc_id):
            act["vpc"][vpc_arn] = inventory["vpc"][vpc_arn] = inventory["vpc"][by_id("vpc", vpc_id)]
        else:
            act["vpc"][vpc_arn] = inventory["vpc"][vpc_arn] = fake_vpc(vpc_id)


def fake_vpc(vpc_id):
    return {
        "ownerid": act["id"],
        "cidrblock": "?",
        "state": "fake",
        "vpcid": vpc_id,
    }


def get_route_gw(r: dict) -> tuple:
    r_t, r_k, gw, lgw = None, None, None, None
    for r_type, r_keys in inv_t.items():
        gw = r.get(r_keys["r"])
        if gw:
            lgw = gw
            for k, i in inventory.get(r_type, {}).items():
                if i.get(r_keys["i"]) == gw:
                    # if get_account(k) == i.get("ownerid") or str != type(g.get(r_type, {}).get(k, "")):
                    if str != type(g.get(r_type, {}).get(k, "")):
                        # If same account match or graph element exists, return first result found
                        return r_type, k
                    r_t, r_k = r_type, k
    else:
        if not r_t and not r_k:
            logging.warning(f"Gateway not found in global inventory: {lgw}")
    return r_t, r_k


def vpcid_to_vpc(vpc_id) -> list:
    r = [k for k, v in inventory["vpc"].items() if v["vpcid"] == vpc_id]
    if len(r) > 1:
        r = [k for k, v in inventory["vpc"].items() if v["vpcid"] == vpc_id and k.split(":")[4] == v.get("ownerid")]
    return r


def subnetid_to_subnet(subnet_id) -> list:
    r = [k for k, v in inventory["subnet"].items() if v["subnetid"] == subnet_id]
    if len(r) > 1:
        r = [
            k
            for k, v in inventory["subnet"].items()
            if v["subnetid"] == subnet_id and k.split(":")[4] == v.get("ownerid")
        ]
    return r


def show_gateways(vpc_arn):
    g_found = False
    for k, v in inventory.get("natgw", {}).items():
        if v["state"] in ["deleted", "deleting"]:
            continue
        if get_id(vpc_arn) == v["vpcid"]:
            g_found = True
            break
        parent_vpcs = [parent(i) for i, j in inventory["subnet"].items() if j["subnetid"] == v["subnetid"]]
        if not bool(parent_vpcs):
            if get_region_arn(vpc_arn) == get_region_arn(k):
                logging.warning(f"[*****] Unable to determine VPC for {v['subnetid']}. Check if {k} exists")
            continue
        if vpc_arn in parent_vpcs[0]:
            if not bool(act.get("natgw")):
                act["natgw"] = {}
            act["natgw"].update({k: v for i, j in inventory["subnet"].items() if j["subnetid"] == v["subnetid"]})
            g_found = True
            break
    if not g_found:
        for v in act.get("vpce", {}).values():
            if get_id(vpc_arn) == v["vpcid"]:
                g_found = True
                break
    if not g_found:
        for v in inventory.get("igw", {}).values():
            a = [z["vpcid"] for z in v.get("attachments")]
            if get_id(vpc_arn) in a:
                g_found = True
                break
    r_vpcendpoint = [e for e in g.get("vpce", {}) if get_object(e).get("vpcid") == get_id(vpc_arn)]
    if g_found or bool(r_vpcendpoint):
        logging.info(f"    |   Gateways")
        with Cluster(label=dup_label("Gateways", vpc_arn), graph_attr={"bgcolor": "transparent"}):
            show_igws(vpc_arn)
            show_nats(vpc_arn)
            show_vpce(vpc_arn)


def get_g_handles(objs, g):
    for i in objs:
        for k, v in i.items():
            if not g.get(k):
                g[k] = {}
            if not bool(v):
                continue
            for o in v:
                g[k][o] = o
    if not g.get("account"):
        g["account"] = {}


def connect_lb_routes():
    for k, v in act.get("elb", {}).items():
        gws = set([gw for s in v.get("subnets") for gw in get_default_route_for_subnet(s)])
        for gw in gws:
            if not g["routetableassociationid"].get(gw):
                if act["id"] != get_account(k):
                    continue
                logging.warning(f"[*****] Missing route table association {gw} for {k}")
                continue
            kw = {"style": "bold", "color": color["unknown"]}
            kw["tooltip"] = f"{v.get('loadbalancername')} -> {gw.split('/')[-1].split(':')[-1]}"
            connect_nodes(g.get("elb", {}).get(k), g["routetableassociationid"][gw], kw)

    for v in act.get("elbv2", {}).values():
        gws = set([gw for az in v.get("availabilityzones") for gw in get_default_route_for_subnet(az.get("subnetid"))])
        tgs = [
            g["targetgroup"][tg["targetgrouparn"]]
            for tg in v.get("targetgroups", [])
            if str != type(g.get("targetgroup", {}).get(tg.get("targetgrouparn", "")))
        ]
        if not bool(tgs):
            continue
        for gw in gws:
            if not g["routetableassociationid"].get(gw):
                if act["id"] != get_account(v.get("loadbalancerarn")):
                    continue
                logging.warning(f"[*****] Missing route table association {gw} for {v['loadbalancerarn']}")
                continue
            kw = {"style": "bold", "color": color["unknown"]}
            kw["tooltip"] = f"{v.get('loadbalancername')} -> {gw.split('/')[-1].split(':')[-1]}"
            connect_nodes(tgs, g["routetableassociationid"][gw], kw)


def connect_ec2_routes():
    dg = {k: get_default_route_for_subnet([v.get("subnetid")]) for k, v in act.get("ec2", {}).items()}
    for k in dg:
        dg[k] = set(dg[k])
        for ri in dg[k]:
            if type(g["ec2"][k]) == str:
                logging.warning(f"[*****] Object not displayed for {k}")
                continue
            if not g["routetableassociationid"].get(ri) or type(g["routetableassociationid"][ri]) == str:
                logging.warning(f"[*****] Route object {ri} not found for {k.split('/')[-1]}")
                continue

            kw = {"style": "bold", "color": color["unknown"]}
            kw["tooltip"] = f"{k.split('/')[-1].split(':')[-1]} -> {ri.split('/')[-1].split(':')[-1]}"
            n1, n2 = g["ec2"][k], g["routetableassociationid"][ri]
            kw["lhead"] = n2._cluster.name
            connect_nodes(n1, n2, kw)


def get_default_route_for_subnet(subnet_ids) -> list:
    ris = []
    for rt in inventory.get("routetable", {}).values():
        for a in rt.get("associations", []):
            if a.get("subnetid") and a["subnetid"] in subnet_ids:
                break
        else:
            continue
        ris.append(a.get("routetableassociationid"))
    if not bool(ris):
        # Fail back to VPC routing
        vpc_ids = [s.get("vpcid") for s in inventory.get("subnet", {}).values() if s.get("subnetid") in subnet_ids]
        for rt in inventory.get("routetable", {}).values():
            for a in rt.get("associations", []):
                if a.get("main"):
                    break
            else:
                continue
            if not rt.get("vpcid") in vpc_ids:
                continue
            ris.append(a.get("routetableassociationid"))
    return list(set(ris))


def connect_ext():
    tgw_connector()
    connect_vpces()
    connect_lb_routes()
    connect_ec2_routes()
    connect_internet()
    connect_dc()


def connect_orphans():
    if not bool(g.get("orphan")) and not bool(g.get("ip")):
        return
    with Cluster(label="External"):
        for k, w in g.get("orphan", {}).items():
            o_t = get_type(k)
            if type(w) != list:
                w = [w]
            for a in w:
                # k = resource arn
                # a = external principal account id
                n1, n2 = None, None
                kw = {"style": "dashed", "color": color["unknown"], "fontcolor": color["unknown"]}
                if type(a) == str:
                    kw["tooltip"] = "{} -> {}".format(a, k)
                    a, b = get_account(a), a
                    if not a:  # Broken CN
                        a = b
                elif type(a) == dict:
                    account_id = list(a.keys())[0]
                    kw["tooltip"] = make_tip(a)
                    a, b = get_account(account_id), account_id
                    if not a:  # Broken CN
                        a = b
                if not a:
                    continue
                if a == act["id"]:
                    continue
                label = a
                if a in inventory.get("org", {}):
                    label = f"{a}<BR />({inventory['org'][a]})"
                kw["label"] = get_format(a).format(label)
                n1 = add_external_node(a, kw)
                if o_t == "s3":
                    n2 = g["s3bucket"].get(k)
                    if not bool(n2):
                        n2 = g["s3bucket"].get(by_id(o_t, get_id(k)))
                else:
                    n2 = g[o_t][k] if g.get(o_t, {}).get(k) else get_node(k)
                kw.update({"labelfloat": "true", "decorate": "true", "labeltooltip": kw["tooltip"]})
                del kw["label"]
                connect_nodes(n1, n2, kw)

        for k, a in g.get("ip", {}).items():
            kw = {"color": color["unknown"], "tooltip": k}
            kw["color"] = color["unknown" if ipaddress.ip_address(k).is_private else "internet"]
            g["unknown"][k] = Client(k, **kw)
            for c in a:
                c_t = get_type(c)
                n1, n2 = g["unknown"][k], g[c_t][c]
                ekw = {"style": "dashed", "color": color["unknown"]}
                ekw["tooltip"] = f"{c.split('/')[-1].split(':')[-1]} <-> {k.split('/')[-1].split(':')[-1]}"
                if c_t == "targetgroup":
                    ekw["tooltip"] = f"{c.split('/')[-2].split(':')[-1]} <-> {k.split('/')[-1].split(':')[-1]}"
                connect_nodes(n1, n2, ekw)
            g["ip"][k] = ""


def add_external_node(a, kw):
    if not g.get("unknown"):
        g["unknown"] = {}
    if not a in g["unknown"]:
        if a == "*":
            kw["label"] = kw["label"].replace("*", "<b>ANY</b>")
        g["unknown"][a] = (Users if a == "*" else OrganizationsAccount)(**kw)
    return g["unknown"][a]


def connect_internet():
    kw = {"style": "dashed", "color": color["internet"], "fontcolor": color["internet"]}
    gw_elbs = {
        k: v for k, v in inventory.get("elbv2", {}).items() if v.get("type") == "gateway" and k in g.get("elbv2", [])
    }
    n_igw = [
        v["associations"][0]
        for v in inventory["routetable"].values()
        for a in v.get("associations")
        if a.get("gatewayid")
    ]
    n_igw_ids = [n.get("gatewayid") for n in n_igw]  # IDs of IGWs that are not internet-connected
    i_igw = {k: v for k, v in g["igw"].items() if type(v) != str and not get_id(k) in n_igw_ids}
    o_natgw = {k: v for k, v in g.get("natgw", {}).items() if type(v) != str}
    i_natgw = {k: inventory["natgw"][k] for k in o_natgw}
    i_ec2_dns = [inventory["ec2"][k].get("publicdnsname") for k in g["ec2"] if inventory["ec2"][k].get("publicdnsname")]
    i_ec2_dns_o = [g["dnsname"][d] for d in i_ec2_dns if g["dnsname"].get(d)]
    i_elb_dns_o = []
    i_eni = [
        k
        for k in g.get("eni", {})
        if inventory.get("eni", {}).get(k, {}).get("association") and inventory["eni"][k]["association"].get("publicip")
    ]
    for elbv2 in g.get("elbv2", []):
        if inventory["elbv2"][elbv2].get("scheme") == "internal":
            continue
        if elbv2 in gw_elbs:
            continue
        elb_dns_name = g["dnsname"].get(inventory["elbv2"][elbv2].get("dnsname"))
        if elb_dns_name:
            i_elb_dns_o.append(elb_dns_name)
    i_gax = {
        k: i.get("ipaddresses")
        for k, v in g["gax"].items()
        for i in act.get("gax", {}).get(k, {}).get("ipsets", [])
        if type(v) != str
    }
    o_gax = {k: v for k, v in g["gax"].items() if type(v) != str}
    if bool(list(i_igw) + list(o_natgw) + i_elb_dns_o + i_ec2_dns_o + i_eni + list(i_gax)):
        kw = {"style": "dashed", "fontcolor": color["internet"], "color": color["internet"]}
        tt = {}
        t = [{v["association"].get("publicip"): k} for k, v in act.get("eni", {}).items() if v.get("association")]
        if bool(t):
            tt = {"ingress": t}
        if bool(i_igw):
            tt["igw"] = list(i_igw.keys())
        if bool(i_gax):
            tt["gax"] = list(i_gax.values())
        if bool(i_elb_dns_o):
            tt["elb"] = i_elb_dns_o
        # if bool(i_ec2_dns_o):
        #     kw["tooltip"] = "Internet -> EC2"
        if bool(i_natgw):
            tt["natgw"] = i_natgw

        kw["tooltip"] = make_tip(tt)
        g["internet"] = {"internet": Internet("Internet", **kw)}
        if bool(i_igw):
            connect_nodes(g["internet"]["internet"], list(i_igw.values()), kw)
        if bool(i_gax):
            connect_nodes(g["internet"]["internet"], list(o_gax.values()), kw)
        if bool(i_elb_dns_o):
            kw["tooltip"] = "Internet -> ELB"
            connect_nodes(g["internet"]["internet"], i_elb_dns_o, kw)
        if bool(i_ec2_dns_o):
            connect_nodes(g["internet"]["internet"], i_ec2_dns_o, kw)
        if bool(i_natgw):
            kw.update({"color": color["unknown"], "style": "solid"})
            connect_nodes(list(o_natgw.values()), g["internet"]["internet"], kw)
        for k in i_eni:
            connect_nodes(g["internet"]["internet"], g["eni"][k], kw)


def connect_vpces():
    vpces_allows = {}
    for k in g.get("vpces", []):
        v = inventory["vpces"][k].get("vpcespermissions", [])
        for p in v:
            if not vpces_allows.get(k):
                vpces_allows[k] = []
            vpces_allows[k].append(get_account(p.get("principal")))

    vpces_elbs = {}
    for k, v in inventory.get("vpces", {}).items():
        for l in v.get("gatewayloadbalancerarns", []) + v.get("networkloadbalancerarns", []):
            if not l in g.get("elbv2", []):
                continue
            if not vpces_elbs.get(k):
                vpces_elbs[k] = []
            vpces_elbs[k].append(l)

    for k, v in vpces_allows.items():
        for i in set(v):
            if get_account(k) == i:
                continue
            if not "partner" in g:
                g["partner"] = {}
            kw = {"label": "\n".join([i, f"({inventory.get('org',{}).get(i,'')})"])}
            if i in inventory.get("org"):
                kw["fontcolor"] = kw["color"] = color["vpce"]
            else:
                kw["fontcolor"] = kw["color"] = color["internet"]
            if not i in g["partner"]:
                g["partner"][i] = InternetAlt1(**kw)
            del kw["label"]
            for f in vpces_elbs.get(k, []):
                for t in inventory.get("elbv2", {}).get(f, {}).get("targetgroups", []):
                    if type(g.get("targetgroup", {}).get(t["targetgrouparn"], "")) == str:
                        logging.warning(f"Missing target group object {t['targetgrouparn']}")
                        continue
                    kw["tooltip"] = "{} -> {}".format(
                        get_id(i.split(":")[-1]), get_id(t["targetgrouparn"].split(":")[-1])
                    )
                    n1, n2 = g["partner"][i], g["targetgroup"][t["targetgrouparn"]]
                    connect_nodes(n1, n2, kw)


def connect_dc():
    if not act.get("dxgw"):
        return
    with Cluster(label="Datacenter"):
        g["datacenter"] = {}
        g["datacenter"]["datacenter"] = Datacenter("Datacenter", color=color["directconnect"])
    with Cluster(label="Partner Connections"):
        if not "partner" in g:
            g["partner"] = {}
        for k in g.get("dxgw", {}):
            vifs = [a.get("virtualinterfaceid") for a in inventory.get("dxgw", {}).get(k, {}).get("attachments", [])]
            for vif in vifs:
                if not g.get("dcvif"):
                    g["dcvif"] = {}
                partner, location = "", ""
                q = ""
                for q, p in inventory.get("dxcon", {}).items():
                    for i in p.get("virtualinterfaces", []):
                        if i.get("virtualinterfaceid") in vifs:
                            partner = p.get("partnername", "").upper()
                            location = p.get("location", "").upper()
                            break
                kw = {}
                kw["label"] = "\n".join([partner, location, vif])
                if not g["dcvif"].get(vif):
                    if q and q in get_encryption(q).get("encrypted"):
                        kw["label"] = f"<<u>{kw['label']}</u>>"
                    kw["tooltip"] = make_tip(get_object(q))
                    g["dcvif"][vif] = SoftwareAsAService(**kw)
                    kw["tooltip"] = f"{vif} -> Datacenter"
                    n1, n2 = g["dcvif"][vif], g["datacenter"]["datacenter"]
                    connect_nodes(n1, n2, kw)
                kw["tooltip"] = f"{k} -> {vif}"
                n1, n2 = g["dxgw"][k], g["dcvif"][vif]
                connect_nodes(n1, n2, kw)
        for k, p in inventory.get("dxcon", {}).items():
            if p.get("owneraccount") != act["id"]:
                continue
            if not bool(p.get("virtualinterfaces", [])):
                partner = p.get("partnername").upper()
                location = p.get("location").upper()
                state = p.get("connectionstate")
                kw = {"color": color["unknown"]} if p.get("connectionstate") != "available" else {}
                kw["label"] = "\n".join([partner, location, state])
                kw["tooltip"] = make_tip(p)
                if not g.get("partner", {}).get(k):
                    g["partner"][k] = SoftwareAsAService(**kw)


def tgw_connector():
    kw = {"style": "dashed", "constraint": "false", "color": color["tgw"]}
    for v in inventory.get("tgwpeeringattachment", {}).values():
        requester_arn = f"arn:aws:ec2:{v['requestertgwinfo']['region']}:{v['requestertgwinfo']['ownerid']}:transit-gateway/{v['requestertgwinfo']['transitgatewayid']}"
        accepter_arn = f"arn:aws:ec2:{v['acceptertgwinfo']['region']}:{v['acceptertgwinfo']['ownerid']}:transit-gateway/{v['acceptertgwinfo']['transitgatewayid']}"
        if not (g["tgw"].get(requester_arn) and g["tgw"].get(accepter_arn)):
            continue
        if type(g["tgw"][requester_arn]) == str or type(g["tgw"][accepter_arn]) == str:
            continue
        kw["tooltip"] = f"{requester_arn} <-> {accepter_arn}"
        kw["forward"] = True
        kw["reverse"] = True
        connect_nodes(g["tgw"][requester_arn], g["tgw"][accepter_arn], kw)
        del kw["forward"]
        del kw["reverse"]


def show_vpc_inventory(vpc_arn):
    logging.info(f"  [v]   {vpc_arn}")
    if (get_id(vpc_arn) == shared_vpc_label) == (vpc_arn.split(":")[4] == act["id"]):
        return

    kw = get_vpc_props(vpc_arn)
    if g.get("vpc") and g["vpc"].get(vpc_arn) and type(g["vpc"][vpc_arn]) != str:
        return  # Guessing this is for owner Shared VPCs that may have multiple accounts feeding from
    with Cluster(**kw) as g["vpc"][vpc_arn]:
        if get_id(vpc_arn) == shared_vpc_label or get_object(vpc_arn).get("ownerid") == act["id"]:
            show_subnets(vpc_arn)
        show_gateways(vpc_arn)
        show_loadbalancers(vpc_arn)
        if get_id(vpc_arn) == shared_vpc_label:
            return
        show_ec2(vpc_arn)
        show_vpcx(vpc_arn)
        show_vpc_routes(vpc_arn)
        show_vpc_services(vpc_arn)


def route_vector(v: dict) -> dict:
    routes = {}
    for i in v.get("routes", []):
        dest, via = "", ""
        for k, e in i.items():
            if not e:
                continue
            if k in ("destinationcidrblock", "destinationprefixlistid"):
                dest = e
            elif k in ("origin", "state"):
                continue
            else:
                via = e
        routes[dest] = {"gw": via, "state": i.get("state")}
    return routes


def show_subnet_routes(sub_id: str):
    for r, v in act.get("routetable", {}).items():
        for a in v.get("associations", []):
            if a.get("main"):
                continue
            if a.get("subnetid", "") != sub_id:
                continue
            show_routes(r, route_vector(v), a.get("routetableassociationid"))


def show_igw_routes(igw_arn: str):
    logging.info(f"     |  Routes for {igw_arn}")
    for r, v in act["routetable"].items():
        for assn in v.get("associations", []):
            if assn.get("gatewayid") != get_id(igw_arn):
                continue
            if assn.get("main"):
                continue
            show_routes(r, route_vector(v), assn.get("routetableassociationid"))


def show_vpc_routes(vpc_arn: str):
    for r, v in act["routetable"].items():
        if v.get("vpcid") != get_id(vpc_arn):
            continue
        for a in v.get("associations", []):
            if not a.get("main"):
                continue
            if not a.get("routetableassociationid"):
                continue
            if a["routetableassociationid"] in g.get("routetableassociationid", {}):
                continue  # Shared VPC duplicates routes
            show_routes(r, route_vector(v), a["routetableassociationid"], a["main"])


def connected_nodes(n1, n2):
    # WONTDO: Reverse connection check
    if not "edges" in g:
        g["edges"] = {}
    if type(n1) == str or type(n2) == str:
        logging.warning(f"*** Trying to connect {type(n1)} to {type(n2)} ***")
        return False
    if not n1.nodeid in g["edges"]:
        g["edges"][n1.nodeid] = {}
    if not n2.nodeid in g["edges"][n1.nodeid]:
        g["edges"][n1.nodeid][n2.nodeid] = {}
        return False
    return True


def connect_routes():
    logging.info(f"    |   Routes")
    for tgw_arn, v in g.get("tgwroutetable", {}).items():
        if type(v) == str:
            continue
        kw = {"forward": False, "tooltip": f"Routes for {tgw_arn.split('/')[-1]}"}
        connect_nodes(g["tgwroutetable"][tgw_arn], g["tgw"][tgw_arn], kw)  # WONTDO: Connect TGW routes
    for rt_arn, v in act.get("routetable", {}).items():
        for assn in v.get("associations", []):
            for r in v.get("routes", []):
                if r.get("gatewayid") == "local":
                    continue
                if r.get("state") == "blackhole":
                    continue
                ot, gw_arn = get_route_gw(r)
                if not g.get("routetable", {}).get(rt_arn) or type(g["routetable"][rt_arn]) == str:
                    if not assn["routetableassociationid"] in g["routetableassociationid"]:  # duplicate in shared VPCs
                        logging.warning(f"[*****] Route Table config missing: {rt_arn}")
                    continue
                if ot == "vpcx" and g.get("pcx", {}).get(get_id(gw_arn)):
                    if type(g["pcx"][get_id(gw_arn)]) == str:
                        logging.warning(f"[*****] Route Table {rt_arn} target missing: {gw_arn}")
                elif not (g.get(ot, {}).get(gw_arn) and type(g[ot][gw_arn]) != str):
                    # This happens with resource sharing across accounts
                    logging.warning(f"[*****] Route Table {rt_arn} target missing: {gw_arn}")
                    if get_account(gw_arn) == act["id"]:
                        assert False, f"Route table target not found in local account: {gw_arn}"
                    continue
                if not (
                    g.get("routetableassociationid", {}).get(assn.get("routetableassociationid"))
                    and type(g["routetableassociationid"][assn["routetableassociationid"]]) != str
                ):
                    logging.warning(f"Route Table {rt_arn} Association missing: {assn.get('routetableassociationid')}")
                    continue
                kw = {"constraint": "false", "style": "solid"}
                if r.get("destinationcidrblock") == "0.0.0.0/0":
                    kw["style"] = "bold"
                if r.get("gatewayid"):
                    if "igw-" in r["gatewayid"]:
                        kw["color"] = color["igw"]
                    elif "nat-" in r["gatewayid"]:
                        kw["color"] = color["external"]
                    elif "vpce-" in r["gatewayid"]:
                        kw["color"] = color["vpce"]
                elif r.get("transitgatewayid") and "tgw-" in r["transitgatewayid"]:
                    kw["color"] = color["tgw"]
                elif r.get("networkinterfaceid") and "eni-" in r["networkinterfaceid"]:
                    kw["color"] = color["eni"]

                kw["tooltip"] = "{}:\n{} -> {}".format(
                    v["routetableid"],
                    r.get("destinationcidrblock") or r.get("destinationprefixlistid"),
                    get_id(gw_arn),
                )
                if "vpcx" == get_type(gw_arn):  # VPCX has "requester" and 'accepter'
                    n1, n2 = (
                        g["routetableassociationid"][assn.get("routetableassociationid")],
                        g["pcx"][get_id(gw_arn)],
                    )
                    if "requester" in n2:
                        if get_object(gw_arn).get("requestervpcinfo", {}).get("region") == get_region(rt_arn):
                            connect_nodes(n1, n2["requester"], kw)  # RouteTable > VPCX requester
                    if "accepter" in n2:
                        if get_object(gw_arn).get("acceptervpcinfo", {}).get("region") == get_region(rt_arn):
                            connect_nodes(n1, n2["accepter"], kw)  # RouteTable > VPCX accepter
                else:
                    n1, n2 = g["routetableassociationid"][assn.get("routetableassociationid")], g[ot][gw_arn]
                    connect_nodes(n1, n2, kw)  # RouteTable > Gateway
                # TODO: incoming connections headport:w + outgoing tailport:e

            ot, key = None, None
            kw = {"style": "solid"}
            if assn.get("gatewayid"):
                if "igw-" in assn["gatewayid"]:
                    ot = "igw"
                    key = assn["gatewayid"]
                    kw["color"] = color[ot]
                elif "nat-" in assn["gatewayid"]:
                    ot = "natgw"
                    key = assn["gatewayid"]
                    kw["color"] = color["external"]
                elif "vpce-" in assn["gatewayid"]:
                    ot = "vpce"
                    key = assn["gatewayid"]
                    kw["color"] = color[ot]
            elif assn.get("gatewayid") and "tgw-" in assn["transitgatewayid"]:
                ot = "tgw"
                key = assn["transitgatewayid"]
                kw["color"] = color[ot]
            if ot:
                for i, gw in g[ot].items():
                    if get_id(i) != key:
                        continue
                    if type(gw) == str:
                        continue
                    logging.info(f"RT Association: {assn.get('routetableassociationid')}")
                    kw["tooltip"] = "{} -> {}".format(get_id(i).split(":")[-1], get_id(rt_arn).split(":")[-1])
                    kw["tailport"] = "e"
                    n1, n2 = gw, g["routetableassociationid"][assn.get("routetableassociationid")]
                    connect_nodes(n1, n2, kw)  # Router outgoing routes


def show_routes(rtb_arn, routes, assn, main=False):
    logging.info(f"      | Route Table {rtb_arn}")
    logging.info(f"       | Route Table Association {assn}")
    with Cluster(label=dup_label("", assn), graph_attr={"bgcolor": color["routetable"]}) as g["routetable"][rtb_arn]:
        rtype_color = {
            "igw-": "igw",
            "nat-": "external",
            "tgw-": "tgw",
            "vpce-": "vpce",
            "pcx-": "vpcx",
            "eni-": "eni",
            "local": "local",
        }
        fm = "<tr><td port='port0' fixedsize='true' width='90' height='90'><img src='{}' /></td><td>{}</td></tr>"
        kw = {"color": "transparent", "fontcolor": color["unknown"], "width": "3.5"}
        kw["height"] = str(1 + len(routes) / 4)
        kw["label"] = f"<<table border='0' cellspacing='0'>"
        kw["tooltip"] = make_tip(act["routetable"][rtb_arn])
        kw["label"] += fm.format(get_icon("router"), f"<B>{rtb_arn.split('/')[-1]}</B>" if main else get_id(rtb_arn))
        for dest, via in routes.items():
            gw = via["gw"]
            for x in rtype_color:
                if gw.startswith(x):
                    fm = "<tr><td port='port{}'><FONT color='{}'>{}</FONT></td><td><FONT color='{}'>{}</FONT></td></tr>"
                    kw["label"] += fm.format(
                        gw.split("-")[-1],
                        color[rtype_color[x]],
                        dest,
                        color[rtype_color[x]],
                        gw if via["state"] == "active" else f"<s>{gw}</s>",
                    )
                    break
            else:
                logging.warning(f"Unrecognized route destination type {gw}")
                assert False, f"Unrecognized route destination type {gw}"
        kw["label"] += f"</table>>"
        g["routetableassociationid"][assn] = Node(**kw)  # TODO headport,tailport - Attach to cell ports


def show_vpcx(vpc_arn: str):
    pcx = {
        e: v
        for e, v in act.get("vpcx", {}).items()
        if get_id(vpc_arn) in [v.get("acceptervpcinfo", {}).get("vpcid"), v.get("requestervpcinfo", {}).get("vpcid")]
    }
    for e, v in pcx.items():
        kw = {
            "color": color["vpcx"],
            "label": get_format(e).format("<BR />".join([v["vpcpeeringconnectionid"], get_name(e)])),
            "tooltip": make_tip(v),
        }
        peer_type = "requester" if get_id(vpc_arn) == v.get("requestervpcinfo", {}).get("vpcid") else "accepter"
        if not g.get("pcx"):
            g["pcx"] = {}
        if not g["pcx"].get(v.get("vpcpeeringconnectionid")) or str == type(g["pcx"][v["vpcpeeringconnectionid"]]):
            g["pcx"][v["vpcpeeringconnectionid"]] = {}
        if not g["vpcx"].get(e):  # or str == type(g["vpcx"][e]):
            g["vpcx"][e] = {}
        # if get_region(vpc_arn) != get_region(e):
        #     continue
        if peer_type in g["pcx"][v["vpcpeeringconnectionid"]]:
            continue
        g["pcx"][v["vpcpeeringconnectionid"]][peer_type] = VPCPeering(**kw)


def connect_vpcx():
    for k in g.get("vpcx", {}).keys():
        o = inventory["vpcx"][k]
        kw = {
            "color": color["vpcx"],
            "rank": "same",
            "forward": True,
            "reverse": True,
            "tooltip": "{}:{}:{} -- {}:{}:{}".format(
                o["requestervpcinfo"]["ownerid"],
                o["requestervpcinfo"]["region"],
                o["requestervpcinfo"]["vpcid"],
                o["acceptervpcinfo"]["ownerid"],
                o["acceptervpcinfo"]["region"],
                o["acceptervpcinfo"]["vpcid"],
            ),
        }
        v = g.get("pcx", {}).get(get_id(k), {})
        if not (v.get("requester") and v.get("accepter")):
            continue
        connect_nodes(v["requester"], v["accepter"], kw)


def get_id(o: str) -> str:
    return o.split("/")[-1] if "/" in o else o.split(":")[-1]


def show_vpces(region_arn):
    r_vpcess = {e: v for e, v in act.get("vpces", {}).items() if region_arn == get_region_arn(e)}
    if not bool(r_vpcess):
        return
    with Cluster(label=dup_label("VPC Endpoint Services", region_arn), graph_attr={"bgcolor": "transparent"}):
        for arn, v in r_vpcess.items():
            kw = {"shape": "box", "style": "dotted"}
            desc = get_id(arn)
            label = "<BR/>".join([desc, get_name(arn), v["privatednsname"] if v.get("privatednsname") else ""])
            kw["label"] = get_format(arn).format(label)
            kw["tooltip"] = make_tip(v)
            g["vpces"][arn] = Privatelink(**kw)


def get_vpc_props(vpc_arn: str) -> dict:
    vpc_id, vpc_o = get_id(vpc_arn), inventory["vpc"].get(vpc_arn)
    vpc_cidr = vpc_o.get("cidrblock", "?") if bool(vpc_o) else ""
    lbl = "  ".join(sorted([x for x in {vpc_id, get_name(vpc_arn), vpc_cidr} if x], reverse=True))
    kw = {
        "label": get_format(vpc_arn).format(lbl)
        if vpc_id != shared_vpc_label
        else dup_label(shared_vpc_label, f"({get_account(vpc_arn)}:{get_region(vpc_arn)})"),
        "graph_attr": {"tooltip": make_tip(vpc_o)},
    }
    return kw


def get_name(arn) -> str:
    if type(arn) == str:
        o = get_object(arn)
    else:
        o = arn
    for t in o.get("tags", []):
        if t.get("key") and t["key"] == "name":
            return t.get("value")
    return get_id(arn)


def region_arns(account_arn: str) -> list:
    return [r for r in g["region"] if get_account(r) == get_account(account_arn) and account_arn in parent(r)]


def get_region_vpcs(region_arn: str) -> list:
    return [v for v in g["vpc"] if get_region_arn(region_arn) == get_region_arn(v)]


def create_findings():
    findings_from_inventory(category="nossm")
    for finding in findings:
        with open(f"data/FINDINGS_{finding}.json", "w") as fout:
            fout.write(
                "{" + ",\n".join(['"' + i + '": ' + json.dumps(findings[finding][i]) for i in findings[finding]]) + "}"
            )


def findings_from_inventory(category="nossm"):
    if inventory.get(category):
        findings[category] = inventory[category]


def clear_findings():
    for f in sorted(glob.glob("data/FINDINGS_*.json")):
        os.remove(f)


def create_dot_dir():
    if os.path.exists("./data/.processed"):
        try:
            shutil.rmtree("./data/.processed")
        except:
            logging.warning(f"Error removing ./data/.processed")
    os.makedirs("./data/.processed")


def get_public_subnets() -> set:
    public_associations = [
        v.get("associations")
        for v in inventory["routetable"].values()
        for vv in v["routes"]
        if vv.get("gatewayid") and vv["gatewayid"].startswith("igw-")
    ]
    return {a["subnetid"] for p_a in public_associations for a in p_a if a.get("subnetid")}


def get_public_vpcs() -> set:
    return set(
        [
            v["vpcid"]
            for v in inventory["routetable"].values()
            for vv in v["routes"]
            if vv.get("gatewayid") and vv["gatewayid"].startswith("igw-")
        ]
    )


def join_pdfs():
    logging.getLogger("PyPDF2").setLevel(logging.ERROR)
    merger = PdfFileMerger(strict=False)
    for file_name in sorted(glob.glob(r"results/pdf/*.pdf")):
        merger.append(file_name)
    merger.write("results/diag.pdf")
    merger.close()


def organize_results(output) -> int:
    ex = 0
    results = (os.sep).join(["results", output, "*"])
    for f in sorted(glob.glob(results)):
        ext = os.path.splitext(f)[-1]
        if len(ext) < 3 or len(ext) > 4 or ext == f".{output}":
            if not ext:
                f0 = (os.sep).join(
                    [(os.sep).join(["data", ".processed", os.path.splitext(f)[0].split(os.sep)[-1].split("-")[0]])]
                )
                f1 = (os.sep).join([(os.sep).join(["data", os.path.splitext(f)[0].split(os.sep)[-1].split("-")[0]])])
                if os.path.exists(f0) > os.path.exists(f1):
                    logging.warning(f"Graphviz may have crashed: {shutil.move(f0, f1, copy_function=shutil.copytree)}")
                    ex = 2
            continue
        dest = (os.sep).join(["results", ext[1:]])
        path = Path(dest)
        path.mkdir(parents=True, exist_ok=True)
        dn = (os.sep).join([dest, f.split(os.sep)[-1]])
        if os.path.exists(dn):
            os.remove(dn)
        shutil.move(f, dest, copy_function=shutil.copytree)
    return ex


def mod_svg():
    svgs = (os.sep).join(["results", "svg", "*.svg"])
    for s in sorted(glob.glob(svgs)):
        with open(s, "r") as f:
            contents = f.readlines()

        with open(s.replace(".svg", ".html"), "w") as f:
            contents = "".join(contents)
            contents = f"{SVGHEADER}{contents}{SVGFOOTER}"
            f.write(contents)
        os.remove(s)
    if not os.path.exists((os.sep).join(["results", "svg", "script.js"])):
        with open((os.sep).join(["results", "svg", "script.js"]), "w") as f:
            f.write(SCRIPT)
    if not os.path.exists((os.sep).join(["results", "svg", "styles.css"])):
        with open((os.sep).join(["results", "svg", "styles.css"]), "w") as f:
            f.write(STYLING)


def kw_diag(act: dict):
    label = (
        f"{act['name']} ({act['id']})"
        if not DEBUG
        else f"{act['name'][:4]}...{act['name'][-4:]} ({act['id'][:4]}...{act['id'][-4:]})"
    )
    label = label.upper()
    return {
        "name": label,
        "filename": (os.sep).join([dest, f"{act['id']}-{act['name']}"]),  # FIXME: destination directories
        "outformat": [output, "svg", "dot"] if DEBUG else [output, "svg"],  # "dot" "svg", "pdf", "png", "dot"
        "direction": "TB",
        "show": False,
        "graph_attr": graph_attr,
    }


def get_image(fname, url) -> str:
    imagedir = "images"
    if not os.path.exists(imagedir):
        os.makedirs(imagedir)
    oname = os.sep.join([imagedir, fname])
    if not os.path.exists(oname):
        urlretrieve(url, oname)
    return os.sep.join(["..", "..", oname])


def get_icon(name):
    if icon.get(name):
        return get_image(f"{name}.png", icon[name])
    logging.warning(f"*** ./images/{name}.png not found ***")
    assert False, f"Image not found for {name}"
    return "unknown.png"


def connect_ram_shares():
    for k, v in inventory.get("ramresourceingress", {}).items():
        for w in v.values():
            for x in g.get("ram", {}):
                if not g.get("ramresourceingress", {}).get(k) or type(g["ramresourceingress"][k]) == str:
                    continue
                if get_region_arn(x) != get_region_arn(w["resourcesharearn"]):
                    continue
                if type(g["ram"][x]) == str:
                    continue
                kw = {"style": "dashed", "color": color["unknown"], "reverse": True, "arrowtail": "invempty"}
                kw["tooltip"] = f"{k.split('/')[-1]} -> {w['resourcesharearn']}"
                connect_nodes(g["ramresourceingress"][k], g["ram"][x], kw)
                break


def get_contact(arn):
    contact = f"::account::{arn}:contact"
    if contact in inventory.get("contact", []):
        return make_tip(inventory["contact"][contact])
    return " "


def get_access_analyzer_findings():
    return [
        f
        for v in inventory.get("accessanalyzer", {}).values()
        for f in v.get("findings")
        if f["status"] == "active" and not f.get("error") == "access_denied"
    ]


def dup_label(show, hide):
    if is_instance(hide, "vpc"):
        if get_id(hide) == shared_vpc_label:
            return "<<FONT color='invis'>{}:{}:{} </FONT>{}>".format(
                get_account(hide), get_region(hide), get_id(hide), show
            )
        return "<<FONT color='invis'>{} </FONT>{}>".format(get_id(hide), show)
    elif is_instance(hide, "region"):
        return "<<FONT color='invis'>{}:{} </FONT>{}>".format(get_account(hide), get_region(hide), show)
    elif is_instance(hide, "account"):
        return "<<FONT color='invis'>{} </FONT>{}>".format(get_account(hide), show)
    elif is_instance(hide, "elbv2"):
        return "<<FONT color='invis'>{} </FONT>{}>".format(get_account(hide), show)
    return "<{}<FONT color='invis'>{}</FONT>>".format(show, hide)


def clean_nones(value):
    """
    Recursively remove all None values from dictionaries and lists, and returns
    the result as a new dictionary or list.
    """
    if isinstance(value, list):
        return [clean_nones(x) for x in value if x is not None]
    elif isinstance(value, dict):
        return {k: clean_nones(v) for k, v in value.items() if v is not None and v != []}
    else:
        return value


def connect_related_services():
    connect_lakeformation_services()
    connect_s3ap_service()


def connect_s3ap_service():
    rt = "s3ap"
    if not g.get(rt):
        return
    for k, v in act.get(rt, {}).items():
        n1 = g.get(rt, {}).get(k)
        bucket_id = by_id("s3", v["bucket"])
        kw = {"color": color["internal"], "fontcolor": color["internal"]}
        if bucket_id:
            n2 = g.get("s3bucket", {}).get(bucket_id)
            if n2 and type(n2) != str:  # Bucket object found as expected
                connect_nodes(n1, n2, kw)
                continue
        n2 = get_s3ap_target(k, v, kw)

        if bool(n2) and type(n2) != str:
            connect_nodes(n1, n2, kw)


def get_s3ap_target(k, v, kw: dict):
    kw["color"] = kw["fontcolor"] = color["internal"]
    if v.get("bucketaccountid") == act["id"]:  # No bucket object, but account shows local
        n2 = [w for b, w in g.get("s3", {}).items() if get_region_arn(b) == get_region_arn(k) and type(w) != str]
        if bool(n2):  # Found some buckets in this region; connecting to service
            n2 = n2[0]
        else:
            kw["color"] = kw["fontcolor"] = color["external"]
            n2 = [w for b, w in g.get("s3", {}).items() if get_account(b) == get_account(k) and type(w) != str]
            if bool(n2):  # Found some buckets in this account; connecting to s3 service anywhere
                n2 = n2[0]
            else:
                logging.warning(f"[*****] {k} is pointing to bucket that should have been in this account")
                assert False, f"{k} does not have bucket target in this account"
    else:  # S3 target is outside of this account
        kw["color"] = kw["fontcolor"] = color["internet"]
        n2 = [w for b, w in g.get("s3", {}).items() if get_account(b) == v.get("bucketaccountid") and type(w) != str]
        if bool(n2):  # Found some buckets in other account; connecting to s3 service anywhere
            n2 = n2[0]
        else:
            add_orphan(k, {v.get("bucketaccountid"): {k: v}})
    return n2


def get_instance_profiles(inventory):
    return {
        p.get("arn"): p
        for v in inventory.get("role", {}).values()
        for p in v["instanceprofilelist"]
        if bool(v.get("instanceprofilelist"))
    }


def get_node(arn):
    match = None
    o_t = get_type(arn)
    for k, v in g.get(o_t, {}).items():
        if type(v) in [str, list]:
            continue
        if (k) == (arn):
            return k
        if get_region_arn(k) == get_region_arn(arn) and o_t in regional_services:
            match = k
            break
        if get_account(k) == get_account(arn):
            match = k
            continue
        if not match:
            match = k
    return match


def by_id(otype, id: str):
    match = None
    for k, v in inventory.get(otype, {}).items():
        # if get_id(k) == id or v.get("id", "") == id or v.get("name", "") == id:
        if get_id(k) in (id, v.get("id"), v.get("name"), v.get("snapshotid")):
            if get_region_arn(k) == get_region_arn(id):
                match = k
                break
            if get_account(k) == get_account(id):
                match = k
                continue
            if not match:
                match = k
    return match


def connect_lakeformation_services():
    rt = "lakeformation"
    if not g.get(rt):
        return

    for k, v in act.get(rt, {}).items():
        kw = {"color": color["internal"], "tooltip": "{} -> {}".format(k, v["resourcearn"])}
        restype = get_type(v["resourcearn"])
        if not restype in ["s3"]:
            # Resourcearn may contain S3/folder path or restype/resourcename
            logging.warning(f"[*****] New resource type for LakeFormation: {restype}")
            assert False, f"New Lake Formation resource type: {restype}"
        n1, n2 = None, None
        # Find lakeformation object node in this resource region
        n1 = [g[rt][x] for x in g[rt] if str != type(g[rt][x]) and get_region_arn(x) == get_region_arn(k)]
        if 1 != len(n1):
            assert False, f"Multiple matches found for LakeFormation target in {k}"  # Sanity check
            continue
        n1 = n1[0]  # Should only have one per region in an account anyway
        for rek, rev in g.get("s3bucket", {}).items():
            if rek.split(":")[-1].split("/")[0] != v["resourcearn"].split(":")[-1].split("/")[0]:
                continue
            if type(rev) == str:
                logging.warning(f"[*****] Missing {rek} for {k}")
                continue
            n2 = rev
            connect_nodes(n1, n2, kw)
        if bool(n2):
            continue

        # If our bucket object is not displayed
        for rek in inventory.get(restype, {}):  # Lakeformation may point at external resouces too
            kw["color"] = color["external"]
            if rek.split(":")[-1].split("/")[0] != v["resourcearn"].split(":")[-1].split("/")[0]:
                continue
            n2 = [
                g[restype][x]
                for x in g[restype]
                if str != type(g[restype][x]) and get_region_arn(x) == get_region_arn(k)
            ]  # Grab the regional service node of this type
            connect_nodes(n1, n2, kw)
            break
        else:
            logging.warning(f"[*****] Unknown resource owner for {k}")
            add_orphan(k, {get_account(v.get("resourcearn")): {k: v}})


def show_xaccount():
    for access in get_xaccess_for_owner(act["id"]):
        if access.get("ispublic") or not access.get("resourcetype") in AA_TYPES:
            logging.warning(json.dumps(access, indent=2))


started = restarted = time.time()
logging.warning(f"{'-'*60}")
create_dot_dir()
clear_findings()
inventory = get_global_inventory()
vpc_logging = vpcs_with_logging()
access_findings = get_access_analyzer_findings()
findings = {}

for f in sorted(glob.glob("data/*/")):
    act, objs, parents, g = {}, {}, {}, {t: {} for t in types}
    graph_attr = {**g_attr}
    act.update({"id": f.split(os.sep)[-2]})
    act["name"] = inventory.get("org", {}).get(act["id"], act["id"])
    logging.warning(f"{act['id']}\t{act['name']}")
    get_account_inventory(f)
    objs = get_basics()
    if not (bool(objs) and bool(objs[0]) and bool(objs[0].keys())):
        logging.info("Nothing to process\n")
        continue
    public_vpcs, public_subnets = get_public_vpcs(), get_public_subnets()
    get_g_handles(objs, g)
    src, dest = (os.sep).join(["data", f"diag.{output}"]), (os.sep).join(["results", output])
    path = Path(dest)
    path.mkdir(parents=True, exist_ok=True)
    restarted = time.time()

    diag = None
    try:
        with Diagram(**kw_diag(act)) as diag:
            for account_arn in sorted(g["account"]):
                awsid = account_arn.split(":")[4]
                logging.warning(f"[a]     {account_arn}")
                ckw = {
                    "graph_attr": {
                        "tooltip": get_contact(awsid),
                        "bgcolor": "#C0E5FC" if awsid == act["id"] else "#C0E5FC50",
                    },
                    "label": get_format(awsid).format(
                        f"{awsid} {'(' + inventory['org'][awsid] + ')' if inventory.get('org',{}).get(awsid) else ''}"
                    ),
                }
                with Cluster(**ckw) as g["account"][account_arn]:
                    for region_arn in region_arns(account_arn):
                        logging.warning(f" [r]    {region_arn}")
                        ckw = {
                            "label": dup_label(region_arn.split(":")[3], account_arn),
                            "graph_attr": {"tooltip": " "},
                        }
                        with Cluster(**ckw) as g["region"][region_arn]:
                            for vpc_arn in get_region_vpcs(region_arn):
                                show_vpc_inventory(vpc_arn)
                            show_regional_services(region_arn)
                    connect_services(account_arn)
                    show_elbtargets()
                    show_account_services(account_arn)
            for eni_arn in g["eni"]:
                connect_enis(eni_arn)
            connect_ext()
            connect_routes()
            connect_vpcx()
            connect_ram_shares()
            connect_related_services()
            connect_orphans()
            show_xaccount()

            src = (os.sep).join(f.split((os.sep))[:-1])
            dest = (os.sep).join(["data", ".processed", act["id"]]) + os.sep

            if not DEBUG:
                shutil.move(src, dest, copy_function=shutil.copytree)
            else:
                lkw = {"format": "%(asctime)s %(message)s", "datefmt": "%H:%M:%S", "level": logging.ERROR}
                logging.basicConfig(**lkw)
    except Exception as e:
        logging.warning("Error: ", e.args)
    finally:
        if diag and os.path.exists(diag.filename):
            for outputformat in diag.outformat:
                cmd = [
                    "dot",
                    "-Kdot",
                    "-Lg",
                    f"-T{outputformat}",
                    "-O",
                    os.path.basename(diag.filename),
                ]
                sub = subprocess.Popen(cmd, cwd=(os.sep).join([".", "results", "pdf"]))
                if sub.wait():
                    continue
            else:
                os.remove(diag.filename)
        logging.warning(
            f"{act['id']}: {sum([len(v) for v in act.values()])} objects. Took {(time.time() - restarted):.2f} s.\n"
        )
        assert not DEBUG, "Debug point"
logging.warning(f"Completed: {(time.time() - started):.2f} s\n")


create_findings()
ex = organize_results(output)
mod_svg()
join_pdfs()
exit(ex)
