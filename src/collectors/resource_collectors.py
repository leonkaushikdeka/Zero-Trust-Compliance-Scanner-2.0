import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from ..config import CloudProvider, ScannerConfig
    from ..rule_engine import RuleEngine
except ImportError:
    from core.config import CloudProvider, ScannerConfig
    from core.rule_engine import RuleEngine

try:
    import boto3
    from botocore.exceptions import ClientError

    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False
    boto3 = None
    ClientError = Exception

logger = logging.getLogger(__name__)


class AWSResourceCollector:
    def __init__(
        self, config: ScannerConfig, session: Optional["boto3.Session"] = None
    ):
        self.config = config
        if not HAS_BOTO3:
            raise ImportError(
                "boto3 is required for AWS resource collection. "
                "Install it with: pip install boto3"
            )
        self.session = session or boto3.Session()
        self.clients = {}
        self._init_clients()

    def _init_clients(self):
        for region in self.config.aws_regions:
            self.clients[region] = {
                "ec2": self.session.client("ec2", region_name=region),
                "s3": self.session.client("s3", region_name=region),
                "iam": self.session.client("iam"),
                "cloudtrail": self.session.client("cloudtrail", region_name=region),
                "kms": self.session.client("kms", region_name=region),
                "rds": self.session.client("rds", region_name=region),
                "lambda": self.session.client("lambda", region_name=region),
                "config": self.session.client("config", region_name=region),
            }

    def collect_all_resources(self) -> Dict[str, List[Dict[str, Any]]]:
        all_resources = {}

        with ThreadPoolExecutor(max_workers=self.config.parallel_scans) as executor:
            futures = {
                executor.submit(self._collect_region_resources, region): region
                for region in self.config.aws_regions
            }

            for future in as_completed(futures):
                region = futures[future]
                try:
                    region_resources = future.result()
                    for resource_type, resources in region_resources.items():
                        if resource_type not in all_resources:
                            all_resources[resource_type] = []
                        all_resources[resource_type].extend(resources)
                except Exception as e:
                    logger.error(
                        f"Error collecting resources from region {region}: {e}"
                    )

        return all_resources

    def _collect_region_resources(self, region: str) -> Dict[str, List[Dict[str, Any]]]:
        resources = {
            "s3_buckets": self._collect_s3_buckets(region),
            "security_groups": self._collect_security_groups(region),
            "iam_policies": self._collect_iam_policies(),
            "iam_password_policy": self._collect_iam_password_policy(),
            "kms_keys": self._collect_kms_keys(region),
            "ebs_volumes": self._collect_ebs_volumes(region),
            "rds_instances": self._collect_rds_instances(region),
            "cloudtrails": self._collect_cloudtrails(region),
            "amis": self._collect_amis(region),
        }
        return resources

    def _collect_s3_buckets(self, region: str) -> List[Dict[str, Any]]:
        buckets = []
        s3_client = self.session.client("s3")

        try:
            response = s3_client.list_buckets()
            for bucket in response.get("Buckets", []):
                bucket_name = bucket["Name"]
                bucket_info = {
                    "Name": bucket_name,
                    "ResourceType": "AWS::S3::Bucket",
                    "Region": "global",
                    "CreationDate": bucket.get("CreationDate"),
                }

                try:
                    block_config = s3_client.get_public_access_block(Bucket=bucket_name)
                    bucket_info["PublicAccessBlockConfiguration"] = block_config.get(
                        "PublicAccessBlockConfiguration", {}
                    )
                except ClientError:
                    bucket_info["PublicAccessBlockConfiguration"] = {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False,
                    }

                try:
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                    bucket_info["Encryption"] = encryption.get(
                        "ServerSideEncryptionConfiguration", {}
                    )
                except ClientError:
                    bucket_info["Encryption"] = {}

                try:
                    logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
                    bucket_info["Logging"] = logging_config.get("LoggingEnabled", {})
                except ClientError:
                    bucket_info["Logging"] = {}

                try:
                    versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    bucket_info["Versioning"] = versioning
                except ClientError:
                    bucket_info["Versioning"] = {}

                buckets.append(bucket_info)
        except ClientError as e:
            logger.error(f"Error collecting S3 buckets: {e}")

        return buckets

    def _collect_security_groups(self, region: str) -> List[Dict[str, Any]]:
        security_groups = []
        ec2_client = self.clients[region]["ec2"]

        try:
            response = ec2_client.describe_security_groups()
            for sg in response.get("SecurityGroups", []):
                security_groups.append(
                    {
                        "Id": sg["GroupId"],
                        "Name": sg["GroupName"],
                        "ResourceType": "AWS::EC2::SecurityGroup",
                        "VpcId": sg.get("VpcId"),
                        "Region": region,
                        "IpPermissions": sg.get("IpPermissions", []),
                        "IpPermissionsEgress": sg.get("IpPermissionsEgress", []),
                        "GroupTenancy": sg.get("GroupTenancy", "default"),
                    }
                )
        except ClientError as e:
            logger.error(f"Error collecting security groups in {region}: {e}")

        return security_groups

    def _collect_iam_policies(self) -> List[Dict[str, Any]]:
        policies = []
        iam_client = self.clients[self.config.aws_regions[0]]["iam"]

        try:
            response = iam_client.list_policies(Scope="Local", MaxItems=1000)
            for policy in response.get("Policies", []):
                policy_version = iam_client.get_policy_version(
                    PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
                )
                policies.append(
                    {
                        "Id": policy["PolicyId"],
                        "Name": policy["PolicyName"],
                        "Arn": policy["Arn"],
                        "ResourceType": "AWS::IAM::Policy",
                        "PolicyDocument": policy_version.get("PolicyVersion", {}).get(
                            "Document", {}
                        ),
                        "AttachmentCount": policy.get("AttachmentCount", 0),
                    }
                )
        except ClientError as e:
            logger.error(f"Error collecting IAM policies: {e}")

        return policies

    def _collect_iam_password_policy(self) -> List[Dict[str, Any]]:
        iam_client = self.clients[self.config.aws_regions[0]]["iam"]

        try:
            response = iam_client.get_account_password_policy()
            return [
                {
                    "Id": "account-password-policy",
                    "Name": "AccountPasswordPolicy",
                    "ResourceType": "AWS::IAM::PasswordPolicy",
                    "PasswordPolicy": response.get("PasswordPolicy", {}),
                }
            ]
        except ClientError:
            return [
                {
                    "Id": "account-password-policy",
                    "Name": "AccountPasswordPolicy",
                    "ResourceType": "AWS::IAM::PasswordPolicy",
                    "PasswordPolicy": {},
                }
            ]

    def _collect_kms_keys(self, region: str) -> List[Dict[str, Any]]:
        keys = []
        kms_client = self.clients[region]["kms"]

        try:
            response = kms_client.list_keys(Limit=1000)
            for key in response.get("Keys", []):
                key_info = {
                    "Id": key["KeyId"],
                    "KeyArn": key["KeyArn"],
                    "ResourceType": "AWS::KMS::Key",
                    "Region": region,
                }

                try:
                    key_metadata = kms_client.describe_key(KeyId=key["KeyId"])
                    key_info.update(key_metadata.get("KeyMetadata", {}))
                except ClientError:
                    pass

                keys.append(key_info)
        except ClientError as e:
            logger.error(f"Error collecting KMS keys in {region}: {e}")

        return keys

    def _collect_ebs_volumes(self, region: str) -> List[Dict[str, Any]]:
        volumes = []
        ec2_client = self.clients[region]["ec2"]

        try:
            response = ec2_client.describe_volumes()
            for volume in response.get("Volumes", []):
                volumes.append(
                    {
                        "Id": volume["VolumeId"],
                        "Name": volume.get("Tags", [{}])[0].get(
                            "Value", volume["VolumeId"]
                        ),
                        "ResourceType": "AWS::EC2::Volume",
                        "Region": region,
                        "Encrypted": volume.get("Encrypted", False),
                        "VolumeType": volume.get("VolumeType", "gp2"),
                        "Size": volume.get("Size", 0),
                    }
                )
        except ClientError as e:
            logger.error(f"Error collecting EBS volumes in {region}: {e}")

        return volumes

    def _collect_rds_instances(self, region: str) -> List[Dict[str, Any]]:
        instances = []
        rds_client = self.clients[region]["rds"]

        try:
            response = rds_client.describe_db_instances()
            for instance in response.get("DBInstances", []):
                instances.append(
                    {
                        "Id": instance["DBInstanceIdentifier"],
                        "Name": instance["DBInstanceIdentifier"],
                        "ResourceType": "AWS::RDS::DBInstance",
                        "Region": region,
                        "PubliclyAccessible": instance.get("PubliclyAccessible", False),
                        "StorageEncrypted": instance.get("StorageEncrypted", False),
                        "DBInstanceClass": instance.get("DBInstanceClass"),
                        "Engine": instance.get("Engine"),
                        "BackupRetentionPeriod": instance.get(
                            "BackupRetentionPeriod", 1
                        ),
                    }
                )
        except ClientError as e:
            logger.error(f"Error collecting RDS instances in {region}: {e}")

        return instances

    def _collect_cloudtrails(self, region: str) -> List[Dict[str, Any]]:
        trails = []
        cloudtrail_client = self.clients[region]["cloudtrail"]

        try:
            response = cloudtrail_client.describe_trails()
            for trail in response.get("trailList", []):
                trails.append(
                    {
                        "Id": trail.get("TrailARN"),
                        "Name": trail.get("Name"),
                        "ResourceType": "AWS::CloudTrail::Trail",
                        "Region": region,
                        "S3BucketName": trail.get("S3BucketName"),
                        "IsMultiRegionTrail": trail.get("IsMultiRegionTrail", False),
                        "LogFileValidationEnabled": trail.get(
                            "LogFileValidationEnabled", False
                        ),
                    }
                )

                try:
                    trail_status = cloudtrail_client.get_trail_status(
                        Name=trail.get("TrailARN")
                    )
                    trails[-1]["LatestDeliveryTime"] = trail_status.get(
                        "LatestDeliveryTime"
                    )
                    trails[-1]["StartLoggingTime"] = trail_status.get(
                        "StartLoggingTime"
                    )
                except ClientError:
                    pass
        except ClientError as e:
            logger.error(f"Error collecting CloudTrail trails in {region}: {e}")

        return trails

    def _collect_amis(self, region: str) -> List[Dict[str, Any]]:
        images = []
        ec2_client = self.clients[region]["ec2"]

        try:
            response = ec2_client.describe_images(Owners=["self"])
            for image in response.get("Images", []):
                images.append(
                    {
                        "Id": image["ImageId"],
                        "Name": image.get("Name", "unknown"),
                        "ResourceType": "AWS::EC2::AMI",
                        "Region": region,
                        "Public": image.get("Public", False),
                        "ImageType": image.get("ImageType", "machine"),
                        "Architecture": image.get("Architecture", "x86_64"),
                    }
                )
        except ClientError as e:
            logger.error(f"Error collecting AMIs in {region}: {e}")

        return images

    def collect_iam_users(self) -> List[Dict[str, Any]]:
        users = []
        iam_client = self.clients[self.config.aws_regions[0]]["iam"]

        try:
            response = iam_client.list_users(MaxItems=1000)
            for user in response.get("Users", []):
                user_info = {
                    "Id": user["UserId"],
                    "Name": user["UserName"],
                    "Arn": user["Arn"],
                    "ResourceType": "AWS::IAM::User",
                    "CreateDate": user.get("CreateDate"),
                }

                try:
                    mfa_devices = iam_client.list_mfa_devices(UserName=user["UserName"])
                    user_info["MFADevice"] = {
                        "Enabled": len(mfa_devices.get("MFADevices", [])) > 0,
                        "Devices": mfa_devices.get("MFADevices", []),
                    }
                except ClientError:
                    user_info["MFADevice"] = {"Enabled": False}

                users.append(user_info)
        except ClientError as e:
            logger.error(f"Error collecting IAM users: {e}")

        return users


class AzureResourceCollector:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.clients = {}
        self._init_clients()

    def _init_clients(self):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.resource import ResourceManagementClient
            from azure.mgmt.storage import StorageManagementClient
            from azure.mgmt.network import NetworkManagementClient
            from azure.mgmt.security import SecurityCenter

            credential = DefaultAzureCredential()

            for subscription_id in self.config.azure_subscriptions:
                self.clients[subscription_id] = {
                    "resource": ResourceManagementClient(credential, subscription_id),
                    "storage": StorageManagementClient(credential, subscription_id),
                    "network": NetworkManagementClient(credential, subscription_id),
                    "security": SecurityCenter(credential, subscription_id),
                }
        except ImportError:
            logger.warning(
                "Azure SDK not installed. Run: pip install azure-mgmt-resource azure-mgmt-storage azure-mgmt-network azure-identity"
            )

    def collect_all_resources(self) -> Dict[str, List[Dict[str, Any]]]:
        all_resources = {}

        for subscription_id in self.config.azure_subscriptions:
            if subscription_id not in self.clients:
                continue

            try:
                sub_resources = {
                    "storage_accounts": self._collect_storage_accounts(subscription_id),
                    "network_security_groups": self._collect_network_security_groups(
                        subscription_id
                    ),
                }

                for resource_type, resources in sub_resources.items():
                    if resource_type not in all_resources:
                        all_resources[resource_type] = []
                    all_resources[resource_type].extend(resources)
            except Exception as e:
                logger.error(
                    f"Error collecting resources from subscription {subscription_id}: {e}"
                )

        return all_resources

    def _collect_storage_accounts(self, subscription_id: str) -> List[Dict[str, Any]]:
        storage_accounts = []
        client = self.clients[subscription_id]["storage"]

        try:
            for account in client.storage_accounts.list():
                props = client.storage_accounts.get_properties(
                    account.id, expand="statuss"
                )
                storage_accounts.append(
                    {
                        "Id": account.id,
                        "Name": account.name,
                        "ResourceType": "Microsoft.Storage/storageAccounts",
                        "enableHttpsTrafficOnly": getattr(
                            props, "enable_https_traffic_only", True
                        ),
                        "allowBlobPublicAccess": getattr(
                            props, "allow_blob_public_access", False
                        ),
                        "location": account.location,
                        "sku_tier": getattr(account.sku, "tier", "Standard"),
                    }
                )
        except Exception as e:
            logger.error(f"Error collecting storage accounts: {e}")

        return storage_accounts

    def _collect_network_security_groups(
        self, subscription_id: str
    ) -> List[Dict[str, Any]]:
        nsgs = []
        client = self.clients[subscription_id]["network"]

        try:
            for nsg in client.network_security_groups.list_all():
                nsgs.append(
                    {
                        "Id": nsg.id,
                        "Name": nsg.name,
                        "ResourceType": "Microsoft.Network/networkSecurityGroups",
                        "location": nsg.location,
                        "securityRules": [
                            {
                                "name": rule.name,
                                "access": rule.access,
                                "destinationPortRange": getattr(
                                    rule, "destination_port_range", "*"
                                ),
                                "sourceAddressPrefix": getattr(
                                    rule, "source_address_prefix", "*"
                                ),
                                "protocol": getattr(rule, "protocol", "*"),
                            }
                            for rule in (nsg.security_rules or [])
                        ],
                    }
                )
        except Exception as e:
            logger.error(f"Error collecting NSGs: {e}")

        return nsgs


class GCResourceCollector:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.clients = {}
        self._init_clients()

    def _init_clients(self):
        try:
            from google.cloud import storage
            from google.cloud.compute_v1 import InstancesClient, ListFirewallsRequest
            from google.cloud import cloudresourcemanager_v1
            from google.cloud import oslogin_v1

            for project_id in self.config.gcp_projects:
                self.clients[project_id] = {
                    "storage": storage.Client(project=project_id),
                    "compute": InstancesClient(),
                    "oslogin": oslogin_v1.OsLoginServiceClient(),
                    "project": cloudresourcemanager_v1.ProjectManagerClient(),
                    "firewall_request": ListFirewallsRequest,
                }
        except ImportError:
            logger.warning(
                "GCP SDK not installed. Run: pip install google-cloud-storage google-cloud-compute google-cloud-oslogin google-cloud-resource-manager"
            )

    def collect_all_resources(self) -> Dict[str, List[Dict[str, Any]]]:
        all_resources = {}

        for project_id in self.config.gcp_projects:
            if project_id not in self.clients:
                continue

            try:
                project_resources = {
                    "storage_buckets": self._collect_storage_buckets(project_id),
                    "firewall_rules": self._collect_firewall_rules(project_id),
                    "compute_instances": self._collect_compute_instances(project_id),
                }

                for resource_type, resources in project_resources.items():
                    if resource_type not in all_resources:
                        all_resources[resource_type] = []
                    all_resources[resource_type].extend(resources)
            except Exception as e:
                logger.error(
                    f"Error collecting resources from project {project_id}: {e}"
                )

        return all_resources

    def _collect_storage_buckets(self, project_id: str) -> List[Dict[str, Any]]:
        buckets = []
        storage_client = self.clients[project_id]["storage"]

        try:
            for bucket in storage_client.list_buckets():
                buckets.append(
                    {
                        "Id": bucket.name,
                        "Name": bucket.name,
                        "ResourceType": "google.storage.Bucket",
                        "location": bucket.location,
                        "iamConfiguration": {
                            "uniformBucketLevelAccess": {
                                "enabled": bucket.iam_configuration.get(
                                    "uniformBucketLevelAccess", {}
                                ).get("enabled", True)
                            }
                        },
                        "encryptionConfig": {
                            "defaultKmsKeyName": bucket.encryption.get(
                                "default_kms_key_name", ""
                            ),
                        },
                        "logging": {
                            "logObjectPrefix": bucket.logging.get(
                                "log_object_prefix", ""
                            ),
                        },
                    }
                )
        except Exception as e:
            logger.error(f"Error collecting storage buckets: {e}")

        return buckets

    def _collect_firewall_rules(self, project_id: str) -> List[Dict[str, Any]]:
        rules = []
        compute_client = self.clients[project_id]["compute"]
        ListFirewallsRequest = self.clients[project_id].get("firewall_request")

        try:
            if ListFirewallsRequest:
                request = ListFirewallsRequest()
                for firewall in compute_client.list(
                    request=request, project=project_id
                ):
                    rules.append(
                        {
                            "Id": firewall.name,
                            "Name": firewall.name,
                            "ResourceType": "google.compute.Firewall",
                            "project": project_id,
                            "network": firewall.network,
                            "priority": firewall.priority,
                            "direction": firewall.direction,
                            "action": "allow" if firewall.alloweds else "deny",
                            "sourceRanges": list(firewall.source_ranges),
                            "allowed": [
                                {
                                    "IPProtocol": allowed.IPProtocol,
                                    "ports": list(allowed.ports or []),
                                }
                                for allowed in (firewall.alloweds or [])
                            ],
                        }
                    )
        except Exception as e:
            logger.error(f"Error collecting firewall rules: {e}")

        return rules

    def _collect_compute_instances(self, project_id: str) -> List[Dict[str, Any]]:
        instances = []
        compute_client = self.clients[project_id]["compute"]

        try:
            from google.cloud.compute_v1 import ListInstancesRequest

            request = ListInstancesRequest()
            for instance in compute_client.list(request=request, project=project_id):
                instances.append(
                    {
                        "Id": instance.name,
                        "Name": instance.name,
                        "ResourceType": "google.compute.Instance",
                        "project": project_id,
                        "zone": instance.zone,
                        "metadata": {
                            "enable-oslogin": "TRUE",
                        },
                    }
                )
        except Exception as e:
            logger.error(f"Error collecting compute instances: {e}")

        return instances


class KubernetesResourceCollector:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.clients = {}

    def collect_all_resources(self) -> Dict[str, List[Dict[str, Any]]]:
        all_resources = {}

        for cluster in self.config.kubernetes_clusters:
            try:
                from kubernetes import client, config as k8s_config

                k8s_config.load_kube_config()
                apps_v1 = client.AppsV1Api()
                core_v1 = client.CoreV1Api()
                networking_v1 = client.NetworkingV1Api()

                cluster_resources = {
                    "pods": self._collect_pods(core_v1),
                    "deployments": self._collect_deployments(apps_v1),
                    "network_policies": self._collect_network_policies(networking_v1),
                    "namespaces": self._collect_namespaces(core_v1),
                }

                for resource_type, resources in cluster_resources.items():
                    key = f"{cluster}/{resource_type}"
                    all_resources[key] = resources
            except ImportError:
                logger.warning(
                    "Kubernetes SDK not installed. Run: pip install kubernetes"
                )
            except Exception as e:
                logger.error(f"Error collecting resources from cluster {cluster}: {e}")

        return all_resources

    def _collect_pods(self, api) -> List[Dict[str, Any]]:
        pods = []
        try:
            for pod in api.list_pod_for_all_namespaces().items:
                pods.append(
                    {
                        "Id": f"{pod.metadata.namespace}/{pod.metadata.name}",
                        "Name": pod.metadata.name,
                        "Namespace": pod.metadata.namespace,
                        "ResourceType": "kubernetes.Pod",
                        "PodSpec": pod.spec.to_dict() if pod.spec else {},
                        "PodSecurityContext": pod.spec.security_context.to_dict()
                        if pod.spec and pod.spec.security_context
                        else {},
                    }
                )
        except Exception as e:
            logger.error(f"Error collecting pods: {e}")

        return pods

    def _collect_deployments(self, api) -> List[Dict[str, Any]]:
        deployments = []
        try:
            for deploy in api.list_deployment_for_all_namespaces().items:
                deployments.append(
                    {
                        "Id": f"{deploy.metadata.namespace}/{deploy.metadata.name}",
                        "Name": deploy.metadata.name,
                        "Namespace": deploy.metadata.namespace,
                        "ResourceType": "kubernetes.Deployment",
                        "PodSpec": deploy.spec.template.spec.to_dict()
                        if deploy.spec
                        and deploy.spec.template
                        and deploy.spec.template.spec
                        else {},
                    }
                )
        except Exception as e:
            logger.error(f"Error collecting deployments: {e}")

        return deployments

    def _collect_network_policies(self, api) -> List[Dict[str, Any]]:
        policies = []
        try:
            for np in api.list_network_policy_for_all_namespaces().items:
                policies.append(
                    {
                        "Id": f"{np.metadata.namespace}/{np.metadata.name}",
                        "Name": np.metadata.name,
                        "Namespace": np.metadata.namespace,
                        "ResourceType": "kubernetes.NetworkPolicy",
                        "Spec": np.spec.to_dict() if np.spec else {},
                    }
                )
        except Exception as e:
            logger.error(f"Error collecting network policies: {e}")

        return policies

    def _collect_namespaces(self, api) -> List[Dict[str, Any]]:
        namespaces = []
        try:
            for ns in api.list_namespace().items:
                namespaces.append(
                    {
                        "Id": ns.metadata.name,
                        "Name": ns.metadata.name,
                        "ResourceType": "kubernetes.Namespace",
                        "Status": ns.status.phase if ns.status else "",
                    }
                )
        except Exception as e:
            logger.error(f"Error collecting namespaces: {e}")

        return namespaces


class TerraformResourceCollector:
    def __init__(self, config: ScannerConfig):
        self.config = config

    def collect_all_resources(self) -> Dict[str, List[Dict[str, Any]]]:
        all_resources = {}

        for path in self.config.terraform_paths:
            resources = self._parse_terraform_directory(path)
            if resources:
                all_resources["terraform"] = resources

        return all_resources

    def _parse_terraform_directory(self, path: str) -> List[Dict[str, Any]]:
        resources = []

        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith((".tf", ".tf.json")):
                    file_path = os.path.join(root, file)
                    try:
                        file_resources = self._parse_terraform_file(file_path)
                        resources.extend(file_resources)
                    except Exception as e:
                        logger.error(f"Error parsing {file_path}: {e}")

        return resources

    def _parse_terraform_file(self, file_path: str) -> List[Dict[str, Any]]:
        resources = []

        try:
            import hcl2

            with open(file_path, "r") as f:
                data = hcl2.load(f)

            for resource in data.get("resource", []):
                for resource_type, instances in resource.items():
                    for instance in instances:
                        resources.append(
                            {
                                "Id": f"{resource_type}_{instance.get('name', instance.get('id', file_path))}",
                                "Name": instance.get("name", resource_type),
                                "ResourceType": resource_type,
                                "SourceFile": file_path,
                                **instance,
                            }
                        )
        except ImportError:
            logger.warning("hcl2 not installed. Run: pip install pyhcl2")
            with open(file_path, "r") as f:
                content = f.read()

            import re

            resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*{([^}]+)}'
            matches = re.findall(resource_pattern, content, re.DOTALL)

            for match in matches:
                resource_type, resource_name, block_content = match
                resources.append(
                    {
                        "Id": f"{resource_type}_{resource_name}",
                        "Name": resource_name,
                        "ResourceType": resource_type,
                        "SourceFile": file_path,
                    }
                )

        return resources


class ResourceCollector:
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.collectors: Dict[CloudProvider, Any] = {}

        if CloudProvider.AWS in config.enabled_providers and HAS_BOTO3:
            try:
                self.collectors[CloudProvider.AWS] = AWSResourceCollector(config)
            except Exception as e:
                logger.warning(f"Failed to initialize AWS collector: {e}")

        if CloudProvider.AZURE in config.enabled_providers:
            try:
                self.collectors[CloudProvider.AZURE] = AzureResourceCollector(config)
            except Exception as e:
                logger.warning(f"Failed to initialize Azure collector: {e}")

        if CloudProvider.GCP in config.enabled_providers:
            try:
                self.collectors[CloudProvider.GCP] = GCResourceCollector(config)
            except Exception as e:
                logger.warning(f"Failed to initialize GCP collector: {e}")

        if CloudProvider.KUBERNETES in config.enabled_providers:
            try:
                self.collectors[CloudProvider.KUBERNETES] = KubernetesResourceCollector(
                    config
                )
            except Exception as e:
                logger.warning(f"Failed to initialize Kubernetes collector: {e}")

        if CloudProvider.TERRAFORM in config.enabled_providers:
            try:
                self.collectors[CloudProvider.TERRAFORM] = TerraformResourceCollector(
                    config
                )
            except Exception as e:
                logger.warning(f"Failed to initialize Terraform collector: {e}")

    def collect_resources(
        self, provider: CloudProvider
    ) -> Dict[str, List[Dict[str, Any]]]:
        collector = self.collectors.get(provider)
        if not collector:
            logger.warning(f"No collector available for provider: {provider}")
            return {}

        return collector.collect_all_resources()

    def collect_all_providers(
        self,
    ) -> Dict[CloudProvider, Dict[str, List[Dict[str, Any]]]]:
        all_resources = {}

        for provider in self.config.enabled_providers:
            if provider in self.collectors:
                try:
                    all_resources[provider] = self.collect_resources(provider)
                except Exception as e:
                    logger.error(f"Error collecting resources for {provider}: {e}")

        return all_resources
