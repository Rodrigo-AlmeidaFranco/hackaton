"""
Hybrid detector: YOLOv8 localizes regions + Llama-vision reclassifies each crop.

Flow:
  1. YOLOv8 (trained supervised model) → bounding boxes with initial class
  2. llama3.2-vision → looks at each cropped region and refines the class label
  3. Returns DetectionResult with vision-corrected labels

This approach satisfies the supervised training requirement while gaining
accuracy on real AWS/Azure diagrams where visual icons differ from synthetic training data.
"""

import base64
import io
import json
import urllib.request
from typing import Optional

import cv2
import numpy as np
from PIL import Image

from src.model.detector import ArchitectureDetector, DetectionResult, Detection
from src.dataset.generator import COMPONENT_CLASSES, CLASS_TO_IDX, COMPONENT_CLASSES_V2, CLASS_TO_IDX_V2

# Descriptions for v1 (12 generic classes) and v2 (111 cloud-specific classes)
COMPONENT_DESCRIPTIONS = {
    # ── v1 generic ────────────────────────────────────────────────────────────
    "user":             "a person icon, stick figure, human avatar, or group of people",
    "web_server":       "a server, EC2 instance, app service, virtual machine, computer, or application box",
    "database":         "a database cylinder, RDS, SQL server, storage drum, or data store",
    "api_gateway":      "an API gateway, API management, Kong, APIM, or traffic routing icon",
    "load_balancer":    "a load balancer, ALB, NLB, traffic distributor, or scale icon",
    "cache":            "a cache, Redis, Memcached, ElastiCache, or in-memory store icon",
    "firewall":         "a firewall, WAF, shield, security group, DDoS protection, or lock icon",
    "cdn":              "a CDN, CloudFront, content delivery, global network, or edge icon",
    "message_queue":    "a message queue, SQS, Service Bus, Kafka, event bus, or envelope icon",
    "cloud_service":    "a cloud/serverless function, Lambda, Logic Apps, cloud service, workflow, or monitoring icon",
    "mobile_app":       "a mobile phone, smartphone, tablet, iOS/Android app, or mobile client icon",
    "external_service": "an external API, third-party service, partner, REST/SOAP service, or integration icon",
    # ── v2 AWS Compute ────────────────────────────────────────────────────────
    "aws_amazon_ec2":                                       "an orange AWS EC2 compute instance icon",
    "aws_ec2_instance":                                     "an orange AWS EC2 instance icon",
    "aws_ec2_instances":                                    "multiple orange AWS EC2 instances icon",
    "aws_amazon_ec2_auto_scaling":                          "an orange AWS EC2 Auto Scaling icon with circular arrows",
    "aws_auto_scaling":                                     "an orange AWS Auto Scaling icon with arrows",
    "aws_autoscaling":                                      "an orange AWS autoscaling icon",
    "aws_lambda":                                           "an orange AWS Lambda icon with λ symbol",
    "aws_lambda_lambda_function":                           "an orange AWS Lambda function icon with λ symbol",
    "aws_amazon_elastic_container_service":                 "an orange AWS ECS container service icon",
    "aws_elastic_container_service_service":                "an orange AWS ECS service icon",
    "aws_elastic_container_service_container_2":            "an orange AWS ECS container icon",
    "aws_amazon_elastic_kubernetes_service":                "an orange AWS EKS Kubernetes icon",
    # ── v2 AWS Databases ──────────────────────────────────────────────────────
    "aws_amazon_rds":                                       "an orange AWS RDS database cylinder icon",
    "aws_rds":                                              "an orange AWS RDS database icon",
    "aws_aurora_amazon_rds_instance":                       "an orange AWS Aurora RDS instance icon",
    "aws_amazon_dynamodb":                                  "an orange AWS DynamoDB NoSQL icon",
    "aws_dynamodb_table":                                   "an orange AWS DynamoDB table icon",
    "aws_amazon_redshift":                                  "an orange AWS Redshift data warehouse icon",
    # ── v2 AWS Storage ────────────────────────────────────────────────────────
    "aws_amazon_simple_storage_service":                    "an orange AWS S3 bucket icon",
    "aws_simple_storage_service_bucket":                    "an orange AWS S3 bucket icon",
    "aws_simple_storage_service_bucket_with_objects":       "an orange AWS S3 bucket with objects icon",
    "aws_simple_storage_service_object":                    "an orange AWS S3 object icon",
    "aws_simple_storage_service_s3_standard":               "an orange AWS S3 Standard storage tier icon",
    "aws_amazon_elastic_block_store":                       "an orange AWS EBS block storage icon",
    "aws_elastic_block_store_volume":                       "an orange AWS EBS volume icon",
    "aws_elactic_file_system(nfs)_multi-az":                "an orange AWS EFS NFS multi-AZ file system icon",
    # ── v2 AWS Messaging ──────────────────────────────────────────────────────
    "aws_amazon_simple_queue_service":                      "an orange AWS SQS queue icon with envelope",
    "aws_simple_queue_service_queue":                       "an orange AWS SQS queue icon",
    "aws_amazon_simple_notification_service":               "an orange AWS SNS notification icon",
    "aws_simple_notification_service_topic":                "an orange AWS SNS topic icon",
    "aws_simple_email_service":                             "an orange AWS SES email icon with envelope",
    # ── v2 AWS Load Balancers ─────────────────────────────────────────────────
    "aws_elastic_load_balancing":                           "an orange AWS ELB load balancer icon",
    "aws_elastic_load_balancing_application_load_balancer": "an orange AWS Application Load Balancer icon",
    "aws_elastic_load_balancing_network_load_balancer":     "an orange AWS Network Load Balancer icon",
    "aws_application_load_balancer":                        "an orange AWS Application Load Balancer icon",
    # ── v2 AWS CDN / DNS / Networking ─────────────────────────────────────────
    "aws_amazon_cloudfront":                                "an orange AWS CloudFront CDN globe icon",
    "aws_cloudfront":                                       "an orange AWS CloudFront CDN icon",
    "aws_amazon_route_53":                                  "an orange AWS Route 53 DNS globe icon",
    "aws_route_53_hosted_zone":                             "an orange AWS Route 53 hosted zone icon",
    "aws_amazon_virtual_private_cloud":                     "a dashed orange AWS VPC boundary box",
    "aws_virtual_private_cloud":                            "a dashed AWS VPC boundary box",
    "aws_vpc_virtual_private_cloud_vpc":                    "a dashed AWS VPC cloud icon",
    "aws_private_subnet":                                   "a green AWS private subnet rectangle",
    "aws_public_subnet":                                    "a blue AWS public subnet rectangle",
    "aws_region":                                           "a large dashed AWS region boundary box",
    "aws_cloud":                                            "an AWS cloud boundary box with orange logo",
    "aws_waf":                                              "an orange/red AWS WAF shield icon",
    # ── v2 AWS IAM / Security ─────────────────────────────────────────────────
    "aws_identity_and_access_management":                   "an orange/red AWS IAM shield or key icon",
    "aws_identity_access_management_role":                  "an orange AWS IAM role icon with person",
    "aws_key_management_service":                           "an orange AWS KMS key icon",
    # ── v2 AWS Monitoring / DevOps ────────────────────────────────────────────
    "aws_amazon_cloudwatch":                                "an orange AWS CloudWatch monitoring graph icon",
    "aws_cloudwatch":                                       "an orange AWS CloudWatch icon",
    "aws_cloud_trail":                                      "an orange AWS CloudTrail audit log icon",
    "aws_amazon_api_gateway":                               "a purple/orange AWS API Gateway icon",
    "aws_amazon_elasticache":                               "an orange AWS ElastiCache in-memory store icon",
    "aws_elasticache":                                      "an orange AWS ElastiCache icon",
    "aws_cloudformation":                                   "an orange AWS CloudFormation stack icon",
    "aws_cloudformation_template":                          "an orange AWS CloudFormation template document",
    "aws_backup":                                           "an orange AWS Backup shield with circular arrow",
    # ── v2 Azure Compute ──────────────────────────────────────────────────────
    "azure_virtual_machine":                                "a blue Azure VM virtual machine icon",
    "azure_vm_scale_sets":                                  "blue Azure VM scale set stacked machines icon",
    "azure_app_services":                                   "a blue Azure App Services icon",
    "azure_container_instances":                            "a blue Azure Container Instances cube icon",
    "azure_kubernetes_services":                            "a blue Azure AKS Kubernetes wheel icon",
    "azure_function_apps":                                  "a yellow/blue Azure Function Apps lightning bolt",
    "azure_databricks":                                     "an orange/blue Azure Databricks spark icon",
    # ── v2 Azure Databases ────────────────────────────────────────────────────
    "azure_sql":                                            "a blue Azure SQL database cylinder icon",
    "azure_sql_database":                                   "a blue Azure SQL Database icon",
    "azure_sql_server":                                     "a grey/blue Azure SQL Server icon",
    "azure_sql_managed_instance":                           "a blue Azure SQL Managed Instance icon",
    "azure_cosmos_db":                                      "a blue Azure Cosmos DB planet/sphere icon",
    "azure_synapse_analytics":                              "a blue Azure Synapse Analytics icon",
    # ── v2 Azure Storage / Messaging / Networking ─────────────────────────────
    "azure_storage_accounts":                               "a blue Azure Storage Account with blob/table/queue",
    "azure_event_hubs":                                     "a blue Azure Event Hubs streaming icon",
    "azure_load_balancers":                                 "a blue Azure Load Balancer icon",
    "azure_virtual_networks":                               "a blue Azure Virtual Networks icon",
    "azure_network_security_groups":                        "a blue Azure NSG shield/filter icon",
    "azure_firewalls":                                      "a blue/red Azure Firewall icon",
    # ── v2 Azure IAM / Monitoring / API ───────────────────────────────────────
    "azure_key_vaults":                                     "a blue Azure Key Vault icon with key",
    "azure_monitor":                                        "a blue Azure Monitor graph/chart icon",
    "azure_application_insights":                           "a blue/purple Azure Application Insights lightbulb",
    "azure_api_management_services":                        "a blue Azure API Management gear icon",
    "azure_logic_apps":                                     "a blue Azure Logic Apps workflow icon",
    "azure_data_factories":                                 "a blue Azure Data Factory pipeline icon",
    "azure_machine_learning":                               "a blue Azure Machine Learning icon",
    "azure_machine_learning_studio_workspaces":             "a blue Azure ML Studio workspace icon",
    "azure_openai":                                         "a blue/purple Azure OpenAI icon",
    "azure_devops":                                         "a blue Azure DevOps infinity loop icon",
    "azure_resource_groups":                                "a blue Azure Resource Groups folder icon",
    "azure_services":                                       "a blue Azure generic services icon",
    # ── v2 GCP ────────────────────────────────────────────────────────────────
    "gcp_compute_engine":                                   "a grey/blue GCP Compute Engine server icon",
    "gcp_cloud_run":                                        "a blue GCP Cloud Run container icon",
    "gcp_google_kubernetes_engine":                         "a blue GCP GKE Kubernetes icon",
    "gcp_cloud_functions":                                  "a yellow/orange GCP Cloud Functions lightning bolt",
    "gcp_cloud_sql":                                        "a blue GCP Cloud SQL database cylinder icon",
    "gcp_bigquery":                                         "a blue GCP BigQuery data warehouse icon",
    "gcp_cloud_storage":                                    "a blue GCP Cloud Storage bucket icon",
    "gcp_pubsub":                                           "a blue GCP Pub/Sub messaging icon",
    "gcp_cloud_load_balancing":                             "a blue GCP Cloud Load Balancing icon",
    "gcp_virtual_private_cloud":                            "a blue GCP VPC network boundary icon",
    "gcp_identity_and_access_management":                   "a blue GCP IAM shield/key icon",
    "gcp_vertex_ai":                                        "a blue GCP Vertex AI brain/neural network icon",
    # ── v2 Generic ────────────────────────────────────────────────────────────
    "api":                                                  "an API icon with REST/HTTP or connection arrows",
    "developer_portal":                                     "a developer portal webpage or API docs icon",
    "logic_apps":                                           "a workflow or flowchart icon",
    "microsoft_entra":                                      "a blue Microsoft Entra ID / Azure AD identity icon",
    "resource_group":                                       "a folder or grouping boundary icon",
    "sass_services":                                        "a SaaS cloud service icon",
    "sei/sip":                                              "a SEI/SIP protocol or telephony integration icon",
    "solr":                                                 "an orange Solr search engine circle/sun icon",
}


def _crop_to_base64(img_bgr: np.ndarray, bbox: tuple, padding: int = 10) -> str:
    """Crop bounding box region from image and encode as base64 PNG."""
    h, w = img_bgr.shape[:2]
    x0, y0, x1, y1 = bbox
    x0 = max(0, x0 - padding)
    y0 = max(0, y0 - padding)
    x1 = min(w, x1 + padding)
    y1 = min(h, y1 + padding)
    crop = img_bgr[y0:y1, x0:x1]
    crop_rgb = cv2.cvtColor(crop, cv2.COLOR_BGR2RGB)
    pil = Image.fromarray(crop_rgb)
    buf = io.BytesIO()
    pil.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def _ask_vision(image_b64: str, yolo_class: str,
                class_names: list,
                ollama_url: str = "http://localhost:11434",
                model: str = "llama3.2-vision") -> str:
    """
    Ask the vision LLM to classify a single cropped architecture component.
    Returns the most likely component class name.
    """
    options_with_desc = "\n".join(
        f"  - {cls}: {desc}"
        for cls, desc in COMPONENT_DESCRIPTIONS.items()
    )

    prompt = (
        f"You are analyzing a cropped region from a software architecture diagram.\n"
        f"The region was initially detected as '{yolo_class}' by an object detection model.\n\n"
        f"Look at the image carefully and choose the SINGLE best matching component type from this list:\n"
        f"{options_with_desc}\n\n"
        f"Reply with ONLY the component name (e.g. 'database'), nothing else."
    )

    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "images": [image_b64],
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 20},
    }).encode()

    req = urllib.request.Request(
        f"{ollama_url}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            response_text = json.loads(resp.read())["response"].strip().lower()
            for cls in class_names:
                if cls in response_text:
                    return cls
            for cls in class_names:
                if any(word in response_text for word in cls.split("_")):
                    return cls
            return yolo_class
    except Exception:
        return yolo_class


class HybridDetector:
    """
    YOLOv8 (localization) + Llama-vision (classification) hybrid detector.

    Use this for real AWS/Azure diagrams where synthetic-trained YOLO
    may misclassify icons but still correctly localizes them.
    """

    def __init__(
        self,
        model_path: str = "models/arch_detector/weights/best.pt",
        conf: float = 0.20,
        vision_model: str = "llama3.2-vision",
        ollama_url: str = "http://localhost:11434",
        use_vision: bool = True,
    ):
        self.detector = ArchitectureDetector(model_path=model_path, conf=conf)
        self.vision_model = vision_model
        self.ollama_url = ollama_url
        self.use_vision = use_vision

    def detect(self, image_input) -> DetectionResult:
        # Step 1: YOLO detection (bounding boxes)
        result = self.detector.detect(image_input)

        if not self.use_vision or not result.detections:
            return result

        # Step 2: vision reclassification of each crop
        img_np = result.annotated_image  # BGR
        # reload original (without annotations) for clean crops
        orig = self.detector._load_image(image_input)[1]

        class_names = self.detector._class_names
        class_to_idx = CLASS_TO_IDX_V2 if len(class_names) == len(COMPONENT_CLASSES_V2) else CLASS_TO_IDX

        refined = []
        for det in result.detections:
            crop_b64 = _crop_to_base64(orig, det.bbox)
            new_class = _ask_vision(
                crop_b64, det.class_name,
                class_names=class_names,
                ollama_url=self.ollama_url,
                model=self.vision_model,
            )
            new_id = class_to_idx.get(new_class, det.class_id)
            refined.append(Detection(
                class_id=new_id,
                class_name=new_class,
                confidence=det.confidence,
                bbox=det.bbox,
                center=det.center,
            ))
            if new_class != det.class_name:
                print(f"  [vision] {det.class_name} → {new_class}  (conf={det.confidence:.2f})")

        # rebuild annotated image with corrected labels
        result.detections = refined
        result.annotated_image = self.detector._annotate(orig.copy(), refined)
        return result
