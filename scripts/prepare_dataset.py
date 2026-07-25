#!/usr/bin/env python3
"""
Convert Pascal VOC XML annotations → YOLO format for the 111-class cloud architecture dataset.
Creates dataset_v2/ with train/val/test splits and data.yaml.

Usage:
    python scripts/prepare_dataset.py
    python scripts/prepare_dataset.py --source ~/Downloads/src/dataset/dataset_augmented --output dataset_v2
"""

import argparse
import random
import xml.etree.ElementTree as ET
from pathlib import Path

# 111 classes sorted alphabetically — must match XML <name> values exactly
COMPONENT_CLASSES_V2 = [
    "api",
    "aws_amazon_api_gateway",
    "aws_amazon_cloudfront",
    "aws_amazon_cloudwatch",
    "aws_amazon_dynamodb",
    "aws_amazon_ec2",
    "aws_amazon_ec2_auto_scaling",
    "aws_amazon_elastic_block_store",
    "aws_amazon_elastic_container_service",
    "aws_amazon_elastic_kubernetes_service",
    "aws_amazon_elasticache",
    "aws_amazon_rds",
    "aws_amazon_redshift",
    "aws_amazon_route_53",
    "aws_amazon_simple_notification_service",
    "aws_amazon_simple_queue_service",
    "aws_amazon_simple_storage_service",
    "aws_amazon_virtual_private_cloud",
    "aws_application_load_balancer",
    "aws_aurora_amazon_rds_instance",
    "aws_auto_scaling",
    "aws_autoscaling",
    "aws_backup",
    "aws_cloud",
    "aws_cloud_trail",
    "aws_cloudformation",
    "aws_cloudformation_template",
    "aws_cloudfront",
    "aws_cloudwatch",
    "aws_dynamodb_table",
    "aws_ec2_instance",
    "aws_ec2_instances",
    "aws_elactic_file_system(nfs)_multi-az",
    "aws_elastic_block_store_volume",
    "aws_elastic_container_service_container_2",
    "aws_elastic_container_service_service",
    "aws_elastic_load_balancing",
    "aws_elastic_load_balancing_application_load_balancer",
    "aws_elastic_load_balancing_network_load_balancer",
    "aws_elasticache",
    "aws_identity_access_management_role",
    "aws_identity_and_access_management",
    "aws_key_management_service",
    "aws_lambda",
    "aws_lambda_lambda_function",
    "aws_private_subnet",
    "aws_public_subnet",
    "aws_rds",
    "aws_region",
    "aws_route_53_hosted_zone",
    "aws_simple_email_service",
    "aws_simple_notification_service_topic",
    "aws_simple_queue_service_queue",
    "aws_simple_storage_service_bucket",
    "aws_simple_storage_service_bucket_with_objects",
    "aws_simple_storage_service_object",
    "aws_simple_storage_service_s3_standard",
    "aws_virtual_private_cloud",
    "aws_vpc_virtual_private_cloud_vpc",
    "aws_waf",
    "azure_api_management_services",
    "azure_app_services",
    "azure_application_insights",
    "azure_container_instances",
    "azure_cosmos_db",
    "azure_data_factories",
    "azure_databricks",
    "azure_devops",
    "azure_event_hubs",
    "azure_firewalls",
    "azure_function_apps",
    "azure_key_vaults",
    "azure_kubernetes_services",
    "azure_load_balancers",
    "azure_logic_apps",
    "azure_machine_learning",
    "azure_machine_learning_studio_workspaces",
    "azure_monitor",
    "azure_network_security_groups",
    "azure_openai",
    "azure_resource_groups",
    "azure_services",
    "azure_sql",
    "azure_sql_database",
    "azure_sql_managed_instance",
    "azure_sql_server",
    "azure_storage_accounts",
    "azure_synapse_analytics",
    "azure_virtual_machine",
    "azure_virtual_networks",
    "azure_vm_scale_sets",
    "developer_portal",
    "gcp_bigquery",
    "gcp_cloud_functions",
    "gcp_cloud_load_balancing",
    "gcp_cloud_run",
    "gcp_cloud_sql",
    "gcp_cloud_storage",
    "gcp_compute_engine",
    "gcp_google_kubernetes_engine",
    "gcp_identity_and_access_management",
    "gcp_pubsub",
    "gcp_vertex_ai",
    "gcp_virtual_private_cloud",
    "logic_apps",
    "microsoft_entra",
    "resource_group",
    "sass_services",
    "sei/sip",
    "solr",
    "user",
]

CLASS_TO_IDX_V2 = {c: i for i, c in enumerate(COMPONENT_CLASSES_V2)}


def parse_xml(xml_path: Path):
    """Return (width, height, [(class_name, xmin, ymin, xmax, ymax)])."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    size = root.find("size")
    w = int(size.find("width").text)
    h = int(size.find("height").text)
    objects = []
    for obj in root.findall("object"):
        name = obj.find("name").text.strip()
        bb = obj.find("bndbox")
        xmin = int(float(bb.find("xmin").text))
        ymin = int(float(bb.find("ymin").text))
        xmax = int(float(bb.find("xmax").text))
        ymax = int(float(bb.find("ymax").text))
        objects.append((name, xmin, ymin, xmax, ymax))
    return w, h, objects


def to_yolo(class_id, xmin, ymin, xmax, ymax, img_w, img_h):
    cx = ((xmin + xmax) / 2) / img_w
    cy = ((ymin + ymax) / 2) / img_h
    bw = (xmax - xmin) / img_w
    bh = (ymax - ymin) / img_h
    return f"{class_id} {cx:.6f} {cy:.6f} {bw:.6f} {bh:.6f}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=str(Path.home() / "Downloads/src/dataset/dataset_augmented"))
    parser.add_argument("--output", default="dataset_v2")
    parser.add_argument("--split", nargs=3, type=float, default=[0.70, 0.15, 0.15],
                        metavar=("TRAIN", "VAL", "TEST"))
    parser.add_argument("--max-images", type=int, default=0,
                        help="Limit total images (0 = use all)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    source = Path(args.source)
    output = Path(args.output)
    train_r, val_r, _ = args.split
    random.seed(args.seed)

    xml_files = sorted(source.glob("*.xml"))
    print(f"Found {len(xml_files)} XML files in {source}")

    valid_pairs, skipped_classes = [], set()
    for xml_path in xml_files:
        img_path = xml_path.with_suffix(".png")
        if not img_path.exists():
            img_path = xml_path.with_suffix(".jpg")
        if not img_path.exists():
            continue
        try:
            w, h, objects = parse_xml(xml_path)
        except Exception as e:
            print(f"[WARN] {xml_path.name}: {e}")
            continue

        lines = []
        for name, xmin, ymin, xmax, ymax in objects:
            if name in CLASS_TO_IDX_V2:
                lines.append(to_yolo(CLASS_TO_IDX_V2[name], xmin, ymin, xmax, ymax, w, h))
            else:
                skipped_classes.add(name)
        if lines:
            valid_pairs.append((img_path, lines))

    print(f"Valid pairs: {len(valid_pairs)}")
    if skipped_classes:
        print(f"Skipped unknown classes: {skipped_classes}")

    random.shuffle(valid_pairs)
    if args.max_images > 0:
        valid_pairs = valid_pairs[:args.max_images]
        print(f"Limiting to {len(valid_pairs)} images (--max-images)")
    n = len(valid_pairs)
    n_train = int(n * train_r)
    n_val = int(n * val_r)
    splits = {
        "train": valid_pairs[:n_train],
        "val":   valid_pairs[n_train:n_train + n_val],
        "test":  valid_pairs[n_train + n_val:],
    }

    for split in splits:
        (output / "images" / split).mkdir(parents=True, exist_ok=True)
        (output / "labels" / split).mkdir(parents=True, exist_ok=True)

    for split, pairs in splits.items():
        for img_path, lines in pairs:
            dst_img = output / "images" / split / img_path.name
            if not dst_img.exists():
                dst_img.symlink_to(img_path.resolve())
            lbl = output / "labels" / split / (img_path.stem + ".txt")
            lbl.write_text("\n".join(lines))
        print(f"  {split}: {len(pairs)} images")

    yaml_lines = [
        f"# STRIDE Architecture Detector v2 — {len(COMPONENT_CLASSES_V2)} cloud service classes",
        f"path: {output.resolve()}",
        "train: images/train",
        "val: images/val",
        "test: images/test",
        "",
        f"nc: {len(COMPONENT_CLASSES_V2)}",
        "names:",
    ] + [f"  - {cls}" for cls in COMPONENT_CLASSES_V2]

    (output / "data.yaml").write_text("\n".join(yaml_lines) + "\n")
    print(f"\nDataset ready at: {output.resolve()}")
    print(f"Classes: {len(COMPONENT_CLASSES_V2)}")


if __name__ == "__main__":
    main()
