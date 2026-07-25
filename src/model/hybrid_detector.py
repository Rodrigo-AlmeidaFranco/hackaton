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
from src.dataset.generator import COMPONENT_CLASSES, CLASS_TO_IDX

COMPONENT_DESCRIPTIONS = {
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
            # find exact match in class list
            for cls in COMPONENT_CLASSES:
                if cls in response_text:
                    return cls
            # partial match
            for cls in COMPONENT_CLASSES:
                if any(word in response_text for word in cls.split("_")):
                    return cls
            return yolo_class  # fallback to YOLO prediction
    except Exception:
        return yolo_class  # fallback on any error


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

        refined = []
        for det in result.detections:
            crop_b64 = _crop_to_base64(orig, det.bbox)
            new_class = _ask_vision(
                crop_b64, det.class_name,
                ollama_url=self.ollama_url,
                model=self.vision_model,
            )
            new_id = CLASS_TO_IDX.get(new_class, det.class_id)
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
