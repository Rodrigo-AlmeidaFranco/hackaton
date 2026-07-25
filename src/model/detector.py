"""
Architecture component detector using a trained YOLOv8 model.
Returns structured detection results for downstream STRIDE analysis.
"""

from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
import cv2
import numpy as np
from PIL import Image
from ultralytics import YOLO

from src.dataset.generator import COMPONENT_CLASSES, COMPONENT_CLASSES_V2


@dataclass
class Detection:
    class_id: int
    class_name: str
    confidence: float
    bbox: tuple  # (x0, y0, x1, y1) in pixels
    center: tuple  # (cx, cy) in pixels


@dataclass
class DetectionResult:
    detections: List[Detection] = field(default_factory=list)
    image_width: int = 0
    image_height: int = 0
    annotated_image: Optional[np.ndarray] = None

    @property
    def component_types(self) -> List[str]:
        return list({d.class_name for d in self.detections})

    @property
    def component_counts(self) -> dict:
        counts = {}
        for d in self.detections:
            counts[d.class_name] = counts.get(d.class_name, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "components": [
                {
                    "type": d.class_name,
                    "confidence": round(d.confidence, 3),
                    "bbox": d.bbox,
                    "center": d.center,
                }
                for d in self.detections
            ],
            "component_types": self.component_types,
            "component_counts": self.component_counts,
        }


class ArchitectureDetector:
    DEFAULT_MODEL = "models/arch_detector/weights/best.pt"
    CONF_THRESHOLD = 0.25
    IOU_THRESHOLD = 0.45

    def __init__(self, model_path: Optional[str] = None, conf: float = CONF_THRESHOLD):
        path = model_path or self.DEFAULT_MODEL
        if not Path(path).exists():
            raise FileNotFoundError(
                f"Model not found at '{path}'. Run train.py first to train the model."
            )
        self.model = YOLO(path)
        self.conf = conf
        nc = len(self.model.names)
        self._class_names = COMPONENT_CLASSES_V2 if nc == len(COMPONENT_CLASSES_V2) else COMPONENT_CLASSES

    def detect(self, image_input) -> DetectionResult:
        """
        Detect architecture components in an image.

        Args:
            image_input: file path (str/Path), PIL Image, or numpy array (BGR)

        Returns:
            DetectionResult with all detected components
        """
        img_pil, img_np = self._load_image(image_input)
        h, w = img_np.shape[:2]

        results = self.model.predict(
            source=img_pil,
            conf=self.conf,
            iou=self.IOU_THRESHOLD,
            verbose=False,
        )

        detections = []
        for r in results:
            if r.boxes is None:
                continue
            for box in r.boxes:
                class_id = int(box.cls[0])
                confidence = float(box.conf[0])
                x0, y0, x1, y1 = map(int, box.xyxy[0].tolist())
                cx = (x0 + x1) // 2
                cy = (y0 + y1) // 2
                detections.append(Detection(
                    class_id=class_id,
                    class_name=self._class_names[class_id] if class_id < len(self._class_names) else f"unknown_{class_id}",
                    confidence=confidence,
                    bbox=(x0, y0, x1, y1),
                    center=(cx, cy),
                ))

        # sort left-to-right so components appear in diagram flow order
        detections.sort(key=lambda d: d.center[0])

        annotated = self._annotate(img_np.copy(), detections)

        return DetectionResult(
            detections=detections,
            image_width=w,
            image_height=h,
            annotated_image=annotated,
        )

    def _load_image(self, image_input):
        if isinstance(image_input, (str, Path)):
            img_pil = Image.open(image_input).convert("RGB")
            img_np = cv2.cvtColor(np.array(img_pil), cv2.COLOR_RGB2BGR)
        elif isinstance(image_input, Image.Image):
            img_pil = image_input.convert("RGB")
            img_np = cv2.cvtColor(np.array(img_pil), cv2.COLOR_RGB2BGR)
        elif isinstance(image_input, np.ndarray):
            img_np = image_input
            img_pil = Image.fromarray(cv2.cvtColor(img_np, cv2.COLOR_BGR2RGB))
        else:
            raise ValueError(f"Unsupported image type: {type(image_input)}")
        return img_pil, img_np

    def _annotate(self, img_np: np.ndarray, detections: List[Detection]) -> np.ndarray:
        """Draw bounding boxes with class labels on the image."""
        color_map = {
            "user":             (74, 144, 217),
            "web_server":       (39, 174, 96),
            "database":         (232, 144, 42),
            "api_gateway":      (155, 89, 182),
            "load_balancer":    (26, 188, 156),
            "cache":            (231, 76, 60),
            "firewall":         (146, 43, 33),
            "cdn":              (41, 128, 185),
            "message_queue":    (243, 156, 18),
            "cloud_service":    (142, 68, 173),
            "mobile_app":       (44, 62, 80),
            "external_service": (127, 140, 141),
        }

        for det in detections:
            x0, y0, x1, y1 = det.bbox
            color = color_map.get(det.class_name, (100, 100, 100))
            cv2.rectangle(img_np, (x0, y0), (x1, y1), color, 2)
            label = f"{det.class_name} {det.confidence:.2f}"
            (tw, th), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.5, 1)
            cv2.rectangle(img_np, (x0, y0 - th - 6), (x0 + tw + 4, y0), color, -1)
            cv2.putText(img_np, label, (x0 + 2, y0 - 4),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
        return img_np
