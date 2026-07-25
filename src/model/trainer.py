"""
YOLOv8 training pipeline for architecture component detection.
"""

import os
from pathlib import Path
from ultralytics import YOLO


def train(
    data_yaml: str = "dataset/data.yaml",
    model_size: str = "n",
    epochs: int = 50,
    img_size: int = 640,
    batch: int = 16,
    output_dir: str = "models",
    project_name: str = "arch_detector",
):
    """
    Train a YOLOv8 model on the architecture diagram dataset.

    Args:
        data_yaml: path to dataset YAML config
        model_size: yolov8 variant - n(ano), s(mall), m(edium), l(arge), x(large)
        epochs: number of training epochs
        img_size: input image size
        batch: batch size
        output_dir: directory to save trained model
        project_name: MLflow/wandb project name
    """
    data_yaml = str(Path(data_yaml).resolve())
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model = YOLO(f"yolov8{model_size}.pt")

    print(f"Training YOLOv8{model_size.upper()} for {epochs} epochs...")
    print(f"Dataset: {data_yaml}")

    results = model.train(
        data=data_yaml,
        epochs=epochs,
        imgsz=img_size,
        batch=batch,
        project=str(output_dir),
        name=project_name,
        exist_ok=True,
        verbose=True,
        plots=True,
        save=True,
        patience=15,
        optimizer="AdamW",
        lr0=0.001,
        lrf=0.01,
        weight_decay=0.0005,
        warmup_epochs=3,
        augment=True,
        mosaic=1.0,
        mixup=0.1,
        degrees=5.0,
        translate=0.1,
        scale=0.3,
        fliplr=0.5,
        flipud=0.0,
    )

    best_model_path = output_dir / project_name / "weights" / "best.pt"
    print(f"\nTraining complete. Best model: {best_model_path}")
    return str(best_model_path), results


def evaluate(model_path: str, data_yaml: str = "dataset/data.yaml", img_size: int = 640):
    """Evaluate a trained model on the test split."""
    model = YOLO(model_path)
    metrics = model.val(data=data_yaml, imgsz=img_size, split="test")
    print(f"mAP50: {metrics.box.map50:.4f}")
    print(f"mAP50-95: {metrics.box.map:.4f}")
    return metrics


if __name__ == "__main__":
    best_path, _ = train()
    evaluate(best_path)
