"""
Training pipeline v2 — uses the real 111-class AWS/Azure/GCP dataset.

Steps:
  1. Prepare dataset (XML → YOLO conversion)       [scripts/prepare_dataset.py]
  2. Train YOLOv8s on dataset_v2/
  3. Evaluate on test split

Usage:
    # First run (converts dataset and trains):
    python train_v2.py

    # Skip conversion if already done:
    python train_v2.py --skip-prepare

    # Larger model, more epochs:
    python train_v2.py --skip-prepare --model-size m --epochs 100
"""

import argparse
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))


def run_prepare(source: str, output: str):
    print("=" * 60)
    print("STEP 1: Converting XML → YOLO (dataset_v2/)")
    print("=" * 60)
    cmd = [
        sys.executable, str(BASE_DIR / "scripts" / "prepare_dataset.py"),
        "--source", source,
        "--output", output,
    ]
    result = subprocess.run(cmd, check=True)
    return result.returncode == 0


def run_training(data_yaml: str, model_size: str, epochs: int, img_size: int, batch: int):
    from src.model.trainer import train, evaluate

    print("\n" + "=" * 60)
    print("STEP 2: Training YOLOv8 model (v2 — 111 classes)")
    print("=" * 60)

    best_model, results = train(
        data_yaml=data_yaml,
        model_size=model_size,
        epochs=epochs,
        img_size=img_size,
        batch=batch,
        output_dir=str(BASE_DIR / "models"),
        project_name="arch_detector_v2",
    )

    print("\n" + "=" * 60)
    print("STEP 3: Evaluating on test split")
    print("=" * 60)
    evaluate(best_model, data_yaml=data_yaml, img_size=img_size)

    print(f"\nDone. Best model: {best_model}")
    print("Update the model path in the Streamlit sidebar to use this model.")
    return best_model


def main():
    parser = argparse.ArgumentParser(description="Train STRIDE detector v2 (111 cloud classes)")
    parser.add_argument("--skip-prepare", action="store_true",
                        help="Skip XML→YOLO conversion (dataset_v2/ already exists)")
    parser.add_argument("--source", default=str(Path.home() / "Downloads/src/dataset/dataset_augmented"),
                        help="Path to Pascal VOC XML+PNG dataset")
    parser.add_argument("--dataset-dir", default="dataset_v2",
                        help="Output directory for converted YOLO dataset")
    parser.add_argument("--model-size", choices=["n", "s", "m", "l", "x"], default="s",
                        help="YOLOv8 model size (default: s — recommended for 111 classes)")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch", type=int, default=16)
    parser.add_argument("--img-size", type=int, default=640)
    args = parser.parse_args()

    dataset_dir = BASE_DIR / args.dataset_dir
    data_yaml = str(dataset_dir / "data.yaml")

    if not args.skip_prepare:
        run_prepare(args.source, str(dataset_dir))
    else:
        print("Skipping dataset preparation (--skip-prepare)")

    if not Path(data_yaml).exists():
        print(f"[ERROR] data.yaml not found at {data_yaml}. Run without --skip-prepare first.")
        sys.exit(1)

    run_training(data_yaml, args.model_size, args.epochs, args.img_size, args.batch)


if __name__ == "__main__":
    main()
