"""
End-to-end training pipeline:
  1. Generate synthetic architecture diagram dataset
  2. Train YOLOv8 model on the dataset
  3. Evaluate on test split
"""

import argparse
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from src.dataset.generator import ArchitectureDiagramGenerator
from src.model.trainer import train, evaluate


def main():
    parser = argparse.ArgumentParser(description="Train STRIDE architecture detector")
    parser.add_argument("--skip-dataset", action="store_true",
                        help="Skip dataset generation (use existing dataset)")
    parser.add_argument("--n-train", type=int, default=300, help="Training images to generate")
    parser.add_argument("--n-val",   type=int, default=60,  help="Validation images to generate")
    parser.add_argument("--n-test",  type=int, default=40,  help="Test images to generate")
    parser.add_argument("--model-size", choices=["n", "s", "m", "l", "x"], default="n",
                        help="YOLOv8 model size (n=nano, s=small, m=medium, ...)")
    parser.add_argument("--epochs",  type=int, default=50,  help="Training epochs")
    parser.add_argument("--batch",   type=int, default=16,  help="Batch size")
    parser.add_argument("--img-size",type=int, default=640, help="Input image size")
    args = parser.parse_args()

    # ── Step 1: Dataset generation ─────────────────────────────────────────────
    if not args.skip_dataset:
        print("=" * 60)
        print("STEP 1: Generating synthetic architecture diagram dataset")
        print("=" * 60)
        gen = ArchitectureDiagramGenerator(output_dir=str(BASE_DIR / "dataset"))
        gen.generate_dataset(
            n_train=args.n_train,
            n_val=args.n_val,
            n_test=args.n_test,
        )
    else:
        print("Skipping dataset generation (--skip-dataset flag set)")

    # ── Step 2: Training ───────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("STEP 2: Training YOLOv8 model")
    print("=" * 60)
    data_yaml = str(BASE_DIR / "dataset" / "data.yaml")
    best_model, results = train(
        data_yaml=data_yaml,
        model_size=args.model_size,
        epochs=args.epochs,
        img_size=args.img_size,
        batch=args.batch,
        output_dir=str(BASE_DIR / "models"),
        project_name="arch_detector",
    )

    # ── Step 3: Evaluation ─────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("STEP 3: Evaluating on test split")
    print("=" * 60)
    evaluate(best_model, data_yaml=data_yaml, img_size=args.img_size)

    print(f"\nDone. Best model saved at: {best_model}")
    print("Run 'streamlit run app.py' to launch the web interface.")


if __name__ == "__main__":
    main()
