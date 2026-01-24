#!/bin/bash

echo "================================"
echo "ML Model Setup and Training"
echo "================================"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    exit 1
fi

echo "✓ Python version: $(python3 --version)"

# Create virtual environment
echo ""
echo "Creating virtual environment..."
python3 -m venv ml_env

# Activate virtual environment
echo "Activating virtual environment..."
source ml_env/bin/activate

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo ""
echo "Installing required packages..."
pip install -r requirements.txt

# Run the training script
echo ""
echo "================================"
echo "Running ML model training..."
echo "================================"
python train_robust_model.py

# Deactivate virtual environment
deactivate

echo ""
echo "================================"
echo "Done! Check the output above."
echo "Model saved to: best_model_no_leakage.pkl"
echo "================================"
