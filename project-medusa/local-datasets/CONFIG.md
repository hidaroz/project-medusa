# Dataset Configuration for Project Medusa

## Local Dataset Paths
```python
# In your Python code, reference datasets like this:
DATASET_PATH = "local-datasets/dataset.json"
ORGANIZED_DATASET_PATH = "local-datasets/dataset_organized.json"
```

## Usage Examples

### Loading Training Data
```python
import json
import os

def load_training_dataset():
    """Load the main training dataset from local storage"""
    dataset_path = os.path.join(os.path.dirname(__file__), "..", "local-datasets", "dataset.json")
    
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")
    
    with open(dataset_path, 'r') as f:
        return json.load(f)
```

### Environment Variables (Alternative)
```bash
# Set in your environment or .env file
export MEDUSA_DATASET_PATH="/path/to/local-datasets/dataset.json"
export MEDUSA_ORGANIZED_DATASET_PATH="/path/to/local-datasets/dataset_organized.json"
```

## Security Reminders
- ✅ This folder is ignored by Git
- ✅ Files here will never be pushed to GitHub
- ✅ Keep your actual datasets secure
- ✅ Only use for authorized security research

## File Structure
```
local-datasets/
├── README.md                    # This file
├── dataset_template.json        # Template for dataset structure
├── dataset.json                 # Your main dataset (add this)
└── dataset_organized.json       # Your organized dataset (add this)
```
