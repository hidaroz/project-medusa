# Dataset Configuration for Project Medusa

## Dataset Paths
```python
# In your Python code, reference datasets like this:
DATASET_PATH = "training-data/raw/full_agent_dataset.json"
RECON_DATASET_PATH = "training-data/raw/recon_dataset.json"
```

## Usage Examples

### Loading Training Data
```python
import json
import os

def load_training_dataset():
    """Load the main training dataset from local storage"""
    dataset_path = os.path.join(os.path.dirname(__file__), "..", "training-data", "raw", "full_agent_dataset.json")
    
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")
    
    with open(dataset_path, 'r') as f:
        return json.load(f)
```

### Environment Variables (Alternative)
```bash
# Set in your environment or .env file
export MEDUSA_DATASET_PATH="/path/to/training-data/raw/full_agent_dataset.json"
export MEDUSA_RECON_DATASET_PATH="/path/to/training-data/raw/recon_dataset.json"
```

## Security Reminders
- ✅ This folder is ignored by Git
- ✅ Files here will never be pushed to GitHub
- ✅ Keep your actual datasets secure
- ✅ Only use for authorized security research

## File Structure
```
training-data/
├── README.md                      # Overview
├── CONFIG.md                      # This file - usage instructions
└── raw/                           # Raw JSON datasets (gitignored)
    ├── full_agent_dataset.json    # Complete training dataset
    ├── recon_dataset.json         # Reconnaissance phase
    ├── discovery_dataset.json     # Discovery phase
    ├── lateral_movement_dataset.json
    ├── privilege_esc_dataset.json
    ├── persistence_dataset.json
    ├── defense_evasion_dataset.json
    ├── credential_access_dataset.json
    ├── exe_dataset.json           # Execution phase
    ├── inital_access_dataset.json # Initial access (note: typo in filename)
    └── dataset_template.json      # Template for new datasets
```
