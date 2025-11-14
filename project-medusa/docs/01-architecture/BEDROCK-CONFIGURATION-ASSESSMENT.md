# AWS Bedrock Configuration Assessment

**Date**: 2025-11-14
**Purpose**: Comprehensive assessment of AWS Bedrock API configuration and user experience

---

## 🎯 Executive Summary

**Current State**: AWS Bedrock integration is **technically implemented but user-facing configuration is incomplete**.

**Key Issues**:
1. ❌ Setup wizard doesn't include Bedrock option
2. ❌ No user-facing documentation for Bedrock setup
3. ❌ AWS credentials configuration not guided
4. ⚠️ Config validation doesn't verify AWS credentials work
5. ⚠️ No clear examples or `.env.example` file

**Impact**: Users cannot easily discover or configure AWS Bedrock despite full implementation.

---

## 📊 Detailed Assessment

### 1. Setup Wizard Analysis

**File**: `medusa-cli/src/medusa/config.py`

**Current LLM Provider Options**:
```python
def setup_llm():
    print("\n" + "="*60)
    print("STEP 1: Configure LLM Provider")
    print("="*60)
    print("\nRecommendation: Use local LLM (Ollama) for privacy and zero cost")
    print("\nAvailable options:")
    print("  1. Local (Ollama) - Recommended, free, private")
    print("  2. Cloud (OpenAI/Anthropic) - Requires API key, costs $")
    print("  3. Mock (Testing only)")
```

**Issue**: Bedrock is NOT listed as an option in the interactive setup wizard.

**Current Behavior**:
- Option 2 prompts for "OpenAI/Anthropic" API key
- Saves as generic `cloud_api_key`
- **Does NOT** ask for AWS-specific credentials
- **Does NOT** mention Bedrock at all

**Expected Behavior**:
```python
print("  1. Local (Ollama) - Recommended, free, private")
print("  2. AWS Bedrock (Claude on AWS) - Requires AWS credentials")
print("  3. Cloud (OpenAI/Anthropic) - Requires API key")
print("  4. Mock (Testing only)")
```

---

### 2. Configuration Flow Gaps

#### Gap 1: No Bedrock-Specific Setup Path

**Current**: Setup wizard flow ends at saving generic cloud provider config
**Missing**: Bedrock-specific credential collection

**What Should Happen**:
```python
if choice == "2":  # AWS Bedrock
    print("\n📦 AWS Bedrock Setup")
    print("Bedrock provides Claude 3.5 models with cost tracking.")
    print("\nYou'll need:")
    print("  - AWS Access Key ID")
    print("  - AWS Secret Access Key")
    print("  - AWS Region (default: us-west-2)")
    print("  - Model access enabled in AWS Console")

    access_key = input("AWS Access Key ID: ").strip()
    secret_key = getpass("AWS Secret Access Key: ").strip()
    region = input("AWS Region [us-west-2]: ").strip() or "us-west-2"

    config.llm['provider'] = 'bedrock'
    config.llm['aws_access_key_id'] = access_key
    config.llm['aws_secret_access_key'] = secret_key
    config.llm['aws_region'] = region
```

#### Gap 2: No Credential Validation During Setup

**Current**: No validation that AWS credentials work
**Missing**: Health check during setup

**What Should Happen**:
```python
# After collecting credentials
print("\n🔍 Verifying AWS Bedrock access...")
try:
    bedrock_client = boto3.client(
        'bedrock',
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    models = bedrock_client.list_foundation_models(
        byProvider='anthropic'
    )
    print("✅ AWS Bedrock connection successful!")
    print(f"✅ Found {len(models['modelSummaries'])} Claude models")
except Exception as e:
    print(f"❌ Failed to connect to AWS Bedrock: {e}")
    print("\nPlease verify:")
    print("  1. AWS credentials are correct")
    print("  2. Bedrock is available in your region")
    print("  3. You have model access enabled")
    retry = input("\nRetry setup? (y/n): ")
    if retry.lower() == 'y':
        # Retry flow
```

---

### 3. Documentation Gaps

#### Gap 3: No User-Facing Bedrock Setup Guide

**Current Documentation**:
- ✅ Architecture docs mention Bedrock (`multi-agent-evolution-plan.md`)
- ✅ Quick reference has AWS setup (`multi-agent-quick-reference.md`)
- ❌ No user quickstart guide for Bedrock
- ❌ Not mentioned in main CLI quickstart

**Missing**: `docs/00-getting-started/bedrock-setup.md`

**What Should Exist**:

```markdown
# Setting Up AWS Bedrock for MEDUSA

## Prerequisites

1. **AWS Account** with Bedrock access
2. **IAM User** with Bedrock permissions
3. **Model Access** enabled for Claude 3.5

## Step 1: Enable Bedrock Model Access

1. Go to AWS Console → Bedrock
2. Navigate to "Model access"
3. Request access for:
   - Anthropic Claude 3.5 Sonnet
   - Anthropic Claude 3.5 Haiku
4. Wait for approval (usually instant)

## Step 2: Create IAM User

```bash
# Create IAM user with Bedrock permissions
aws iam create-user --user-name medusa-bedrock

# Attach Bedrock policy
aws iam attach-user-policy \
  --user-name medusa-bedrock \
  --policy-arn arn:aws:iam::aws:policy/AmazonBedrockFullAccess

# Create access key
aws iam create-access-key --user-name medusa-bedrock
```

## Step 3: Configure MEDUSA

### Option A: Interactive Setup
```bash
medusa setup
# Select option 2: AWS Bedrock
# Enter your credentials when prompted
```

### Option B: Environment Variables
```bash
export LLM_PROVIDER=bedrock
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-west-2
```

### Option C: Config File
Edit `~/.medusa/config.yaml`:
```yaml
llm:
  provider: bedrock
  aws_region: us-west-2
  cloud_model: anthropic.claude-3-5-haiku-20241022-v1:0
  smart_model: anthropic.claude-3-5-sonnet-20241022-v2:0
  fast_model: anthropic.claude-3-5-haiku-20241022-v1:0
```

Then set credentials:
```bash
aws configure  # Or set env vars
```

## Step 4: Verify Setup

```bash
medusa llm verify
```

Expected output:
```
✅ AWS Bedrock connection successful
✅ Model: anthropic.claude-3-5-haiku-20241022-v1:0
✅ Region: us-west-2
✅ Smart routing enabled (Sonnet + Haiku)
```

## Cost Optimization

MEDUSA automatically uses smart model routing:
- **Haiku** (cheap) for tool parsing, data extraction
- **Sonnet** (smart) for planning, reporting

This saves ~60% on costs compared to using Sonnet for everything.

## Troubleshooting

### Error: AccessDeniedException
**Solution**: Enable model access in AWS Bedrock console

### Error: Invalid credentials
**Solution**: Verify access key with `aws sts get-caller-identity`

### Error: Region not supported
**Solution**: Bedrock is available in: us-east-1, us-west-2, eu-west-1
```

---

### 4. Missing Files and Examples

#### Gap 4: No `.env.example` File

**Current**: Users don't know what environment variables to set
**Missing**: Template file showing all options

**Should Create**: `medusa-cli/.env.example`

```bash
# MEDUSA CLI Environment Variables

# ============================================================================
# LLM Provider Configuration
# ============================================================================

# Provider: local, bedrock, openai, anthropic, auto
LLM_PROVIDER=bedrock

# ============================================================================
# AWS Bedrock Configuration (if provider=bedrock)
# ============================================================================

# AWS Credentials (required for Bedrock)
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_REGION=us-west-2

# Model Selection (optional - these are defaults)
SMART_MODEL=anthropic.claude-3-5-sonnet-20241022-v2:0
FAST_MODEL=anthropic.claude-3-5-haiku-20241022-v1:0
CLOUD_MODEL=anthropic.claude-3-5-haiku-20241022-v1:0

# ============================================================================
# LLM Generation Parameters
# ============================================================================

LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=2048
LLM_TIMEOUT=60

# ============================================================================
# Local Provider (Ollama) Configuration
# ============================================================================

OLLAMA_URL=http://localhost:11434
LOCAL_MODEL=mistral:7b-instruct

# ============================================================================
# Other Cloud Providers
# ============================================================================

# OpenAI/Anthropic API Key (if provider=openai or anthropic)
# CLOUD_API_KEY=sk-...

# ============================================================================
# Neo4j Graph Database (for World Model)
# ============================================================================

NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password

# ============================================================================
# MEDUSA Configuration
# ============================================================================

# Risk tolerance: low, medium, high
RISK_TOLERANCE=medium

# Auto-approve levels: none, low, medium, high
AUTO_APPROVE_LEVEL=low
```

#### Gap 5: No Config Validation Command

**Current**: `medusa llm verify` exists but might not show detailed info
**Missing**: Clear config validation with helpful error messages

**Should Enhance**: CLI command output

```bash
$ medusa config validate

🔍 Validating MEDUSA Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LLM Provider Configuration:
  ✅ Provider: bedrock
  ✅ AWS Region: us-west-2
  ✅ AWS Credentials: Configured via environment
  ✅ Smart Model: anthropic.claude-3-5-sonnet-20241022-v2:0
  ✅ Fast Model: anthropic.claude-3-5-haiku-20241022-v1:0

Bedrock Connection Test:
  ✅ Authentication successful
  ✅ Model access granted
  ✅ Rate limits: 100K tokens/min

Cost Tracking:
  ✅ Enabled
  ✅ Sonnet: $3/$15 per 1M tokens
  ✅ Haiku: $0.80/$4 per 1M tokens
  ✅ Est. savings: 60% with smart routing

Neo4j Database:
  ✅ Connected to bolt://localhost:7687
  ✅ Version: 5.x

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ All systems operational!
```

---

### 5. Code Implementation Gaps

#### Gap 6: Setup Wizard Doesn't Save AWS Credentials Securely

**Current Issue**: Config file stores credentials in plain text YAML

**Security Risk**: Credentials in `~/.medusa/config.yaml` are not encrypted

**Better Approach**:
1. **Don't store AWS credentials in config file**
2. Guide users to use AWS credential chain:
   - `~/.aws/credentials` (standard AWS location)
   - Environment variables
   - IAM roles

**Updated Setup Flow**:
```python
if choice == "2":  # AWS Bedrock
    print("\n📦 AWS Bedrock Setup")
    print("\n⚠️  Security Best Practice:")
    print("We recommend using AWS CLI to configure credentials securely.")
    print("\nOption 1 (Recommended): AWS CLI")
    print("  Run: aws configure")
    print("  This stores credentials in ~/.aws/credentials")
    print("\nOption 2: Environment Variables")
    print("  Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
    print("\nOption 3: IAM Roles (if running on AWS)")

    choice = input("\nConfigure now with AWS CLI? (y/n): ")
    if choice.lower() == 'y':
        import subprocess
        subprocess.run(['aws', 'configure'])

    # Only save provider choice, not credentials
    config.llm['provider'] = 'bedrock'
    config.llm['aws_region'] = input("AWS Region [us-west-2]: ").strip() or "us-west-2"
```

---

## 🔧 Required Fixes

### Priority 1: Critical (Blocks Users)

1. **Update Setup Wizard** ✅ REQUIRED
   - Add "AWS Bedrock" as option 2
   - Guide AWS credential configuration
   - Validate connection during setup
   - **File**: `medusa-cli/src/medusa/config.py`

2. **Create Bedrock Setup Guide** ✅ REQUIRED
   - User-facing documentation
   - Step-by-step AWS setup
   - Troubleshooting section
   - **File**: `docs/00-getting-started/bedrock-setup.md`

3. **Add .env.example** ✅ REQUIRED
   - Template for environment variables
   - Clear comments for each variable
   - **File**: `medusa-cli/.env.example`

### Priority 2: Important (Improves UX)

4. **Enhance Config Validation** ⚠️ IMPORTANT
   - Better error messages
   - Detailed status output
   - Connection testing
   - **File**: `medusa-cli/src/medusa/cli.py`

5. **Update Main Quickstart** ⚠️ IMPORTANT
   - Mention Bedrock option
   - Link to Bedrock setup guide
   - **File**: `docs/00-getting-started/cli-quickstart.md`

6. **Add Config Command** ⚠️ IMPORTANT
   - `medusa config validate` command
   - `medusa config show` command
   - **File**: `medusa-cli/src/medusa/cli.py`

### Priority 3: Nice to Have

7. **Interactive Credential Helper** 💡 ENHANCEMENT
   - `medusa bedrock setup` dedicated command
   - Interactive AWS configuration
   - Model access verification

8. **Cost Estimation Tool** 💡 ENHANCEMENT
   - `medusa bedrock estimate-cost` command
   - Show pricing for different models
   - Calculate costs for typical operations

---

## 📋 Implementation Checklist

### Phase 1: Core User Experience (2-3 hours)

- [ ] Update `config.py` setup wizard to include Bedrock option
- [ ] Add AWS credential configuration flow
- [ ] Add connection validation during setup
- [ ] Create `.env.example` file with all variables
- [ ] Test setup flow end-to-end

### Phase 2: Documentation (1-2 hours)

- [ ] Create `docs/00-getting-started/bedrock-setup.md`
- [ ] Update `docs/00-getting-started/cli-quickstart.md`
- [ ] Add Bedrock section to main README
- [ ] Create troubleshooting guide

### Phase 3: Enhanced Validation (1-2 hours)

- [ ] Add `medusa config validate` command
- [ ] Improve `medusa llm verify` output
- [ ] Add detailed error messages
- [ ] Test error scenarios

---

## 🎯 Success Criteria

A user should be able to:

1. ✅ Run `medusa setup` and see "AWS Bedrock" as clear option
2. ✅ Be guided through AWS credential configuration
3. ✅ Have their Bedrock connection validated during setup
4. ✅ Find clear documentation on AWS setup requirements
5. ✅ Understand cost implications of Sonnet vs Haiku
6. ✅ Troubleshoot issues with helpful error messages
7. ✅ Verify their configuration with `medusa config validate`

---

## 💰 Cost Transparency

Current implementation has excellent cost tracking, but users need to understand:

### What Users Should Know

1. **Model Costs**:
   - Sonnet: $3 input / $15 output per 1M tokens
   - Haiku: $0.80 input / $4 output per 1M tokens

2. **Smart Routing Savings**:
   - MEDUSA automatically uses Haiku for 60% of tasks
   - Saves ~60% compared to all-Sonnet usage
   - Typical operation: $0.20-$0.30

3. **Cost Visibility**:
   - Every operation shows cost breakdown
   - `medusa agent report` shows per-agent costs
   - Cumulative cost tracking in real-time

### Documentation Should Show

```markdown
## Expected Costs

### Typical Security Assessment

**With Smart Routing** (Default):
- Reconnaissance: 5 Haiku calls = $0.05
- Analysis: 3 Haiku + 1 Sonnet = $0.04
- Planning: 2 Sonnet calls = $0.08
- Reporting: 1 Sonnet call = $0.04
**Total: ~$0.21**

**Without Smart Routing** (All Sonnet):
- Same operation: ~$0.58
**Savings: 64%**

### Monthly Estimates

- 10 assessments/month: ~$2-3
- 50 assessments/month: ~$10-15
- 100 assessments/month: ~$20-30
```

---

## 🚨 Security Considerations

### Current Issues

1. **Plain Text Storage**: Config file stores AWS credentials (if provided)
2. **No Encryption**: Credentials not encrypted at rest
3. **File Permissions**: Config file might not have restricted permissions

### Recommendations

1. **Don't Store AWS Credentials in Config**
   - Use AWS credential chain instead
   - Guide users to `aws configure`
   - Support environment variables

2. **Restrict Config File Permissions**
   ```python
   import os
   config_path = Path.home() / '.medusa' / 'config.yaml'
   os.chmod(config_path, 0o600)  # Owner read/write only
   ```

3. **Add Security Warning**
   ```python
   if config.llm.get('aws_access_key_id'):
       print("⚠️  Warning: AWS credentials in config file")
       print("   Consider using 'aws configure' instead for better security")
   ```

---

## 📊 Current vs. Desired User Experience

### Current Experience

```bash
$ medusa setup

STEP 1: Configure LLM Provider
Available options:
  1. Local (Ollama) - Recommended, free, private
  2. Cloud (OpenAI/Anthropic) - Requires API key
  3. Mock (Testing only)

Choose provider (1-3): 2
Enter API key: [user confused - which key? AWS or OpenAI?]

# Setup completes but Bedrock isn't actually configured
```

### Desired Experience

```bash
$ medusa setup

STEP 1: Configure LLM Provider
Available options:
  1. Local (Ollama) - Recommended, free, private
  2. AWS Bedrock (Claude 3.5 on AWS) - Requires AWS account
  3. Cloud (OpenAI/Anthropic) - Requires API key
  4. Mock (Testing only)

Choose provider (1-4): 2

📦 AWS Bedrock Setup
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Bedrock provides Claude 3.5 models with:
  ✓ Cost tracking and optimization
  ✓ Smart routing (60% cost savings)
  ✓ Enterprise-grade reliability

Prerequisites:
  • AWS account with Bedrock access
  • Model access enabled for Claude 3.5
  • IAM user with Bedrock permissions

Need help? See: docs/00-getting-started/bedrock-setup.md

Configure credentials:
  1. AWS CLI (Recommended) - Run 'aws configure'
  2. Environment variables
  3. Manual entry

Choose method (1-3): 1

Running: aws configure
[AWS CLI configuration flow]

✅ AWS credentials configured!

AWS Region [us-west-2]:
✅ Using region: us-west-2

🔍 Verifying Bedrock access...
✅ Connection successful!
✅ Found 6 Claude models available
✅ Smart routing enabled

Configuration saved to ~/.medusa/config.yaml

Next steps:
  • Verify: medusa llm verify
  • Run test: medusa agent run scanme.nmap.org --type recon_only
  • View costs: medusa agent report
```

---

## 🎬 Conclusion

**Current State**: Implementation is solid, user experience is incomplete

**Root Cause**: Development focused on technical implementation before user-facing setup

**Fix Complexity**: Medium (2-4 hours for core fixes, 4-6 hours for complete implementation)

**Business Impact**: High - Users cannot discover/use Bedrock without reading code

**Recommendation**: **Implement Priority 1 fixes immediately** to unblock users

---

**Last Updated**: 2025-11-14
**Status**: Assessment Complete - Ready for Implementation
**Next Action**: Implement Priority 1 fixes in `config.py` and create setup documentation

---

**Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → [Architecture](README.md) → Bedrock Configuration Assessment