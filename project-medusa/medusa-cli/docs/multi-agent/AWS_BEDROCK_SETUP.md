# AWS Bedrock Setup Guide for MEDUSA

## Overview

MEDUSA uses AWS Bedrock to access Claude 3.5 models for AI-powered security analysis. This guide will walk you through the complete setup process.

## Prerequisites

- AWS Account with billing enabled
- AWS CLI installed (optional but recommended)
- Python 3.8+ installed

---

## Step 1: Enable AWS Bedrock Access

### 1.1 Sign in to AWS Console

Go to [AWS Console](https://console.aws.amazon.com/) and sign in.

### 1.2 Navigate to AWS Bedrock

- Search for "Bedrock" in the AWS Console search bar
- Click on "Amazon Bedrock"
- **Important**: Make sure you're in a supported region (us-west-2, us-east-1, or eu-west-3)

### 1.3 Request Model Access

AWS Bedrock requires you to request access to foundation models:

1. In the Bedrock console, click **"Model access"** in the left sidebar
2. Click **"Enable specific models"** or **"Modify model access"**
3. Find and enable:
   - ✅ **Claude 3.5 Sonnet** (anthropic.claude-3-5-sonnet-20241022-v2:0)
   - ✅ **Claude 3.5 Haiku** (anthropic.claude-3-5-haiku-20241022-v1:0)

4. Click **"Request model access"**
5. Review the terms and click **"Submit"**

**⏱️ Access is usually granted instantly**, but can take up to 24 hours for some models.

### 1.4 Verify Model Access

Once approved, you should see:
```
✓ Claude 3.5 Sonnet - Access granted
✓ Claude 3.5 Haiku - Access granted
```

---

## Step 2: Create IAM Credentials

### 2.1 Create IAM User

1. Go to **IAM** in AWS Console
2. Click **"Users"** → **"Create user"**
3. User name: `medusa-bedrock-user`
4. **Do NOT** check "Provide user access to the AWS Management Console"
5. Click **"Next"**

### 2.2 Attach Permissions

You have two options:

#### Option A: Full Bedrock Access (Easiest)

1. Click **"Attach policies directly"**
2. Search for and select:
   - `AmazonBedrockFullAccess`
3. Click **"Next"** → **"Create user"**

#### Option B: Minimal Permissions (Most Secure)

1. Click **"Create policy"**
2. Switch to **JSON** tab
3. Paste this policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "BedrockInvokeModels",
            "Effect": "Allow",
            "Action": [
                "bedrock:InvokeModel",
                "bedrock:InvokeModelWithResponseStream"
            ],
            "Resource": [
                "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0",
                "arn:aws:bedrock:*::foundation-model/anthropic.claude-3-5-haiku-20241022-v1:0"
            ]
        }
    ]
}
```

4. Click **"Next"**
5. Policy name: `MedusaBedrockMinimal`
6. Click **"Create policy"**
7. Go back to user creation and attach this policy

### 2.3 Create Access Keys

1. Click on the created user (`medusa-bedrock-user`)
2. Go to **"Security credentials"** tab
3. Scroll to **"Access keys"**
4. Click **"Create access key"**
5. Choose **"Application running on an AWS compute service"** or **"Local code"**
6. Click **"Next"** → **"Create access key"**

**🔑 Save these credentials immediately:**
```
Access Key ID:     AKIAIOSFODNN7EXAMPLE
Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

⚠️ **You can only view the Secret Access Key once!** Save it securely.

---

## Step 3: Configure MEDUSA

### 3.1 Set Environment Variables

Add these to your shell profile (`~/.bashrc`, `~/.zshrc`, or `~/.bash_profile`):

```bash
# AWS Bedrock Configuration
export AWS_REGION="us-west-2"  # or us-east-1, eu-west-3
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# MEDUSA Model Configuration
export SMART_MODEL="anthropic.claude-3-5-sonnet-20241022-v2:0"
export FAST_MODEL="anthropic.claude-3-5-haiku-20241022-v1:0"
```

**Apply the changes:**
```bash
source ~/.bashrc  # or ~/.zshrc
```

### 3.2 Alternative: AWS Credentials File

Instead of environment variables, you can use AWS credentials file:

```bash
# Configure AWS CLI (will create ~/.aws/credentials)
aws configure
```

Enter:
- **AWS Access Key ID**: Your access key
- **AWS Secret Access Key**: Your secret key
- **Default region**: `us-west-2`
- **Default output format**: `json`

### 3.3 Run MEDUSA Setup

```bash
medusa setup
```

When prompted:
1. **LLM Provider**: Select `AWS Bedrock` (or `bedrock`)
2. **Region**: `us-west-2` (or your chosen region)
3. The setup will use credentials from environment variables or `~/.aws/credentials`

---

## Step 4: Verify Setup

### 4.1 Test Bedrock Connection

```bash
medusa llm verify
```

**Expected output:**
```
┌─ ✓ LLM Connected ──────────────────────┐
│                                        │
│ Provider    bedrock                    │
│ Model       claude-3-5-haiku-*         │
│                                        │
└────────────────────────────────────────┘
```

### 4.2 Test Multi-Agent System

```bash
# Quick test (low cost, ~$0.01)
medusa agent run http://localhost --type recon_only --max-duration 60
```

If successful, you'll see:
```
🤖 Multi-Agent Operation
Target: http://localhost
Type: recon_only

⠋ Running recon_only...

✅ Operation Complete
...
Total Cost: $0.012
```

---

## Troubleshooting

### ❌ "AccessDeniedException"

**Error:**
```
AccessDeniedException: User is not authorized to perform: bedrock:InvokeModel
```

**Solutions:**
1. Verify IAM policy is attached to user
2. Wait 5-10 minutes for IAM changes to propagate
3. Try using `AmazonBedrockFullAccess` policy temporarily

### ❌ "ValidationException: The provided model identifier is invalid"

**Error:**
```
ValidationException: The provided model identifier is invalid
```

**Solutions:**
1. Check model access is granted in Bedrock console
2. Verify model ID is correct:
   - ✅ `anthropic.claude-3-5-sonnet-20241022-v2:0`
   - ✅ `anthropic.claude-3-5-haiku-20241022-v1:0`
3. Ensure you're in a supported region (us-west-2, us-east-1, or eu-west-3)

### ❌ "ThrottlingException: Rate exceeded"

**Error:**
```
ThrottlingException: Rate exceeded
```

**Solutions:**
1. You're making too many requests - wait a few seconds
2. Implement exponential backoff (MEDUSA does this automatically)
3. Request quota increase in AWS Service Quotas console

### ❌ "No credentials found"

**Error:**
```
NoCredentialsError: Unable to locate credentials
```

**Solutions:**
1. Verify environment variables are set:
   ```bash
   echo $AWS_ACCESS_KEY_ID
   echo $AWS_SECRET_ACCESS_KEY
   ```
2. Check `~/.aws/credentials` file exists:
   ```bash
   cat ~/.aws/credentials
   ```
3. Re-run `aws configure`

### ❌ Region not supported

**Error:**
```
EndpointConnectionError: Could not connect to the endpoint URL
```

**Solutions:**
1. Change to a supported region:
   ```bash
   export AWS_REGION="us-west-2"
   ```
2. Supported regions for Bedrock:
   - `us-west-2` (Oregon) - ✅ Recommended
   - `us-east-1` (Virginia)
   - `eu-west-3` (Paris)
   - `ap-northeast-1` (Tokyo)

---

## Cost Management

### Understanding Costs

MEDUSA uses two models with different pricing:

| Model | Input Tokens | Output Tokens | Use Case |
|-------|--------------|---------------|----------|
| **Claude 3.5 Haiku** | $0.80/1M | $4.00/1M | Fast operations (recon, vuln scanning) |
| **Claude 3.5 Sonnet** | $3.00/1M | $15.00/1M | Complex operations (planning, reporting) |

**Typical Operation Costs:**
- Quick scan (recon only): **$0.01 - $0.05**
- Vulnerability assessment: **$0.10 - $0.20**
- Full security test: **$0.30 - $1.00**

### Cost Monitoring

**Check costs after operation:**
```bash
medusa agent status --verbose
```

**Shows:**
```
Agent Performance:
┌───────────────┬───────┬───────────┬───────┐
│ Agent         │ Tasks │ Tokens    │ Cost  │
├───────────────┼───────┼───────────┼───────┤
│ recon         │     3 │     1,200 │ $0.01 │
│ vuln_analysis │     5 │     3,500 │ $0.02 │
│ planning      │     2 │     2,000 │ $0.04 │
└───────────────┴───────┴───────────┴───────┘

Total Cost: $0.08
```

### Set Budget Alerts

In AWS Console:
1. Go to **AWS Budgets**
2. Create a budget for **"Cost budget"**
3. Set threshold (e.g., $10/month)
4. Add email notification

---

## Security Best Practices

### 1. Rotate Access Keys Regularly

```bash
# Every 90 days, create new keys and delete old ones
aws iam create-access-key --user-name medusa-bedrock-user
aws iam delete-access-key --user-name medusa-bedrock-user --access-key-id OLD_KEY_ID
```

### 2. Use IAM Roles (for EC2/ECS)

If running MEDUSA on AWS infrastructure, use IAM roles instead of access keys:

```bash
# No credentials needed - uses instance role
medusa agent run http://example.com
```

### 3. Enable CloudTrail Logging

Monitor all Bedrock API calls:
1. Go to **CloudTrail** in AWS Console
2. Create a trail
3. Enable logging for **Bedrock** service

### 4. Use Environment-Specific Credentials

```bash
# Development
export AWS_PROFILE=medusa-dev

# Production
export AWS_PROFILE=medusa-prod
```

---

## Advanced Configuration

### Multi-Region Setup

Use different regions for redundancy:

```bash
# Primary region
export AWS_REGION="us-west-2"

# Fallback region (if primary is down)
export AWS_FALLBACK_REGION="us-east-1"
```

### Custom Model Selection

Override default models:

```bash
# Use only Haiku (cheapest)
export SMART_MODEL="anthropic.claude-3-5-haiku-20241022-v1:0"
export FAST_MODEL="anthropic.claude-3-5-haiku-20241022-v1:0"

# Use only Sonnet (highest quality)
export SMART_MODEL="anthropic.claude-3-5-sonnet-20241022-v2:0"
export FAST_MODEL="anthropic.claude-3-5-sonnet-20241022-v2:0"
```

### Programmatic Access

```python
from medusa.core.llm import LLMConfig, create_llm_client

config = LLMConfig(
    provider="bedrock",
    aws_region="us-west-2",
    aws_access_key_id="YOUR_KEY",
    aws_secret_access_key="YOUR_SECRET",
    smart_model="anthropic.claude-3-5-sonnet-20241022-v2:0",
    fast_model="anthropic.claude-3-5-haiku-20241022-v1:0"
)

client = create_llm_client(config)
```

---

## Quick Reference

### Environment Variables

```bash
# Required
export AWS_REGION="us-west-2"
export AWS_ACCESS_KEY_ID="YOUR_KEY"
export AWS_SECRET_ACCESS_KEY="YOUR_SECRET"

# Optional
export SMART_MODEL="anthropic.claude-3-5-sonnet-20241022-v2:0"
export FAST_MODEL="anthropic.claude-3-5-haiku-20241022-v1:0"
```

### Essential Commands

```bash
# Verify setup
medusa llm verify

# Run quick test
medusa agent run localhost --type recon_only

# Check costs
medusa agent status --verbose

# Generate report
medusa agent report --type executive
```

### Supported Regions

- ✅ `us-west-2` (Oregon) - **Recommended**
- ✅ `us-east-1` (Virginia)
- ✅ `eu-west-3` (Paris)
- ✅ `ap-northeast-1` (Tokyo)

### Supported Models

- ✅ `anthropic.claude-3-5-sonnet-20241022-v2:0` - Best quality
- ✅ `anthropic.claude-3-5-haiku-20241022-v1:0` - Best value
- ✅ `amazon.titan-text-premier-v1:0` - Alternative

---

## Getting Help

### Documentation
- [User Guide](USER_GUIDE.md)
- [Architecture Guide](ARCHITECTURE.md)
- [API Reference](API_REFERENCE.md)

### AWS Bedrock
- [AWS Bedrock Documentation](https://docs.aws.amazon.com/bedrock/)
- [Claude Model Documentation](https://docs.anthropic.com/claude/docs)
- [AWS Bedrock Pricing](https://aws.amazon.com/bedrock/pricing/)

### Support
- GitHub Issues: [project-medusa/issues](https://github.com/your-org/project-medusa/issues)
- AWS Support: [AWS Console Support](https://console.aws.amazon.com/support/)

---

## Checklist

Before running MEDUSA, ensure:

- ✅ AWS Account created
- ✅ Bedrock model access granted (Claude 3.5 Sonnet & Haiku)
- ✅ IAM user created with Bedrock permissions
- ✅ Access keys created and saved
- ✅ Environment variables set (or AWS credentials file configured)
- ✅ `medusa llm verify` passes
- ✅ Test operation completes successfully

**Ready to go!** 🚀

```bash
medusa agent run http://example.com
```
