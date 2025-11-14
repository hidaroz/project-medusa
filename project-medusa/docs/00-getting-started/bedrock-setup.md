# AWS Bedrock Setup Guide for MEDUSA

**Complete guide to configuring AWS Bedrock with MEDUSA CLI**

> **Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → [Getting Started](README.md) → Bedrock Setup

---

## 📋 Overview

AWS Bedrock provides access to Claude 3.5 models (Sonnet and Haiku) through a managed service. MEDUSA automatically optimizes costs using **smart model routing** that switches between models based on task complexity.

### Benefits of AWS Bedrock

- ✅ **Enterprise-grade reliability** - AWS infrastructure
- ✅ **Cost optimization** - Smart routing saves ~60% on costs
- ✅ **Automatic cost tracking** - Per-operation cost reporting
- ✅ **No rate limits** - Higher throughput than API providers
- ✅ **Data privacy** - No training on your data

### Cost Comparison

| Model | Input (per 1M tokens) | Output (per 1M tokens) | Use Case |
|-------|----------------------|------------------------|----------|
| **Claude 3.5 Sonnet** | $3.00 | $15.00 | Complex planning, reporting |
| **Claude 3.5 Haiku** | $0.80 | $4.00 | Tool execution, parsing |

**Typical MEDUSA operation**: $0.20-$0.30 with smart routing (vs. $0.60 with Sonnet only)

---

## 🚀 Quick Start (5 minutes)

### Prerequisites

- AWS Account ([Create one](https://aws.amazon.com/free/))
- AWS CLI installed (`pip install awscli`)
- MEDUSA CLI installed

### Quick Setup

```bash
# 1. Configure AWS credentials
aws configure
# Enter your access key, secret key, and region (us-west-2 recommended)

# 2. Set LLM provider to Bedrock
export LLM_PROVIDER=bedrock

# 3. Verify setup
medusa llm verify

# 4. Run test operation
medusa agent run scanme.nmap.org --type recon_only
```

That's it! For detailed setup, continue reading.

---

## 📖 Detailed Setup Instructions

### Step 1: AWS Account Setup

#### 1.1 Create AWS Account (if you don't have one)

1. Go to [aws.amazon.com](https://aws.amazon.com/)
2. Click "Create an AWS Account"
3. Follow the registration process
4. Add payment method (required for Bedrock)

**Note**: AWS Free Tier does NOT include Bedrock. You'll pay for usage (~$0.20-0.30 per security assessment).

#### 1.2 Enable AWS Bedrock in Your Region

Bedrock is available in these regions:
- `us-east-1` (US East - N. Virginia)
- `us-west-2` (US West - Oregon) **← Recommended**
- `eu-west-1` (Europe - Ireland)
- `ap-southeast-1` (Asia Pacific - Singapore)

**We recommend `us-west-2` for best availability and pricing.**

---

### Step 2: Request Model Access

**You MUST request access to Claude 3.5 models before using them.**

#### Via AWS Console (Easiest)

1. Log in to [AWS Console](https://console.aws.amazon.com/)
2. Navigate to **Bedrock** service
3. In left sidebar, click **Model access**
4. Click **Modify model access**
5. Check the boxes for:
   - ☑️ **Anthropic Claude 3.5 Sonnet**
   - ☑️ **Anthropic Claude 3.5 Haiku**
6. Click **Request model access**

**Access is usually granted instantly** (you'll see status change to "Access granted").

#### Via AWS CLI

```bash
# Request access to Claude 3.5 Sonnet
aws bedrock put-model-invocation-logging-configuration \
  --region us-west-2

# Verify access
aws bedrock list-foundation-models \
  --region us-west-2 \
  --by-provider anthropic
```

---

### Step 3: Create IAM User for MEDUSA

**Security Best Practice**: Create a dedicated IAM user for MEDUSA with minimal permissions.

#### 3.1 Create IAM User

```bash
# Create user
aws iam create-user --user-name medusa-bedrock

# Create IAM policy for Bedrock access
cat > bedrock-policy.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock:ListFoundationModels",
        "bedrock:GetFoundationModel"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Create the policy
aws iam create-policy \
  --policy-name MedusaBedrockAccess \
  --policy-document file://bedrock-policy.json

# Attach policy to user (replace ACCOUNT_ID with your AWS account ID)
aws iam attach-user-policy \
  --user-name medusa-bedrock \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/MedusaBedrockAccess

# Create access key
aws iam create-access-key --user-name medusa-bedrock
```

**Save the Access Key ID and Secret Access Key** - you'll need these for MEDUSA.

#### 3.2 Alternative: Use Existing Admin User

If you already have an AWS user with admin access, you can use those credentials instead. However, a dedicated user with minimal permissions is more secure.

---

### Step 4: Configure MEDUSA

You have **three options** for configuring MEDUSA with AWS Bedrock:

#### Option A: Interactive Setup (Recommended for first-time users)

```bash
medusa setup
```

1. Select **"AWS Bedrock"** when prompted for LLM provider
2. Choose credential configuration method:
   - AWS CLI (recommended)
   - Environment variables
   - Manual entry
3. Enter AWS region when prompted
4. Setup validates your connection automatically

#### Option B: AWS CLI Configuration (Recommended for security)

```bash
# Configure AWS credentials (stored securely in ~/.aws/credentials)
aws configure

# Output:
# AWS Access Key ID [None]: AKIA...
# AWS Secret Access Key [None]: ...
# Default region name [None]: us-west-2
# Default output format [None]: json

# Set MEDUSA to use Bedrock
export LLM_PROVIDER=bedrock

# Verify
medusa llm verify
```

#### Option C: Environment Variables

```bash
# Set AWS credentials
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-west-2

# Set MEDUSA provider
export LLM_PROVIDER=bedrock

# Optional: Customize models
export SMART_MODEL=anthropic.claude-3-5-sonnet-20241022-v2:0
export FAST_MODEL=anthropic.claude-3-5-haiku-20241022-v1:0

# Verify
medusa llm verify
```

#### Option D: Configuration File

Edit `~/.medusa/config.yaml`:

```yaml
llm:
  provider: bedrock
  aws_region: us-west-2
  cloud_model: anthropic.claude-3-5-haiku-20241022-v1:0
  smart_model: anthropic.claude-3-5-sonnet-20241022-v2:0
  fast_model: anthropic.claude-3-5-haiku-20241022-v1:0
  temperature: 0.7
  max_tokens: 2048
  timeout: 60
```

**Then configure AWS credentials separately** using `aws configure` or environment variables.

---

### Step 5: Verify Setup

```bash
medusa llm verify
```

**Expected Output**:
```
🔍 Verifying LLM Configuration...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Provider: AWS Bedrock
✅ Region: us-west-2
✅ Model: anthropic.claude-3-5-haiku-20241022-v1:0
✅ Smart Routing: Enabled
   - Smart Model: anthropic.claude-3-5-sonnet-20241022-v2:0
   - Fast Model: anthropic.claude-3-5-haiku-20241022-v1:0

🔌 Connection Test:
✅ AWS Bedrock connection successful
✅ Model access granted

💰 Cost Information:
  Sonnet: $3/$15 per 1M tokens (input/output)
  Haiku: $0.80/$4 per 1M tokens (input/output)
  Est. savings with smart routing: ~60%

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ AWS Bedrock is ready to use!
```

---

## 🎯 Usage Examples

### Basic Security Assessment

```bash
# Run reconnaissance against legal test target
medusa agent run scanme.nmap.org --type recon_only

# View cost report
medusa agent report
```

**Expected Cost**: $0.05-0.10

### Full Security Assessment

```bash
# Comprehensive assessment with planning
medusa agent run http://testphp.vulnweb.com \
  --type full_assessment \
  --objectives "Find SQL injection, XSS vulnerabilities"

# View detailed report with costs
medusa agent report --detailed
```

**Expected Cost**: $0.20-0.30

### Cost-Optimized Mode

```bash
# Use only Haiku (cheapest) for simple scans
export SMART_MODEL=anthropic.claude-3-5-haiku-20241022-v1:0

medusa agent run scanme.nmap.org --type recon_only
```

**Expected Cost**: $0.02-0.05

---

## 💰 Cost Management

### Understanding Costs

MEDUSA tracks costs in real-time and provides detailed breakdowns:

```bash
# View last operation cost
medusa agent report

# View specific operation
medusa agent report OP-20251114-001

# Export cost data
medusa agent report --export costs.json
```

### Cost Optimization Tips

1. **Use Smart Routing** (Default)
   - Automatically uses Haiku for 60% of tasks
   - Saves ~60% compared to Sonnet-only
   - No configuration needed

2. **Choose Right Operation Type**
   - `recon_only`: ~$0.05-0.10
   - `vuln_scan`: ~$0.10-0.15
   - `full_assessment`: ~$0.20-0.30

3. **Set Cost Limits**
   ```bash
   medusa agent run target.com \
     --max-cost 0.50  # Stop if cost exceeds $0.50
   ```

4. **Use Mock Mode for Testing**
   ```bash
   export LLM_PROVIDER=mock
   medusa agent run target.com  # No API calls, no cost
   ```

### Monthly Cost Estimates

| Usage | Operations/Month | Est. Monthly Cost |
|-------|-----------------|-------------------|
| Light | 10 assessments | $2-3 |
| Medium | 50 assessments | $10-15 |
| Heavy | 100 assessments | $20-30 |
| Enterprise | 500+ assessments | $100-150 |

---

## 🔧 Troubleshooting

### Error: "AccessDeniedException"

**Cause**: Model access not enabled in AWS Bedrock

**Solution**:
1. Go to AWS Console → Bedrock → Model access
2. Request access for Claude 3.5 Sonnet and Haiku
3. Wait for approval (usually instant)
4. Retry `medusa llm verify`

### Error: "Invalid AWS credentials"

**Cause**: Incorrect or expired access keys

**Solution**:
```bash
# Verify credentials work
aws sts get-caller-identity

# If fails, reconfigure
aws configure

# Retry MEDUSA
medusa llm verify
```

### Error: "Region not supported"

**Cause**: Bedrock not available in your region

**Solution**:
```bash
# Use supported region
export AWS_REGION=us-west-2

# Or update config.yaml
# aws_region: us-west-2
```

### Error: "ThrottlingException"

**Cause**: Too many requests to Bedrock API

**Solution**:
- Wait a few seconds and retry
- Bedrock limits: 100K tokens/minute
- MEDUSA automatically retries with exponential backoff

### High Costs

**Symptoms**: Operations costing more than expected

**Diagnosis**:
```bash
# Check if smart routing is enabled
medusa llm verify

# Review recent costs
medusa agent report --detailed
```

**Solution**:
```bash
# Ensure smart routing is enabled
export SMART_MODEL=anthropic.claude-3-5-sonnet-20241022-v2:0
export FAST_MODEL=anthropic.claude-3-5-haiku-20241022-v1:0

# Verify configuration
medusa llm verify
```

---

## 🔒 Security Best Practices

### 1. Never Commit Credentials

```bash
# Add to .gitignore
echo ".env" >> .gitignore
echo "config.yaml" >> .gitignore
```

### 2. Use IAM Roles When Possible

If running MEDUSA on AWS EC2:
```bash
# No credentials needed - use IAM role
# Just set provider
export LLM_PROVIDER=bedrock
```

### 3. Rotate Access Keys Regularly

```bash
# Create new key
aws iam create-access-key --user-name medusa-bedrock

# Update credentials
aws configure

# Delete old key
aws iam delete-access-key \
  --user-name medusa-bedrock \
  --access-key-id OLD_KEY_ID
```

### 4. Use Principle of Least Privilege

Only grant `bedrock:InvokeModel` permission - nothing more.

### 5. Monitor Usage

Set up AWS CloudWatch alerts for unexpected usage:
```bash
# Create billing alert in AWS Console
# Billing → Budgets → Create budget
# Set threshold: $50/month
```

---

## 🆘 Getting Help

### Documentation

- **AWS Bedrock Docs**: [docs.aws.amazon.com/bedrock](https://docs.aws.amazon.com/bedrock/)
- **MEDUSA Architecture**: [docs/01-architecture/](../01-architecture/)
- **Multi-Agent Guide**: [docs/01-architecture/multi-agent-quick-reference.md](../01-architecture/multi-agent-quick-reference.md)

### Support

- **GitHub Issues**: [github.com/your-org/medusa/issues](https://github.com/)
- **AWS Support**: [console.aws.amazon.com/support](https://console.aws.amazon.com/support)

### Community

- Check existing GitHub issues
- Review AWS Bedrock known issues
- Join MEDUSA discussions

---

## ✅ Setup Checklist

Use this checklist to verify your setup:

- [ ] AWS account created
- [ ] Bedrock service accessed in AWS Console
- [ ] Model access enabled for Claude 3.5 Sonnet
- [ ] Model access enabled for Claude 3.5 Haiku
- [ ] IAM user created (or existing user ready)
- [ ] Access key and secret key obtained
- [ ] AWS credentials configured (`aws configure`)
- [ ] `LLM_PROVIDER=bedrock` set
- [ ] `medusa llm verify` passes successfully
- [ ] Test operation completed with cost report
- [ ] Cost tracking verified
- [ ] Smart routing confirmed enabled

---

## 🎓 Next Steps

Once Bedrock is configured:

1. **Run Your First Assessment**
   ```bash
   medusa agent run scanme.nmap.org --type recon_only
   ```

2. **Understand Multi-Agent System**
   - Read: [Multi-Agent Quick Reference](../01-architecture/multi-agent-quick-reference.md)

3. **Optimize Costs**
   - Review cost reports after each operation
   - Adjust operation types based on needs

4. **Learn Advanced Features**
   - Context fusion (vector + graph DB)
   - Custom agent objectives
   - Report generation

---

**Last Updated**: 2025-11-14
**Status**: Production-ready setup guide
**Tested With**: AWS Bedrock, Claude 3.5 Sonnet/Haiku

---

**Navigation**: [Home](../../README.md) → [Docs](../INDEX.md) → [Getting Started](README.md) → Bedrock Setup