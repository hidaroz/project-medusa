# MEDUSA Webapp Deployment Guide

This guide covers deploying the MEDUSA webapp to fly.io.

## Prerequisites

### 1. Install flyctl CLI

```bash
# macOS
brew install flyctl

# Linux
curl -L https://fly.io/install.sh | sh

# Windows
pwsh -Command "iwr https://fly.io/install.ps1 -useb | iex"
```

### 2. Create a fly.io Account

Sign up at [https://fly.io](https://fly.io) if you haven't already.

### 3. Login to fly.io

```bash
flyctl auth login
```

## Configuration

### Update API URL

Before deploying, update the API URL in `fly.toml`:

```toml
[build.args]
  NEXT_PUBLIC_MEDUSA_API_URL = 'https://your-api-url.fly.dev'
```

Replace `https://your-api-url.fly.dev` with your actual deployed API URL (e.g., `https://medusa-api-v2.fly.dev`).

### App Name (Optional)

If you want to change the app name, update it in `fly.toml`:

```toml
app = 'your-custom-app-name'
```

**Note:** App names must be unique across all of fly.io.

## Deployment

### Option 1: Using the Deployment Script (Recommended)

The easiest way to deploy is using the provided deployment script:

```bash
cd medusa-webapp
./deploy.sh
```

The script will:
- ✅ Check prerequisites (flyctl installed, logged in)
- ✅ Validate configuration
- ✅ Create the app if it doesn't exist
- ✅ Build and deploy the application
- ✅ Show deployment information and useful commands

### Option 2: Manual Deployment

#### First-time Deployment

1. Create the app:

```bash
flyctl apps create medusa-webapp
```

2. Deploy:

```bash
flyctl deploy --ha=false
```

The `--ha=false` flag deploys a single instance (good for testing/development).

#### Subsequent Deployments

For updates, just run:

```bash
flyctl deploy
```

## Deployment Architecture

### Docker Build Process

The deployment uses a multi-stage Docker build:

1. **deps stage**: Installs dependencies
2. **builder stage**: Builds the Next.js application with standalone output
3. **runner stage**: Creates minimal production image with only necessary files

### Resource Allocation

Default configuration (can be adjusted in `fly.toml`):
- **CPU**: 1 shared vCPU
- **Memory**: 512 MB
- **Instances**: 1 (auto_stop_machines = off, auto_start_machines = true)

### Health Checks

The application includes health checks:
- **Endpoint**: `/api/health`
- **Interval**: 15 seconds
- **Timeout**: 3 seconds
- **Grace Period**: 10 seconds

## Post-Deployment

### Verify Deployment

Check if the app is running:

```bash
flyctl status
```

### View Logs

View real-time logs:

```bash
flyctl logs
```

### Open Application

Open the deployed app in your browser:

```bash
flyctl open
```

Or visit: `https://medusa-webapp.fly.dev` (replace with your app name)

### SSH Access

Access the running container:

```bash
flyctl ssh console
```

## Scaling

### Vertical Scaling (More Resources)

Increase memory:

```bash
flyctl scale memory 1024
```

Increase CPU:

```bash
flyctl scale vm shared-cpu-2x
```

### Horizontal Scaling (More Instances)

Scale to multiple instances:

```bash
flyctl scale count 2
```

Scale by region:

```bash
flyctl scale count 2 --region sjc
flyctl scale count 1 --region iad
```

## Environment Variables

### Build-Time Variables

Set in `fly.toml` under `[build.args]`:
- `NEXT_PUBLIC_MEDUSA_API_URL`: API endpoint URL (embedded in client-side code)

### Runtime Variables

Set in `fly.toml` under `[env]`:
- `NODE_ENV`: Set to 'production'
- `PORT`: Internal port (3000)

### Adding Secrets

For sensitive data, use fly.io secrets:

```bash
flyctl secrets set API_KEY=your-secret-key
```

List secrets:

```bash
flyctl secrets list
```

## Monitoring

### Application Metrics

View metrics in the fly.io dashboard:

```bash
flyctl dashboard
```

Or visit: https://fly.io/dashboard

### Health Check Status

Check health check status:

```bash
flyctl checks list
```

### Resource Usage

Monitor resource usage:

```bash
flyctl status
flyctl vm status
```

## Troubleshooting

### Deployment Fails

1. Check logs:
   ```bash
   flyctl logs
   ```

2. Verify build:
   ```bash
   flyctl deploy --verbose
   ```

3. Check configuration:
   ```bash
   flyctl config validate
   ```

### App Not Responding

1. Check if app is running:
   ```bash
   flyctl status
   ```

2. Check health checks:
   ```bash
   flyctl checks list
   ```

3. Restart app:
   ```bash
   flyctl apps restart
   ```

### Out of Memory Issues

Increase memory allocation:

```bash
flyctl scale memory 1024
```

### API Connection Issues

1. Verify API URL in `fly.toml` is correct
2. Check if API is accessible:
   ```bash
   curl https://your-api-url.fly.dev/api/health
   ```
3. Redeploy with updated configuration:
   ```bash
   flyctl deploy
   ```

### Build Cache Issues

Clear build cache and rebuild:

```bash
flyctl deploy --no-cache
```

## Updating the Application

### Standard Update

1. Make your code changes
2. Commit changes (optional but recommended)
3. Deploy:
   ```bash
   flyctl deploy
   ```

### Rollback

View release history:

```bash
flyctl releases
```

Rollback to a previous version:

```bash
flyctl releases rollback <version>
```

## Cost Management

### Auto-Stop Machines

Enable auto-stop to reduce costs (already disabled in config for availability):

```toml
[http_service]
  auto_stop_machines = 'suspend'  # or 'stop'
```

### Scale Down During Off-Hours

Scale to 0 instances (app will auto-start on request):

```bash
flyctl scale count 0
```

### Monitor Usage

Check resource usage and billing:

```bash
flyctl dashboard
```

Visit: https://fly.io/dashboard/personal/billing

## CI/CD Integration

### GitHub Actions Example

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to Fly.io

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - uses: superfly/flyctl-actions/setup-flyctl@master
      
      - name: Deploy to Fly.io
        run: flyctl deploy --remote-only
        working-directory: ./medusa-webapp
        env:
          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
```

Create a deploy token:

```bash
flyctl auth token
```

Add it to GitHub repository secrets as `FLY_API_TOKEN`.

## Custom Domains

### Add Custom Domain

```bash
flyctl certs create yourdomain.com
```

### Verify DNS

Add these DNS records:

```
A     @    <fly.io IP>
AAAA  @    <fly.io IPv6>
```

Or use CNAME:

```
CNAME  www  medusa-webapp.fly.dev
```

### Check Certificate Status

```bash
flyctl certs show yourdomain.com
```

## Multiple Environments

### Development Environment

Create a separate app for development:

```bash
flyctl apps create medusa-webapp-dev
```

Create `fly.dev.toml` and deploy:

```bash
flyctl deploy -c fly.dev.toml
```

### Staging Environment

Similarly create staging environment:

```bash
flyctl apps create medusa-webapp-staging
```

## Backup and Disaster Recovery

### Configuration Backup

Keep `fly.toml` in version control (it's already tracked in git).

### Application State

The webapp is stateless, so no data backup is needed. All state is managed by the API.

### Quick Recovery

If the app fails completely, redeploy from scratch:

```bash
flyctl deploy --strategy immediate
```

## Security Best Practices

### HTTPS

Fly.io automatically provides HTTPS certificates. Ensure `force_https = true` in `fly.toml`.

### Environment Variables

Never commit secrets to `fly.toml`. Use fly.io secrets instead:

```bash
flyctl secrets set SECRET_KEY=value
```

### Network Security

The webapp is on the public internet. Ensure your API has proper authentication and CORS configuration.

## Additional Resources

- [Fly.io Documentation](https://fly.io/docs/)
- [Next.js Deployment Guide](https://nextjs.org/docs/deployment)
- [Fly.io Pricing](https://fly.io/docs/about/pricing/)
- [Fly.io Status](https://status.flyio.net/)

## Support

### Fly.io Support

- Community Forum: https://community.fly.io/
- Discord: https://fly.io/discord

### MEDUSA Project

- Report issues in the project repository
- Check project documentation in `/docs`

## Quick Reference

```bash
# Deploy
flyctl deploy

# View logs
flyctl logs

# Check status
flyctl status

# Scale
flyctl scale count 2

# Restart
flyctl apps restart

# SSH access
flyctl ssh console

# Open app
flyctl open

# Destroy app
flyctl apps destroy medusa-webapp
```

