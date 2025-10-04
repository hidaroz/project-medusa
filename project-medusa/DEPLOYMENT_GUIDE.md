# GitHub Pages Deployment Guide for Medusa Webapp

## Overview
This guide will help you deploy the Medusa webapp to GitHub Pages using GitHub Actions for automatic deployment.

## Prerequisites
- GitHub repository (public or private with GitHub Pages enabled)
- Node.js 18+ installed locally
- Git configured

## Deployment Steps

### 1. Repository Setup

1. **Create a new GitHub repository** or use an existing one
2. **Push your code** to the repository:
   ```bash
   git init
   git add .
   git commit -m "Initial commit with GitHub Pages deployment setup"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
   git push -u origin main
   ```

### 2. Enable GitHub Pages

1. Go to your repository on GitHub
2. Navigate to **Settings** → **Pages**
3. Under **Source**, select **GitHub Actions**
4. The workflow will automatically deploy when you push to the main branch

### 3. Configure Repository Settings

The deployment is already configured with the following files:

- **`.github/workflows/deploy.yml`** - GitHub Actions workflow for automatic deployment
- **`next.config.ts`** - Next.js configuration for static export
- **`package.json`** - Updated with deployment scripts
- **`public/.nojekyll`** - Prevents Jekyll processing

### 4. Custom Domain (Optional)

If you want to use a custom domain:

1. Create a `CNAME` file in the `public` directory:
   ```bash
   echo "your-domain.com" > medusa-webapp/public/CNAME
   ```
2. Configure your domain's DNS to point to GitHub Pages
3. Enable HTTPS in GitHub Pages settings

### 5. Manual Deployment (Alternative)

If you prefer manual deployment:

```bash
cd medusa-webapp
npm run build
# The 'out' directory contains your static files
# Upload the contents of 'out' to your web server
```

## Configuration Details

### Next.js Configuration
The `next.config.ts` file is configured for GitHub Pages:
- `output: 'export'` - Enables static export
- `trailingSlash: true` - Adds trailing slashes to URLs
- `images: { unoptimized: true }` - Disables image optimization for static export
- `basePath` and `assetPrefix` - Configured for GitHub Pages subdirectory

### GitHub Actions Workflow
The workflow (`deploy.yml`) includes:
- Node.js 18 setup
- Dependency installation
- Build process
- Automatic deployment to GitHub Pages

### Static Generation
- All pages are pre-rendered at build time
- Dynamic routes use `generateStaticParams()` for static generation
- Patient pages are generated for all mock patients (P001-P005)

## Testing Locally

Test the static export locally:

```bash
cd medusa-webapp
npm run build
# Serve the static files
npx serve out
# Visit http://localhost:3000
```

## Troubleshooting

### Common Issues

1. **Build fails with dynamic routes**
   - Ensure all dynamic routes have `generateStaticParams()`
   - Check that the function returns the correct parameter structure

2. **Assets not loading**
   - Verify `basePath` and `assetPrefix` in `next.config.ts`
   - Check that `.nojekyll` file exists in the output

3. **GitHub Actions fails**
   - Check repository permissions
   - Ensure GitHub Pages is enabled in repository settings
   - Verify the workflow file is in `.github/workflows/`

### Build Output
The build creates an `out` directory with:
- Static HTML files
- Optimized JavaScript and CSS
- Static assets
- `.nojekyll` file for GitHub Pages compatibility

## Security Considerations

⚠️ **Important Security Notes:**

- This is a **mock EHR system** for security research
- No real patient data or backend systems
- All data is static and pre-generated
- Safe for public deployment as a demonstration

## Deployment URL

Once deployed, your webapp will be available at:
- `https://YOUR_USERNAME.github.io/YOUR_REPO_NAME/`
- Or your custom domain if configured

## Next Steps

After successful deployment:
1. Test all functionality on the live site
2. Verify patient pages load correctly
3. Check responsive design on mobile devices
4. Monitor GitHub Actions for any deployment issues

---

**Project Medusa** - AI Adversary Simulation Platform
