# MEDUSA Web Application

Modern, responsive web dashboard for the MEDUSA (Multi-Environment Dynamic Universal Security Assessment) AI penetration testing system.

## Overview

The MEDUSA webapp is a Next.js 14 application that provides a real-time monitoring and control interface for AI-powered penetration testing operations.

## Features

- **Operations Center**: Monitor and manage active penetration testing operations
- **Real-time Terminal**: Interactive terminal interface with command execution
- **Reports Dashboard**: View and analyze security assessment reports
- **Cost Tracking**: Monitor API usage and costs for AI operations
- **System Status**: Track agent health and zombie detection
- **Settings Management**: Configure API keys and system preferences

## Technology Stack

- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Charts**: Recharts
- **Icons**: Lucide React
- **Animations**: Framer Motion

## Prerequisites

- Node.js 18+
- npm or yarn
- Access to MEDUSA API (locally or deployed)

## Installation

```bash
# Install dependencies
npm install

# Copy environment file
cp .env.example .env.local

# Update the API URL in .env.local
```

## Configuration

### Environment Variables

Create a `.env.local` file:

```bash
# API endpoint for MEDUSA backend
NEXT_PUBLIC_MEDUSA_API_URL=http://localhost:5000

# Or for production
NEXT_PUBLIC_MEDUSA_API_URL=https://your-api-url.fly.dev
```

**Note**: Variables prefixed with `NEXT_PUBLIC_` are embedded in the client-side bundle.

## Development

```bash
# Run development server
npm run dev

# Open browser to http://localhost:3000
```

The development server includes:
- Hot module replacement
- Fast refresh
- TypeScript type checking

## Building

```bash
# Build for production
npm run build

# Start production server
npm start
```

The build creates a standalone Next.js server in `.next/standalone/`.

## Deployment

See [DEPLOYMENT.md](./DEPLOYMENT.md) for detailed deployment instructions to fly.io.

### Quick Deploy

```bash
# Deploy to fly.io
./deploy.sh
```

## Project Structure

```
medusa-webapp/
├── src/
│   ├── app/                  # Next.js App Router pages
│   │   ├── layout.tsx        # Root layout
│   │   ├── page.tsx          # Home page
│   │   ├── globals.css       # Global styles
│   │   └── api/              # API routes
│   │       └── health/       # Health check endpoint
│   ├── components/           # React components
│   │   ├── MedusaDashboard.tsx
│   │   ├── Dashboard.tsx
│   │   ├── Terminal.tsx
│   │   ├── Operations/       # Operations center components
│   │   ├── Reports/          # Reports viewer components
│   │   ├── Cost/             # Cost tracking components
│   │   ├── System/           # System status components
│   │   ├── Charts/           # Chart components
│   │   └── Settings/         # Settings page components
│   ├── contexts/             # React contexts
│   │   └── MedusaContext.tsx # Global state management
│   ├── lib/                  # Utilities
│   │   └── api.ts            # API client
│   └── types/                # TypeScript types
│       └── medusa.ts         # Type definitions
├── public/                   # Static assets
├── Dockerfile.fly            # Production Dockerfile for fly.io
├── fly.toml                  # Fly.io configuration
├── deploy.sh                 # Deployment script
├── DEPLOYMENT.md             # Deployment guide
├── next.config.js            # Next.js configuration
├── tailwind.config.ts        # Tailwind CSS configuration
└── package.json              # Dependencies
```

## Key Components

### MedusaDashboard
Main dashboard container with navigation and tab switching.

### OperationsCenter
Monitor active operations, approve actions, and track progress.

### Terminal
Interactive terminal for executing commands and viewing output.

### ReportsPage
View detailed security assessment reports with findings.

### CostDashboard
Track API costs and usage metrics.

### SystemStatus
Monitor system health, agent status, and zombie detection.

## API Integration

The webapp communicates with the MEDUSA API (FastAPI backend):

```typescript
// Example API call
import { medusaApi } from '@/lib/api';

const operations = await medusaApi.getOperations();
```

API client is configured via `NEXT_PUBLIC_MEDUSA_API_URL`.

## Styling

Uses Tailwind CSS with a dark cybersecurity theme:

- **Primary**: Cyan/blue accents
- **Background**: Dark slate shades
- **Text**: Light gray/white
- **Accents**: Neon cyan, red for alerts

## Performance

- **Standalone mode**: Optimized production bundle
- **Dynamic rendering**: Real-time data updates
- **Component-level code splitting**: Faster page loads
- **Optimized images and fonts**: Next.js automatic optimization

## Browser Support

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)

## Development Tips

### Hot Reload Issues

If hot reload stops working:

```bash
# Clear Next.js cache
rm -rf .next
npm run dev
```

### Type Checking

```bash
# Run TypeScript checks
npx tsc --noEmit
```

### Linting

```bash
# Run ESLint
npm run lint
```

## Troubleshooting

### API Connection Failed

1. Check `NEXT_PUBLIC_MEDUSA_API_URL` is set correctly
2. Verify API is running and accessible
3. Check CORS settings on API

### Build Errors

1. Clear cache: `rm -rf .next node_modules`
2. Reinstall: `npm install`
3. Rebuild: `npm run build`

### Styling Issues

1. Check Tailwind CSS is compiling: Look for `globals.css`
2. Verify PostCSS config: `postcss.config.js`
3. Clear cache and rebuild

## Contributing

This is part of the MEDUSA project. See the main repository for contribution guidelines.

## License

Part of the MEDUSA project - see main repository for license information.

## Related Documentation

- [API Documentation](../medusa-cli/docs/API.md)
- [Deployment Guide](./DEPLOYMENT.md)
- [Project Architecture](../STRUCTURE.md)

## Support

For issues and questions:
- Check existing documentation
- Review logs: `npm run dev` or `flyctl logs`
- Report issues in the main repository

