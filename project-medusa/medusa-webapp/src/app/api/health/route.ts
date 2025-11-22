import { NextResponse } from 'next/server';

/**
 * Health check endpoint for monitoring and load balancers
 * Used by fly.io health checks and Docker healthcheck
 */
export async function GET() {
  return NextResponse.json(
    {
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'medusa-webapp',
      version: process.env.npm_package_version || '1.0.0',
    },
    { status: 200 }
  );
}

