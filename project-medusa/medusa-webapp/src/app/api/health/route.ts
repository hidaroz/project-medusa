// Health check endpoint for Docker health checks
import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json(
    { 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      service: 'medusa-frontend'
    },
    { status: 200 }
  );
}

