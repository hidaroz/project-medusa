'use client';

import { MedusaProvider } from '../contexts/MedusaContext';
import ZombieAlert from './System/ZombieAlert';

/**
 * Client-only wrapper for providers that cannot be serialized during build
 * This prevents Next.js from trying to serialize the context during static generation
 */
export default function ClientProviders({ children }: { children: React.ReactNode }) {
  return (
    <MedusaProvider>
      <ZombieAlert />
      {children}
    </MedusaProvider>
  );
}

