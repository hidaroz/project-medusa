'use client';

import Navigation from './Navigation';

interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  return (
    <div className="min-h-screen bg-slate-900 flex">
      <Navigation />
      <main className="flex-1 overflow-y-auto">
        {children}
      </main>
    </div>
  );
}
