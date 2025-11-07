'use client';

import Navigation from './Navigation';

interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  return (
    <div className="h-screen bg-slate-900 flex overflow-hidden">
      <Navigation />
      <main className="flex-1 overflow-y-auto overflow-x-hidden">
        {children}
      </main>
    </div>
  );
}
