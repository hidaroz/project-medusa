import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import ClientProviders from "../components/ClientProviders";

const inter = Inter({ subsets: ["latin"] });

// Force dynamic rendering for the entire app
export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: "MEDUSA Dashboard",
  description: "AI-Powered Penetration Testing Control Center",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <ClientProviders>
          {children}
        </ClientProviders>
      </body>
    </html>
  );
}

