import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Space_Grotesk, Instrument_Sans } from "next/font/google";

import "./globals.css";
import { Toaster } from "@/components/ui/sonner";

const display = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-display",
});

const sans = Instrument_Sans({
  subsets: ["latin"],
  variable: "--font-sans",
});

export const metadata: Metadata = {
  title: "anti-scam.ai",
  description: "Next.js operator console for email risk triage, quarantine review, and link analysis.",
  icons: {
    icon: "/icon.svg",
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className={`${display.variable} ${sans.variable}`}>
        {children}
        <Toaster richColors position="top-right" />
      </body>
    </html>
  );
}
