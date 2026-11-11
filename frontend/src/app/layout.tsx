import type { Metadata } from "next";
import "./globals.css";
import { AppShell } from "@/components/layout/AppShell";

export const metadata: Metadata = {
  title: "MICHAEL – The Guardian AI",
  description:
    "Intelligent Log Analysis and Anomaly Detection Platform. AI that watches. Intelligence that protects.",
  keywords: ["AI", "cybersecurity", "log analysis", "anomaly detection", "SIEM", "SOC"],
  authors: [{ name: "MICHAEL Guardian AI" }],
  icons: {
    icon: "/michael-logo.png",
    apple: "/michael-logo.png",
  },
  openGraph: {
    title: "MICHAEL – The Guardian AI",
    description: "Intelligence That Watches. AI That Protects.",
    type: "website",
    images: ["/michael-logo.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning data-scroll-behavior="smooth">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          href="https://fonts.googleapis.com/css2?family=Lato:ital,wght@0,300;0,400;0,700;1,300;1,400&family=Playfair+Display:ital,wght@0,600;0,700;1,600;1,700&family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
