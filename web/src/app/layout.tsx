import type { Metadata } from "next";

import "./tokens.css";
import "./globals.css";

export const metadata: Metadata = {
  title: "Argus",
  description: "Network observability platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
