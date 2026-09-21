import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Aiproxy Compliance",
  description: "Compliance evidence for enterprise AI systems",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="sv">
      <body>{children}</body>
    </html>
  );
}
