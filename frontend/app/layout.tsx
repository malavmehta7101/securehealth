import "./globals.css";

export const metadata = { title: "SecureHealth", description: "Secure patient records portal" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
