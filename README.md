# AegisShare

A self-hosted, zero-knowledge paste and file sharing app. Text and attachments are encrypted in the browser with AES-256-GCM before the encrypted payload is stored in SQLite. The decryption key stays in the URL fragment and is never sent to the server.

## Getting Started

Install dependencies and run the LAN-accessible development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3080](http://localhost:3080). The server binds to `0.0.0.0` so another device on the same network can use the generated QR code.

The SQLite database is created at `data/aegisshare.db` on first use. Keep the `data` directory private.

## Features

- Client-side AES-256-GCM encryption
- Optional PBKDF2 password protection
- Text, Markdown preview, and attachments up to 10 MB
- Burn-on-read or timed expiration
- Deletion links and LAN-friendly QR codes

## Production

```bash
npm run build
npm run start
```

The main UI is in `src/app/page.tsx`; API routes live under `src/app/api`.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
