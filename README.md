# 🔐 PassVault

A zero-knowledge encrypted password manager. Passwords are encrypted in the browser with AES-256-GCM **before** reaching the server — the database only stores ciphertext.

## Stack

- **Backend**: Node.js + Express
- **Database**: Neon (PostgreSQL)
- **Hosting**: Render
- **Encryption**: WebCrypto API (AES-256-GCM, PBKDF2 key derivation)
- **Auth**: bcrypt + JWT (httpOnly cookie)

## Security Model

1. Your **master password** is used client-side to derive an AES-256 encryption key via PBKDF2 (310,000 iterations, SHA-256)
2. Every password, username, and note is **encrypted in the browser** before being sent to the server
3. The server stores only ciphertext — even if the database is compromised, passwords are unreadable without the master password
4. The master password is **never sent to the server** — only used locally for key derivation
5. Sessions use httpOnly + secure + sameSite cookies with JWT

---

## Local Development

### 1. Clone and install
```bash
git clone https://github.com/YOUR_USERNAME/passvault.git
cd passvault
npm install
```

### 2. Set up environment
```bash
cp .env.example .env
# Edit .env and fill in your Neon DB credentials + a JWT_SECRET
```

Generate a JWT secret:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 3. Run
```bash
npm run dev
# Open http://localhost:3000
```

---

## Deploy to Render

### Option A — One-click (render.yaml)
1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → New → Blueprint
3. Connect your GitHub repo — Render reads `render.yaml` automatically
4. In the Render dashboard, set the `PGPASSWORD` environment variable manually (it's marked `sync: false` for security)
5. Deploy!

### Option B — Manual
1. Push to GitHub
2. Render → New Web Service → Connect repo
3. **Build command**: `npm install`
4. **Start command**: `npm start`
5. Add environment variables:
   | Key | Value |
   |-----|-------|
   | `PGHOST` | `ep-lively-band-a1nzyfl0-pooler.ap-southeast-1.aws.neon.tech` |
   | `PGDATABASE` | `neondb` |
   | `PGUSER` | `neondb_owner` |
   | `PGPASSWORD` | *(your Neon password)* |
   | `JWT_SECRET` | *(generate a random 64-char hex string)* |

---

## Database

Tables are created automatically on first start:
- `users` — username + bcrypt password hash
- `vault_entries` — encrypted entries (ciphertext + IV per field)
- `devices` — registered device names per user

---

## Project Structure

```
passvault/
├── server.js          # Express API + DB
├── public/
│   └── index.html     # Full SPA (auth + vault UI)
├── package.json
├── render.yaml        # Render deployment config
├── .env.example       # Environment template
└── .gitignore
```

---

## Features

- ✅ Register / login with username + master password
- ✅ Client-side AES-256-GCM encryption (zero-knowledge)
- ✅ Add, edit, delete vault entries
- ✅ Password generator (length, character sets)
- ✅ Password strength meter
- ✅ Search / filter entries
- ✅ Device management
- ✅ Click-to-reveal + copy buttons
- ✅ Responsive (works on phone + laptop)
- ✅ Deployable to Render with one click
