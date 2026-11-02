# AEGIS IDPS — Cloud License Portal

Next.js + Tailwind CSS + Firebase management dashboard for issuing and managing Aegis IDPS desktop licenses.

## Features
- **Dedicated License Issuance Form**: Auto-generates cryptographically unique 16-character keys (`AEGIS-XXXX-XXXX-XXXX`).
- **Hardware ID (HWID) Locking**: Locks each license to the client's PC hardware fingerprint to prevent sharing.
- **Active Subscription Enforcement**: Real-time expiration calculation with countdown badges (30d, 7d warning, Expired).
- **One-Click Revocation**: Instantly block access for any client machine from anywhere in the world.
- **Vercel & Firebase Native**: Zero server cost using Vercel free tier and Google Firebase Firestore REST API.

---

## 🚀 How to Run Locally

```bash
cd license-portal
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🌐 How to Deploy to Vercel (1-Click Free Hosting)

1. Push this folder to your GitHub repository.
2. Go to [vercel.com](https://vercel.com) and click **"Add New Project"**.
3. Select your repository and choose the `license-portal` directory as the root.
4. (Optional) In **Environment Variables**, add:
   - `NEXT_PUBLIC_FIREBASE_PROJECT_ID` = `your-firebase-project-id`
5. Click **"Deploy"**! Your portal will be live in 60 seconds (e.g. `https://aegis-licenses.vercel.app`).

---

## 📡 API Endpoints for Aegis Desktop App

### 1. Verify / Activate License
`POST /api/licenses/verify`
```json
{
  "licenseKey": "AEGIS-7X9K-8821-M4QP",
  "hardwareId": "4C4C4544-0044-4A10-8043-B2C04F343232",
  "machineHostname": "CLIENT-PC"
}
```

### 2. Response:
```json
{
  "valid": true,
  "status": "active",
  "clientName": "Muhammad Ali",
  "daysRemaining": 30,
  "message": "License active for Muhammad Ali (30 days remaining)"
}
```

