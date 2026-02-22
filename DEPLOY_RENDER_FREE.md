# Deploy Backend On Render (Free Tier)

## 1. Rotate secrets first
- Change MongoDB password.
- Generate a new strong `JWT_SECRET`.
- Do not reuse values previously shared in chat/screenshots.

## 2. Prepare MongoDB Atlas
- Keep cluster on free tier (M0).
- Create database user/password.
- In Network Access, allow Render egress:
  - quick setup: `0.0.0.0/0` (acceptable for college demo)
  - better: restrict later to known IP ranges.

## 3. Deploy to Render
- Push code to GitHub.
- In Render: `New +` -> `Blueprint`.
- Select repo root (uses `render.yaml`).
- Set all env vars marked `sync: false` in Render dashboard.

## 4. Minimum env vars required
- `MONGO_URI`
- `JWT_SECRET`
- `FRONTEND_URL` (if you have a web frontend)
- `SUPERUSER_EMAIL`
- `SUPERUSER_PASSWORD`

Optional:
- SMTP vars (email/forgot-password features)
- Firebase vars + `firebase-admin-key.json` handling

## 5. Validate deployment
- Open: `https://<your-service>.onrender.com/api/health`
- Open: `https://<your-service>.onrender.com/api/docs`

## 6. Point Flutter app to production API
Use dart-define for release builds:

```bash
flutter build apk --release --dart-define=API_BASE_URL=https://<your-service>.onrender.com
```

For local Android emulator:

```bash
flutter run --dart-define=API_BASE_URL=http://10.0.2.2:5000
```

## Free-tier notes
- Service sleeps when idle; first request can be slow.
- Local disk is ephemeral on free services, so file uploads may not persist.
- For your project, prefer storing video links (already supported) over large file uploads.
