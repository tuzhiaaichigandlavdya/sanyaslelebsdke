# Hosting (Railway backend + MilesWeb frontend)

## Backend on Railway

### Deploy
- Create a new Railway project and connect this repo.
- Railway can build from the included `Dockerfile`.

### Persistence (important)
- SQLite needs a persistent disk.
- Create a Railway Volume and mount it at `/data`.
- Set `CHAT_DB_PATH` to `/data/app.db`.

### Required environment variables
- `CHAT_JWT_SECRET`: long random string (keeps logins valid across restarts)
- `CHAT_KEYSYNC_SECRET_B64`: base64 of 32 random bytes (keeps stored keys decryptable)
- `MASTER_CODE`: your master code (example: `X1X2X3`)
- `CHAT_CORS_ORIGINS`: comma-separated origins allowed to call the API
  - Example: `https://YOUR-MILESWEB-DOMAIN.com,http://localhost:8000`

### Railway URL
- After deploy, Railway will provide a public URL like `https://YOURAPP.up.railway.app`.
- Your frontend will use this as `API_BASE`.

## Frontend on MilesWeb

### Upload files
Upload these files to your website root:
- `index.html`
- `sw.js`
- `manifest.webmanifest`
- `icon.svg`
- `config.js`

### Configure API base URL
Edit `config.js` on MilesWeb to point at Railway:

```js
window.SD_CONFIG = {
  API_BASE: "https://YOURAPP.up.railway.app"
}
```

### Notes
- The current frontend references `/icon.svg` and `/manifest.webmanifest`, so it should be hosted at the domain root.
- If you change the path, update those URLs in `index.html`.

