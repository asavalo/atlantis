set -euo pipefail

WEBUI_DIR="/home/asavalo/Phase_2/webui"
STACK_DIR="/home/asavalo/Phase_2/stack"

mkdir -p "$WEBUI_DIR/src"

# 1) If DarkOps.jsx is tiny or missing, create a minimal placeholder
if [ ! -s "$WEBUI_DIR/DarkOps.jsx" ] || [ "$(wc -c < "$WEBUI_DIR/DarkOps.jsx")" -lt 200 ]; then
  cat > "$WEBUI_DIR/DarkOps.jsx" <<'EOF'
import React from "react";
export default function App(){
  const baseUrl = import.meta?.env?.VITE_CAPI_URL || "http://localhost:8001";
  return (
    <div style={{background:"#0a0f14", color:"#d1d5db", minHeight:"100vh", fontFamily:"monospace", padding:"2rem"}}>
      <h1 style={{letterSpacing:"0.15em", textTransform:"uppercase", color:"#7dd3fc"}}>Atlantis-AIxCC Competition Portal</h1>
      <p style={{marginTop:"0.25rem", color:"#94a3b8"}}>A seamless interface for submitting code vulnerability scanning tasks</p>
      <p style={{marginTop:"1rem"}}>UI is alive. API Base: <code>{baseUrl}</code></p>
      <div style={{marginTop:"1rem", fontSize:"12px", color:"#9aa4b2", border:"1px solid #1b2836", padding:"10px", borderRadius:"8px"}}>
        <strong style={{color:"#d1d5db"}}>Unofficial Notice:</strong> This is a user-developed interface and is not affiliated with or endorsed by Atlantis, Team Atlanta, or AIXCC.
      </div>
    </div>
  );
}
EOF
fi

# 2) Minimal Vite+React app files
cat > "$WEBUI_DIR/package.json" <<'EOF'
{
  "name": "capi-ui",
  "private": true,
  "version": "0.0.1",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview --port 5173"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.1",
    "vite": "^5.4.0"
  }
}
EOF

cat > "$WEBUI_DIR/vite.config.js" <<'EOF'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({
  plugins: [react()],
})
EOF

cat > "$WEBUI_DIR/index.html" <<'EOF'
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1.0" />
    <title>Atlantis-AIxCC Competition Portal</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.jsx"></script>
  </body>
</html>
EOF

cat > "$WEBUI_DIR/src/main.jsx" <<'EOF'
import React from 'react'
import { createRoot } from 'react-dom/client'
import App from '../DarkOps.jsx'
createRoot(document.getElementById('root')).render(<App />)
EOF

# 3) Production nginx config
cat > "$WEBUI_DIR/nginx.conf" <<'EOF'
server {
  listen 80;
  server_name _;
  root /usr/share/nginx/html;
  index index.html;

  location / {
    try_files $uri $uri/ /index.html;
  }

  add_header X-Content-Type-Options nosniff;
  add_header X-Frame-Options SAMEORIGIN;
  add_header Referrer-Policy no-referrer-when-downgrade;
}
EOF

# 4) Robust Dockerfile (no npm create vite; uses our files)
cat > "$WEBUI_DIR/Dockerfile" <<'EOF'
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json vite.config.js index.html /app/
COPY src /app/src
COPY DarkOps.jsx /app/DarkOps.jsx
RUN npm ci || npm i
ENV VITE_CAPI_URL=${VITE_CAPI_URL:-http://localhost:8001}
RUN npm run build

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
EOF

# 5) Ensure compose has a single, valid capi-webui service
# Create/replace override file to avoid touching main compose
cat > "$STACK_DIR/capi-webui.override.yaml" <<'EOF'
services:
  capi-webui:
    build:
      context: ../webui
      dockerfile: Dockerfile
      args:
        VITE_CAPI_URL: http://localhost:8001
    ports:
      - "8082:80"
    restart: unless-stopped
EOF

# 6) Build & start container with override
cd "$STACK_DIR"
docker-compose -f compose.yaml -f capi-webui.override.yaml up -d --build capi-webui

echo "-------------------------------------------------------"
echo "WebUI should be up on http://localhost:8082"
echo "cAPI health (host):    curl -s http://localhost:8001/health/"
echo "If 8082 fails, check:  docker-compose -f compose.yaml -f capi-webui.override.yaml logs --tail=200 capi-webui"
