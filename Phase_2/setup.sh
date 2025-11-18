#!/bin/bash

# Initialize the web UI scaffold
echo "Scaffolding Atlantis-AIxCC UI..."

# Create web UI folder and inject component
mkdir -p /home/asavalo/Phase_2/webui
cat > /home/asavalo/Phase_2/webui/DarkOps.jsx <<EOF
# Paste the updated DarkOps UI code here with GP/VD integration
EOF

# Create Dockerfile
cat > /home/asavalo/Phase_2/webui/Dockerfile <<EOF
# Multi-stage build: Vite + Nginx production build
FROM node:20-alpine AS build
WORKDIR /src
COPY DarkOps.jsx /src/DarkOps.jsx
RUN npm create vite@latest capi-ui -- --template react --yes && \
    cd capi-ui && npm i && \
    node -e "const fs=require('fs');fs.writeFileSync('src/App.jsx', fs.readFileSync('/src/DarkOps.jsx','utf8'));" && \
    printf 'VITE_CAPI_URL=%s\n' "${VITE_CAPI_URL:-http://capi:8000}" > capi-ui/.env && \
    npm run build --prefix capi-ui

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/capi-ui/dist /usr/share/nginx/html
EXPOSE 80
EOF

# Create nginx.conf for production
cat > /home/asavalo/Phase_2/webui/nginx.conf <<EOF
server {
  listen 80;
  server_name _;

  root /usr/share/nginx/html;
  index index.html;

  location / {
    try_files $uri $uri/ /index.html;
  }
}
EOF

# Update compose.yaml with the web UI service
cat >> /home/asavalo/Phase_2/stack/compose.yaml <<EOF
  capi-webui:
    build:
      context: ../webui
      dockerfile: Dockerfile
    ports:
      - "8082:80"
    restart: unless-stopped
EOF

# Build and start the app
echo "Building the Docker images..."
docker-compose up -d --build capi-webui
echo "UI is available at http://localhost:8082"
