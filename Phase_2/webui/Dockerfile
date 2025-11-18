FROM node:20-alpine AS build
WORKDIR /app
COPY package.json vite.config.js index.html /app/
COPY src /app/src
COPY DarkOps.jsx /app/DarkOps.jsx
RUN npm ci || npm i
# Bake the API base URL at build time; you can override with --build-arg
ARG VITE_CAPI_URL=http://localhost:8001
ENV VITE_CAPI_URL=$VITE_CAPI_URL
RUN npm run build

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
