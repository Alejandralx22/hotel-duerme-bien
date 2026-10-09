FROM node:22-alpine
WORKDIR /app
COPY package.json server.js ./
COPY src ./src
COPY public ./public
RUN mkdir -p /data && chown -R node:node /data /app
USER node
ENV NODE_ENV=production PORT=3000 DB_FILE=/data/hotel.db
EXPOSE 3000
HEALTHCHECK CMD wget -qO- http://localhost:3000/api/health || exit 1
CMD ["node", "--no-warnings", "server.js"]
