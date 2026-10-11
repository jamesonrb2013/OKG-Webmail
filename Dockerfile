FROM node:24-alpine

RUN apk add --no-cache python3 make g++ sqlite
WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .
ENV NODE_ENV=production
ENV PORT=3000
ENV DATA_DIR=/data
RUN mkdir -p /data && chown -R node:node /app /data

USER node
EXPOSE 3000
CMD ["npm", "start"]