FROM node:20-slim

ENV NODE_ENV=production

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

COPY --chown=node:node . .

EXPOSE 3000

USER node

CMD ["npm", "start"]
