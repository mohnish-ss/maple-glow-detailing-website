FROM node:20

WORKDIR /ICS4UFinal

COPY package.json .

RUN npm install

COPY . .

EXPOSE 3000

USER node

CMD ["node", "index.js"]
