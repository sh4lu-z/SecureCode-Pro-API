FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

EXPOSE 8000

ENV NODE_OPTIONS="--max-old-space-size=460 --expose-gc"

CMD ["npm", "start"]
