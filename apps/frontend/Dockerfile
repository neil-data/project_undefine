# apps/frontend/Dockerfile

FROM node:20-alpine

WORKDIR /app

COPY apps/frontend/package*.json ./
RUN npm install

COPY apps/frontend ./

EXPOSE 3000

ENV HOST=0.0.0.0
ENV PORT=3000

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]
