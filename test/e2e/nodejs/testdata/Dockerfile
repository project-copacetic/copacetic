FROM node:18-alpine

WORKDIR /app

# Copy package files first to leverage Docker layer caching
COPY package*.json ./

# Install dependencies, including the vulnerable lodash version
RUN npm install

# Copy the rest of the application code
COPY . .

EXPOSE 3000

CMD ["node", "index.js"]
