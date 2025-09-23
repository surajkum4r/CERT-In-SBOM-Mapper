# Use official Node.js LTS image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy the rest of the application code
COPY . .

# Expose port (default for many React apps)
EXPOSE 3000

# Start the app (adjust if you use a different start script)
CMD ["npm", "start"]
