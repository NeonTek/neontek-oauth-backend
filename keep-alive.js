const axios = require('axios');

const APP_URL = 'http://localhost:5000';
const PING_INTERVAL = 5 * 60 * 1000;

const pingServer = async () => {
  try {
    const response = await axios.get(APP_URL);
    console.log(`[${new Date().toISOString()}] Ping successful! Status: ${response.status}`);
  } catch (error) {
    console.error(`[${new Date().toISOString()}] Ping failed:`, error.message);
  }
};

console.log('🚀 Keep-alive service started.');
console.log(`Pinging ${APP_URL} every 5 minutes.`);

pingServer();
setInterval(pingServer, PING_INTERVAL);