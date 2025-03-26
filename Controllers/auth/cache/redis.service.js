const redis = require('redis');
require('dotenv').config();

class RedisService {
  constructor() {
    this.client = redis.createClient({
      url: process.env.REDIS_URL,
      socket: {
        connectTimeout: 5000,
        reconnectStrategy: (retries) => {
          if (retries > 5) return new Error("Max retries reached");
          return 2000;
        },
      },
    });

    this.client.on('error', (err) => console.error('Redis error:', err));
    this.client.on('connect', () => console.log('Connected to Redis'));
    this.client.connect();
  }

  async set(key, value, ttl = 3600) {
    await this.client.setEx(key, ttl, JSON.stringify(value));
  }

  async get(key) {
    const data = await this.client.get(key);
    return data ? JSON.parse(data) : null;
  }

  async del(key) {
    await this.client.del(key);
  }

  async blacklistToken(token, userId, ttl = 7 * 24 * 60 * 60) {
    await this.client.setEx(`blacklist:${token}`, ttl, '1');
    await this.client.set(`invalidate:${userId}`, Date.now());
  }
}

module.exports = new RedisService();