const NodeCache = require('node-cache');
const redisService = require('./redis.service');

class CacheService {
  constructor() {
    this.cache = new NodeCache({ stdTTL: 3600 });
  }

  async getUser(email) {
    const cachedUser = this.cache.get(email);
    if (cachedUser) return cachedUser;

    const data = await redisService.get(`u:${email}`);
    if (data) {
      this.cache.set(email, data);
      return data;
    }
    return null;
  }

  async setUser(email, user) {
    this.cache.set(email, user);
    await redisService.set(`u:${email}`, user);
  }

  async clearUser(email) {
    this.cache.del(email);
    await redisService.del(`u:${email}`);
  }
}

module.exports = new CacheService();