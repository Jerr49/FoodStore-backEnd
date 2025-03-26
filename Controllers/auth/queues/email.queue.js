const Queue = require('bull');
const { sendVerificationEmail } = require('../../../Utils/email');
require('dotenv').config();

class EmailQueue {
  constructor() {
    this.queue = new Queue('email', {
      redis: process.env.REDIS_URL || 'redis://localhost:6379',
    });

    this.queue.process(5, async (job) => {
      const { email, token } = job.data;
      await sendVerificationEmail(email, token);
    });

    this.queue.on('error', (err) => console.error('Bull queue error:', err));
    this.queue.on('completed', (job) => console.log(`Job ${job.id} completed`));
  }

  add(email, token) {
    return this.queue.add({ email, token });
  }
}

module.exports = new EmailQueue();