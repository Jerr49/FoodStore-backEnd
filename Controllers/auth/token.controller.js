const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

class TokenController {
  constructor() {
    if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
      throw new Error('JWT secrets must be configured');
    }
  }

  generateAccessToken(user, sessionId) {
    return jwt.sign(
      {
        userId: user._id,
        role: user.role,
        sessionVersion: user.sessionVersion,
        sessionId,
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '15m' }
    );
  }

  generateRefreshToken(user, sessionId) {
    return jwt.sign(
      {
        userId: user._id,
        sessionVersion: user.sessionVersion,
        sessionId,
      },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
    );
  }

  verifyRefreshToken(token) {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
  }

  generateVerificationToken() {
    return {
      token: uuidv4(),
      expires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
    };
  }
}

module.exports = new TokenController();