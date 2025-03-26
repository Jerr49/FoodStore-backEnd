const User = require('../../Models/user');
const tokenController = require('./token.controller');
const { createSession } = require('./session.controller'); 
const emailQueue = require('./queues/email.queue');
const cacheService = require('./cache/cache.service');

class AuthController {
  async register(email, password, role) {
    try {
      // Validate email exists and is a string
      if (!email || typeof email !== 'string') {
        throw new Error('Valid email required');
      }

      const normalizedEmail = email.toLowerCase();
      const existingUser = await User.findOne({ email: normalizedEmail })
        .collation({ locale: 'en', strength: 2 });

      if (existingUser) throw new Error('User already exists');

      const newUser = new User({
        email: normalizedEmail,
        password,
        role: role || 'user',
        isEmailVerified: false,
      });

      const { token } = tokenController.generateVerificationToken();
      newUser.emailVerificationToken = token;
      newUser.emailVerificationTokenExpires = Date.now() + 24 * 60 * 60 * 1000;

      await emailQueue.add(normalizedEmail, token);
      await newUser.save();

      return {
        message: 'User registered successfully. Please verify your email.'
      };
    } catch (error) {
      console.error('Registration error:', error);
      throw error;
    }
  }

  async login(req, res) {  // Add res parameter
    try {
        console.log('Login request received:', req.body); // Log incoming request

        // Validate Content-Type
        if (!req.is('application/json')) {
            return res.status(415).json({ error: 'Content-Type must be application/json' });
        }

        const { email, password } = req.body;
        
        if (!email || !password) {
            console.log('Missing credentials');
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const normalizedEmail = email.toLowerCase();
        console.log('Looking for user:', normalizedEmail);
        
        const user = await User.findOne({ email: normalizedEmail })
            .select('+password +refreshToken +sessions +isEmailVerified +sessionVersion');

        if (!user) {
            console.log('User not found');
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await user.comparePassword(password);
        if (!validPassword) {
            console.log('Invalid password');
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        if (!user.isEmailVerified) {
            console.log('Email not verified');
            return res.status(403).json({ error: 'Please verify your email first' });
        }

        console.log('Creating session...');
        const session = createSession(user, req);
        
        const accessToken = tokenController.generateAccessToken(user, session.id);
        const refreshToken = tokenController.generateRefreshToken(user, session.id);

        user.refreshToken = refreshToken;
        await user.save();

        await cacheService.setUser(user.email, {
            _id: user._id,
            email: user.email,
            role: user.role,
            isEmailVerified: user.isEmailVerified,
            sessionVersion: user.sessionVersion,
            sessions: user.sessions,
        });

        console.log('Login successful for:', normalizedEmail);
        return res.status(200).json({
            accessToken,
            refreshToken,
            user: {
                id: user._id,
                email: user.email,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
                currentSessionId: session.id,
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        if (!res.headersSent) {
            return res.status(500).json({ error: 'Internal server error' });
        }
    }
}

  async verifyEmail(token) {
    try {
      if (!token || typeof token !== 'string') {
        throw new Error('Verification token is required');
      }

      const decodedToken = decodeURIComponent(token);
      const user = await User.findOneAndUpdate(
        {
          emailVerificationToken: decodedToken,
          emailVerificationTokenExpires: { $gt: new Date() },
        },
        {
          $set: { isEmailVerified: true },
          $unset: { emailVerificationToken: '', emailVerificationTokenExpires: '' },
        },
        { new: true }
      );

      if (!user) throw new Error('Invalid or expired verification token');

      await cacheService.setUser(user.email, user);
      return { success: true };
    } catch (error) {
      console.error('Email verification error:', error);
      throw error;
    }
  }
}

module.exports = new AuthController();