const { authLimiter, sensitiveActionLimiter } = require('./middleware/rateLimit');
const compression = require('compression');
const { verifyToken } = require('./middleware/auth.middleware');

// Controller imports - ADD createSession to the destructuring
const auth = require('./auth.controller');
const tokenController = require('./token.controller'); 
const {
  logout,
  logoutAll,
  getSessions,
  terminateSession,
  createSession // ADD THIS IMPORT
} = require('./session.controller');

// Create middleware instances
const compressionMiddleware = compression();

// Enhanced adapter that handles createSession differently
const adaptSessionMethod = (method, methodName) => {
  return async (req, res, next) => {
    try {
      const user = req.user || req.body;
      let result;
      
      if (methodName === 'terminateSession') {
        result = await terminateSession(user, req.params.sessionId, req.session.id);
      } else if (methodName === 'getSessions') {
        result = await getSessions(user, req.session.id);
      } else if (methodName === 'createSession') {
        // createSession needs the request object
        result = await createSession(user, req);
      } else {
        result = await method(user, req);
      }

      if (!res.headersSent) {
        result !== undefined ? res.json(result) : res.sendStatus(200);
      }
    } catch (error) {
      next(error);
    }
  };
};

module.exports = {
  controllers: {
    auth,
    token: {
      refreshToken: (req, res, next) => {
        try {
          const refreshToken = tokenController.generateRefreshToken(req.user, req.session.id);
          res.json({ refreshToken });
        } catch (error) {
          next(error);
        }
      }
    },
    session: {
      logout: adaptSessionMethod(logout, 'logout'),
      logoutAll: adaptSessionMethod(logoutAll, 'logoutAll'),
      getSessions: adaptSessionMethod(getSessions, 'getSessions'),
      terminateSession: adaptSessionMethod(terminateSession, 'terminateSession'),
      createSession: adaptSessionMethod(createSession, 'createSession') // Add this
    }
  },
  
  middleware: {
    authLimiter,
    sensitiveActionLimiter,
    compression: compressionMiddleware,
    verifyToken
  },
  
  routes: {
    register: [
      authLimiter,
      compressionMiddleware,
      auth.register
    ],
    login: [
      authLimiter,
      compressionMiddleware,
      auth.login
    ],
    logout: [
      compressionMiddleware,
      verifyToken,
      adaptSessionMethod(logout, 'logout')
    ],
    logoutAll: [
      sensitiveActionLimiter,
      compressionMiddleware,
      verifyToken,
      adaptSessionMethod(logoutAll, 'logoutAll')
    ],
    getSessions: [
      compressionMiddleware,
      verifyToken,
      adaptSessionMethod(getSessions, 'getSessions')
    ],
    terminateSession: [
      compressionMiddleware,
      verifyToken,
      adaptSessionMethod(terminateSession, 'terminateSession')
    ]
  }
};