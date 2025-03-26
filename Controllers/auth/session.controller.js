const geoip = require("geoip-lite");
const device = require("device");
const { v4: uuidv4 } = require("uuid");

// Must include this export
exports.createSession = (user, req) => {
  const ip =
    req.ip || req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  const geo = geoip.lookup(ip);
  const deviceInfo = device(req.headers["user-agent"]);

  const session = {
    id: uuidv4(),
    ipAddress: ip,
    location: geo ? `${geo.city}, ${geo.country}` : "Unknown",
    device: `${deviceInfo.type} (${deviceInfo.model})`,
    os: deviceInfo.os,
    browser: deviceInfo.browser,
    lastActive: new Date(),
    createdAt: new Date(),
  };

  user.sessions.push(session);
  return session;
};

// Other methods
exports.logout = async (user) => {
  /*...*/
};
exports.logoutAll = async (user) => {
  /*...*/
};
exports.getSessions = async (user, currentSessionId) => {
  /*...*/
};
exports.terminateSession = async (user, sessionId, currentSessionId) => {
  /*...*/
};
