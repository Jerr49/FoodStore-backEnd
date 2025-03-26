const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const validator = require("validator");
const { v4: uuidv4 } = require("uuid");

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      index: true,
      validate: {
        validator: (value) => validator.isEmail(value),
        message: "Invalid email address",
      },
    },
    password: {
      type: String,
      required: true,
      select: false,
      validate: {
        validator: (value) =>
          validator.isStrongPassword(value, {
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1,
          }),
        message:
          "Password must be at least 8 characters long and include at least one lowercase letter, one uppercase letter, one number, and one symbol.",
      },
    },
    role: {
      type: String,
      enum: {
        values: ["user", "admin"],
        message: "Role must be either 'user' or 'admin'",
      },
      default: "user",
    },
    refreshToken: { type: String, select: false, index: true },
    isEmailVerified: { type: Boolean, default: false },
    emailVerificationToken: { type: String, select: false, index: true },
    emailVerificationTokenExpires: { type: Date },
    sessionVersion: {
      type: Number,
      default: 1,
    },
    sessions: [
      {
        _id: false,
        id: { type: String, required: true },
        ipAddress: { type: String, required: true },
        location: { type: String },
        device: { type: String },
        os: { type: String },
        browser: { type: String },
        lastActive: { type: Date, default: Date.now },
        createdAt: { type: Date, default: Date.now },
      },
    ],
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

userSchema.index(
  { emailVerificationTokenExpires: 1 },
  { expireAfterSeconds: 0 }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare hashed password
userSchema.methods.comparePassword = async function (enteredPassword) {
  try {
    return await bcrypt.compare(enteredPassword, this.password);
  } catch (error) {
    throw new Error("Error comparing passwords");
  }
};

// Method to generate email verification token
userSchema.methods.generateEmailVerificationToken = function () {
  this.emailVerificationToken = uuidv4();
  this.emailVerificationTokenExpires = Date.now() + 300000;
};

// Method to invalidate all sessions
userSchema.methods.invalidateAllSessions = async function () {
  this.sessionVersion += 1;
  this.refreshToken = undefined;
  this.sessions = [];
  await this.save();
  return this.sessionVersion;
};

// Method to add a new session
userSchema.methods.addSession = function (req) {
  const ip =
    req.ip || req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  const geo = require("geoip-lite").lookup(ip);
  const deviceInfo = require("device")(req.headers["user-agent"]);

  const session = {
    id: uuidv4(),
    ipAddress: ip,
    location: geo ? `${geo.city}, ${geo.country}` : "Unknown",
    device: `${deviceInfo.type} (${deviceInfo.model})`,
    os: deviceInfo.os,
    browser: deviceInfo.browser,
    lastActive: new Date(),
  };

  this.sessions.push(session);
  return session;
};

// Method to remove a session
userSchema.methods.removeSession = function (sessionId) {
  this.sessions = this.sessions.filter((s) => s.id !== sessionId);
  if (this.sessions.length === 0) {
    this.refreshToken = undefined;
  }
};

userSchema.statics.comparePasswordDirect = async function(candidatePassword, hashedPassword) {
  if (!hashedPassword) {
    throw new Error('No hashed password provided for comparison');
  }
  
  try {
    return await bcrypt.compare(candidatePassword, hashedPassword);
  } catch (error) {
    console.error('Direct password comparison error:', error);
    throw new Error('Error comparing passwords');
  }
};

const User = mongoose.model("User", userSchema);
module.exports = User;
