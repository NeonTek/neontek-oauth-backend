const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: false },

  googleId: { type: String, unique: true, sparse: true },

  // name fields
  name: { type: String, default: '' },
  givenName: { type: String, default: '' },
  familyName: { type: String, default: '' },

  // profile
  profilePicture: { type: String, default: null },
  phoneNumber: { type: String, default: null },
  phoneVerified: { type: Boolean, default: false },

  // personal
  gender: { type: String, enum: ['male', 'female', 'other', 'prefer_not_to_say'], default: 'prefer_not_to_say' },
  birthday: { type: Date, default: null },

  // locale / preferences
  language: { type: String, default: 'en' },
  country: { type: String, default: '' },
  timezone: { type: String, default: '' },

  // email verification fields
  emailVerified: { type: Boolean, default: false },
  emailVerificationTokenHash: { type: String, default: null },
  emailVerificationExpiresAt: { type: Date, default: null },

  // magic link
  magicLinkTokenHash: { type: String, default: null },
  magicLinkExpiresAt: { type: Date, default: null },

  // 2FA
  twoFactorSecret: { type: String, default: null },
  twoFactorEnabled: { type: Boolean, default: false },

  // roles & auditing
  roles: { type: [String], default: ['user'] },
  lastLoginAt: { type: Date },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// update timestamp on save
userSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('User', userSchema);