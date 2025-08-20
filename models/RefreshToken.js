const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  tokenHash: { type: String, required: true, index: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
  createdByIp: { type: String },
  userAgent: { type: String },
  revoked: { type: Boolean, default: false },
  revokedAt: { type: Date },
  revokedByIp: { type: String },
  replacedByTokenId: { type: mongoose.Schema.Types.ObjectId, ref: 'RefreshToken', default: null },
});

refreshTokenSchema.virtual('isExpired').get(function () {
  return Date.now() >= this.expiresAt;
});

refreshTokenSchema.virtual('isActive').get(function () {
  return !this.revoked && !this.isExpired;
});

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);
