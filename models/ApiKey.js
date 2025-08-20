const mongoose = require('mongoose');

const apiKeySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  
  keyHash: { type: String, required: true, unique: true },

  keyPrefix: { type: String, required: true, unique: true },
  
  name: { type: String, required: true },
  
  scopes: { type: [String], default: ['read'] },

  expiresAt: { type: Date, default: null }, 
  lastUsedAt: { type: Date, default: null },
  
  revoked: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('ApiKey', apiKeySchema);