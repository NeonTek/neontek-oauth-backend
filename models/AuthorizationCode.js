const mongoose = require('mongoose');

const authorizationCodeSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  client: { type: mongoose.Schema.Types.ObjectId, ref: 'Client', required: true },
  redirectUri: { type: String, required: true },
  
  expiresAt: { type: Date, required: true },
  
  // scope: [String],
});

module.exports = mongoose.model('AuthorizationCode', authorizationCodeSchema);