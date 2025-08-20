const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const clientSchema = new mongoose.Schema({
  name: { type: String, required: true },

  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },

  clientId: { type: String, default: () => uuidv4(), unique: true },

  clientSecretHash: { type: String, required: true },

  redirectUris: { type: [String], required: true },
  
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Client', clientSchema);