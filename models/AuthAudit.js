const mongoose = require('mongoose');

const authAuditSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
  action: { type: String, required: true }, 
  ip: { type: String },
  userAgent: { type: String },
  meta: { type: Object, default: {} }, 
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('AuthAudit', authAuditSchema);
