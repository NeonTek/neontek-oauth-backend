const { hashToken } = require('../utils/crypto');
const ApiKey = require('../models/ApiKey');
const User = require('../models/User');

module.exports = async function (req, res, next) {
  const keyHeader = req.headers['x-api-key'];

  if (!keyHeader) {
    return res.status(401).json({ message: 'Missing API Key. Provide it in the X-API-Key header.' });
  }
  
  const key = keyHeader.replace(/^neonk_/, '');
  const keyHash = hashToken(key);

  try {
    const apiKeyDoc = await ApiKey.findOne({ keyHash, revoked: false });

    if (!apiKeyDoc) {
      return res.status(401).json({ message: 'Invalid API Key.' });
    }
    
    // Check for expiration
    if (apiKeyDoc.expiresAt && apiKeyDoc.expiresAt < new Date()) {
      return res.status(401).json({ message: 'API Key has expired.' });
    }
    
    const user = await User.findById(apiKeyDoc.user).select('-passwordHash').lean();

    if (!user) {
      return res.status(401).json({ message: 'User associated with this key no longer exists.' });
    }
    
    req.user = { 
      sub: user._id.toString(),
      email: user.email,
      roles: user.roles,
    };
    req.auth = { type: 'api-key', scopes: apiKeyDoc.scopes };
    
    apiKeyDoc.lastUsedAt = new Date();
    apiKeyDoc.save();

    next();
  } catch (err) {
    next(err);
  }
};