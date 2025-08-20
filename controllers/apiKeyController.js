const crypto = require('crypto');
const ApiKey = require('../models/ApiKey');
const { hashToken } = require('../utils/crypto'); 

function generateApiKey() {
  const key = crypto.randomBytes(32).toString('hex');
  const prefix = key.slice(0, 8);
  return { key, prefix };
}


exports.createApiKey = async (req, res, next) => {
  try {
    const userId = req.user.sub;
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({ message: 'A name for the key is required.' });
    }

    const { key, prefix } = generateApiKey();
    const keyHash = hashToken(key);

    const newApiKey = await ApiKey.create({
      user: userId,
      name,
      keyHash,
      keyPrefix: prefix,
      // logic for scopes
    });

    res.status(201).json({
      message: 'API Key created successfully. Please save this key securely; you will not be able to see it again.',
      apiKey: `neonk_${key}`, 
      keyDetails: {
        id: newApiKey._id,
        name: newApiKey.name,
        prefix: newApiKey.keyPrefix,
        createdAt: newApiKey.createdAt,
      },
    });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /api/keys
 * List all active API keys for the authenticated user
 */
exports.listApiKeys = async (req, res, next) => {
  try {
    const userId = req.user.sub;
    const keys = await ApiKey.find({ user: userId, revoked: false })
      .select('-keyHash') // Exclude the hash from the response
      .lean();
      
    res.json({ keys });
  } catch (err) {
    next(err);
  }
};

/**
 * DELETE /api/keys/:id
 * Revoke (delete) an API key
 */
exports.revokeApiKey = async (req, res, next) => {
  try {
    const userId = req.user.sub;
    const { id } = req.params;

    const key = await ApiKey.findOne({ _id: id, user: userId });

    if (!key) {
      return res.status(404).json({ message: 'API Key not found or you do not have permission to revoke it.' });
    }

    key.revoked = true;
    await key.save();
    //hard delete
    // await ApiKey.deleteOne({ _id: id, user: userId });
    
    res.status(200).json({ message: 'API Key revoked successfully.' });
  } catch (err) {
    next(err);
  }
};