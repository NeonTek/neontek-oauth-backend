const { v4: uuidv4 } = require('uuid');
const argon2 = require('argon2');
const Client = require('../models/Client');

exports.registerClient = async (req, res, next) => {
  try {
    const ownerId = req.user.sub; 
    const { name, redirectUris } = req.body;

    if (!name || !redirectUris || !Array.isArray(redirectUris) || redirectUris.length === 0) {
      return res.status(400).json({ message: 'Client name and at least one redirect URI are required.' });
    }

    const clientSecret = uuidv4(); 
    const clientSecretHash = await argon2.hash(clientSecret);

    const newClient = await Client.create({
      name,
      owner: ownerId,
      clientSecretHash,
      redirectUris,
    });

    res.status(201).json({
      message: 'Client application registered successfully. Store the clientId and clientSecret securely.',
      client: {
        name: newClient.name,
        clientId: newClient.clientId,
        clientSecret: clientSecret, 
      },
    });

  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ message: 'A client with this identifier already exists.' });
    }
    next(err);
  }
};

/**
 * GET /api/clients
 * Lists all client applications registered by the authenticated user.
 */
exports.listClients = async (req, res, next) => {
  try {
    const ownerId = req.user.sub;
    const clients = await Client.find({ owner: ownerId }).select('-clientSecretHash').lean();
    res.json({ clients });
  } catch (err) {
    next(err);
  }
};