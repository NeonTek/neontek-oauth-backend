const express = require('express');
const router = express.Router();
const apiKeyController = require('../controllers/apiKeyController');
const authMiddleware = require('../middleware/authMiddleware');

router.post('/', authMiddleware, apiKeyController.createApiKey);
router.get('/', authMiddleware, apiKeyController.listApiKeys);
router.delete('/:id', authMiddleware, apiKeyController.revokeApiKey);

module.exports = router;