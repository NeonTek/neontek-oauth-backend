const express = require('express');
const router = express.Router();

const authMiddleware = require('../middleware/authMiddleware');
const twoFactorController = require('../controllers/twoFactorController');

router.post('/generate', authMiddleware, twoFactorController.generateSecret);
router.post('/verify', authMiddleware, twoFactorController.verifyAndEnable);
router.post('/disable', authMiddleware, twoFactorController.disable);

module.exports = router;