const express = require('express');
const router = express.Router();

const authMiddleware = require('../middleware/authMiddleware');
const checkRole = require('../middleware/roleMiddleware');
const adminController = require('../controllers/adminController');

// This route is protected by two middleware functions.
// 1. authMiddleware: Ensures the user is logged in.
// 2. checkRole(['admin']): Ensures the logged-in user has the 'admin' role.
router.get('/users', authMiddleware, checkRole(['admin']), adminController.getAllUsers);

module.exports = router;