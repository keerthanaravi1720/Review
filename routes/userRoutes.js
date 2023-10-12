// const express = require('express');
// const router = express.Router();
// const userController = require('../controllers/userControllers');

// // Registration route
// router.post('/register', userController.registerUser);

// // Login route
// router.post('/login', userController.loginUser);

// // Profile route
// // router.get('/profile', userController.getUserProfile);

// module.exports = router;


const express = require('express');
const router = express.Router();
const userController = require('../controllers/userControllers');
const { verifyToken } = require('../middleware/verifyToken'); // Import your verifyToken middleware

// Registration route
router.post('/register', userController.registerUser);

// Login route
router.post('/login', userController.loginUser);

// Profile route with the verifyToken middleware
router.get('/profile', verifyToken, userController.userProfile);

module.exports = router;
