const express = require('express');
const router = express.Router();
const { body } = require('express-validator');

// ==================== CONTROLLERS ====================
const {
  register,
  login,
  getProfile,
  logout,
  forgotPassword,
  forgotPasswordDebug,
  resetPassword,
  bootstrapSuperAdmin,
  refresh
} = require('../../controllers/authController');

// ==================== MIDDLEWARE ====================
const { protect } = require('../../middleware/auth');
const { validateRegistration, validateLogin, handleValidationErrors } = require('../../middleware/validation');

// ==================== PUBLIC ROUTES ====================

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *               - role
 *             properties:
 *               name:
 *                 type: string
 *                 description: Full name of the user
 *                 example: John Doe
 *               email:
 *                 type: string
 *                 format: email
 *                 description: Valid email address
 *                 example: john@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 description: Password (min 6 chars, 1 uppercase, 1 lowercase, 1 number)
 *                 example: Password123
 *               role:
 *                 type: string
 *                 enum: ['child', 'therapist']
 *                 description: User role
 *                 example: therapist
 *           example:
 *             name: John Doe
 *             email: john@example.com
 *             password: Password123
 *             role: therapist
 *     responses:
 *       201:
 *         description: User registered successfully
 */
router.post('/register', validateRegistration, register);

/**
 * @swagger
 * /api/auth/bootstrap-superadmin:
 *   post:
 *     summary: Bootstrap a superuser (dev/secret-protected)
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *               secret:
 *                 type: string
 *     responses:
 *       201:
 *         description: Superuser created
 */
router.post('/bootstrap-superadmin', [
  body('name').notEmpty(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
  handleValidationErrors
], bootstrapSuperAdmin);

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User email address
 *                 example: john@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 description: User password
 *                 example: Password123
 *           example:
 *             email: john@example.com
 *             password: Password123
 *     responses:
 *       200:
 *         description: Login successful
 */
router.post('/login', validateLogin, login);

/**
 * @swagger
 * /api/auth/forgot-password:
 *   post:
 *     summary: Request password reset
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: Email address associated with the account
 *                 example: john@example.com
 *           example:
 *             email: john@example.com
 *     responses:
 *       200:
 *         description: Password reset email sent
 */
router.post('/forgot-password', [
  body('email').isEmail().normalizeEmail(),
  handleValidationErrors
], forgotPassword);

if (process.env.NODE_ENV === 'development') {
  router.post('/forgot-password-debug', [
    body('email').isEmail().normalizeEmail(),
    handleValidationErrors
  ], forgotPasswordDebug);
}

/**
 * @swagger
 * /api/auth/reset-password:
 *   post:
 *     summary: Reset password with token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - password
 *             properties:
 *               token:
 *                 type: string
 *                 description: Password reset token from email link
 *               password:
 *                 type: string
 *                 format: password
 *                 description: New password (min 6 chars, 1 uppercase, 1 lowercase, 1 number)
 *           example:
 *             token: abc123token
 *             password: NewPassword456
 *     responses:
 *       200:
 *         description: Password reset successful
 */
router.post('/reset-password', [
  body('token').notEmpty(),
  body('password').isLength({ min: 6 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/),
  handleValidationErrors
], resetPassword);

// //////////////////////
// Refresh token route
// //////////////////////
router.post('/refresh', refresh);

// ==================== PROTECTED ROUTES ====================

/**
 * @swagger
 * /api/auth/profile:
 *   get:
 *     summary: Get current user profile
 *     tags: [Authentication]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: User profile retrieved
 */
router.get('/profile', protect, getProfile);

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout user
 *     tags: [Authentication]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Logged out successfully
 */
router.post('/logout', protect, logout);

module.exports = router;
