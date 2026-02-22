// controllers/authController.js
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ==================== HELPER TO GENERATE JWT ====================
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET || 'secretkey',
    { expiresIn: '7d' }
  );
};

// ==================== HELPER TO SET COOKIE ====================
const setAuthCookie = (res, token) => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  // Cookie configuration for security
  const cookieOptions = {
    httpOnly: true,        // Cannot be accessed by JavaScript (prevents XSS attacks)
    secure: isProduction,  // Only sent over HTTPS in production
    sameSite: 'strict',    // CSRF protection - cookie only sent with same-site requests
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
    path: '/',             // Available for all routes
  };
  
  // In development, allow non-HTTPS
  if (!isProduction) {
    cookieOptions.secure = false;
  }
  
  res.cookie('authToken', token, cookieOptions);
};

// ==================== HELPER TO CLEAR COOKIE ====================
const clearAuthCookie = (res) => {
  res.clearCookie('authToken', {
    httpOnly: true,
    path: '/',
  });
};

// ==================== HELPER TO SET REFRESH COOKIE ====================
const setRefreshCookie = (res, refreshToken) => {
  const isProduction = process.env.NODE_ENV === 'production';
  const cookieOptions = {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: (parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS || '30') * 24 * 60 * 60 * 1000), // default 30 days
    path: '/',
  };
  if (!isProduction) cookieOptions.secure = false;
  res.cookie('refreshToken', refreshToken, cookieOptions);
};

// ==================== HELPER TO CLEAR REFRESH COOKIE ====================
const clearRefreshCookie = (res) => {
  res.clearCookie('refreshToken', {
    httpOnly: true,
    path: '/',
  });
};

// ==================== REFRESH TOKEN ENDPOINT ====================
exports.refresh = async (req, res) => {
  try {
    // Accept refresh token via httpOnly cookie (web) or request body (mobile)
    let providedToken = null;
    if (req.cookies && req.cookies.refreshToken) {
      providedToken = req.cookies.refreshToken;
    } else if (req.body && req.body.refreshToken) {
      providedToken = req.body.refreshToken;
    }

    if (!providedToken) {
      return res.status(401).json({ success: false, message: 'No refresh token provided' });
    }

    const hashedToken = crypto.createHash('sha256').update(providedToken).digest('hex');

    // Find user with this refresh token
    const user = await User.findOne({ 'refreshTokens.token': hashedToken });
    if (!user) return res.status(401).json({ success: false, message: 'Invalid refresh token' });

    // Find specific token entry
    const tokenEntry = user.refreshTokens.find(t => t.token === hashedToken);
    if (!tokenEntry) return res.status(401).json({ success: false, message: 'Refresh token not found' });

    if (tokenEntry.expiresAt && tokenEntry.expiresAt < Date.now()) {
      // Remove expired token
      user.refreshTokens = user.refreshTokens.filter(t => t.token !== hashedToken);
      await user.save({ validateBeforeSave: false });
      clearRefreshCookie(res);
      return res.status(401).json({ success: false, message: 'Refresh token expired' });
    }

    // Generate new access token
    const newAccessToken = generateToken(user);

    // Rotate refresh token: replace old token with new one
    const newRefreshToken = crypto.randomBytes(48).toString('hex');
    const newHashed = crypto.createHash('sha256').update(newRefreshToken).digest('hex');
    const expiresAt = Date.now() + (parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS || '30') * 24 * 60 * 60 * 1000);

    // Replace tokenEntry
    user.refreshTokens = user.refreshTokens.map(t => t.token === hashedToken ? {
      token: newHashed,
      createdAt: Date.now(),
      expiresAt,
      createdByIp: req.ip || ''
    } : t);

    await user.save({ validateBeforeSave: false });

    // Set cookies and respond
    setAuthCookie(res, newAccessToken);
    setRefreshCookie(res, newRefreshToken);

    res.status(200).json({ success: true, token: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({ success: false, message: 'Failed to refresh token' });
  }
};

// ==================== REGISTER ====================
exports.register = async (req, res) => {
  try {
    // Support both formats: {name} or {firstName, lastName}
    let firstName, lastName;
    if (req.body.name) {
      // Frontend sends "name" - split it
      const nameParts = req.body.name.trim().split(' ');
      firstName = nameParts[0] || '';
      lastName = nameParts.slice(1).join(' ') || '';
    } else {
      // Backend format: firstName and lastName
      firstName = req.body.firstName;
      lastName = req.body.lastName;
    }

    const {
      email,
      password,
      role
    } = req.body;

    // Normalize and validate role input (accept common variants)
    const normalizedRole = (role || '').toString().toLowerCase().replace(/_/g, '');
    const roleMap = {
      'admin': 'superuser',
      'superadmin': 'superuser',
      'superuser': 'superuser',
      'super_admin': 'superuser',
      'therapist': 'therapist',
      'child': 'child',
      'children': 'child'
    };

    if (!role) {
      return res.status(400).json({ 
        success: false, 
        message: 'Role is required',
        errors: [
          {
            field: 'role',
            message: 'Role must be one of: therapist, child (or superuser when created by admin)'
          }
        ]
      });
    }

    const mappedRole = roleMap[normalizedRole];
    // Dev/Bootstrap flags that relax superuser creation checks when explicitly enabled
    // Allow dev superuser creation when ALLOW_DEV_SUPERADMIN=true OR when running in non-production (local development)
    const allowDevSuper = process.env.ALLOW_DEV_SUPERADMIN === 'true' || process.env.NODE_ENV !== 'production';
    const allowBootstrap = process.env.ALLOW_BOOTSTRAP === 'true';
    // Check if a superuser already exists in the system
    const superExists = await User.exists({ role: 'superuser' });

    if (!mappedRole) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid role specified',
        errors: [
          {
            field: 'role',
            message: 'Role must be one of: therapist, child (or superuser when created by admin)'
          }
        ]
      });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Email already in use' });
    }

    // Role validation logic
    const requester = req.user || null;
    const allowedPublicRoles = ['therapist', 'child']; // public registration allowed roles
    const restrictedRoles = ['superuser', 'hospital'];

    // If public request and role is not allowed, deny unless dev flag/bootstrap permits creating a superuser
    if (!requester && !allowedPublicRoles.includes(mappedRole)) {
      if (mappedRole === 'superuser' && (allowDevSuper || (allowBootstrap && !superExists))) {
        // Allowed in development/bootstrap mode
      } else {
        return res.status(403).json({ 
          success: false, 
          message: 'Invalid role specified',
          errors: [
            {
              field: 'role',
              message: 'Role must be one of: therapist, child'
            }
          ]
        });
      }
    }

    // Check restricted roles that require authentication
    if (restrictedRoles.includes(mappedRole)) {
      if (!requester) {
        // Allow creating a superuser in development or bootstrap mode when explicitly enabled
        if (mappedRole === 'superuser' && (allowDevSuper || (allowBootstrap && !superExists))) {
          // allowed
        } else {
          return res.status(403).json({ 
            success: false, 
            message: 'Authentication required for this role',
            errors: [
              {
                field: 'role',
                message: 'This role requires administrator approval.'
              }
            ]
          });
        }
      }

      // Superuser role restrictions when requester exists
      if (mappedRole === 'superuser' && requester && requester.role !== 'superuser') {
        return res.status(403).json({ 
          success: false, 
          message: 'Only superuser can create superuser accounts',
          errors: [
            {
              field: 'role',
              message: 'Only superuser can create superuser accounts'
            }
          ]
        });
      }

      // Hospital role restrictions
      if (mappedRole === 'hospital' && requester && requester.role !== 'superuser') {
        return res.status(403).json({ 
          success: false, 
          message: 'Only superuser can register hospital accounts',
          errors: [
            {
              field: 'role',
              message: 'Only superuser can register hospital accounts'
            }
          ]
        });
      }
    }

    // Create new user with the provided role
    const user = await User.create({
      Name: req.body.name || `${firstName} ${lastName}`.trim(), // Set Name field (required by schema)
      firstName,
      lastName,
      email,
      password,
      role: mappedRole
    });

    // Generate token
    const token = generateToken(user);

    // Logging for debugging: new user created
    console.log('🆕 User registered:', { email: user.email, id: user._id.toString(), role: user.role });
    
    // Create refresh token for mobile and web clients
    const refreshToken = crypto.randomBytes(48).toString('hex');
    const hashedRefresh = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const refreshExpiresAt = Date.now() + (parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS || '30') * 24 * 60 * 60 * 1000);

    user.refreshTokens = user.refreshTokens || [];
    user.refreshTokens.push({ token: hashedRefresh, createdAt: Date.now(), expiresAt: refreshExpiresAt, createdByIp: req.ip || '' });
    await user.save({ validateBeforeSave: false });

    // Set JWT token and refresh token in httpOnly cookies
    setAuthCookie(res, token);
    setRefreshCookie(res, refreshToken);

    res.status(201).json({
      success: true,
      message: 'Registration successful',
      token: token,
      refreshToken: refreshToken,
      user: {
        id: user._id,
        name: `${user.firstName} ${user.lastName}`.trim(),
        email: user.email,
        role: user.role
      },
      // Also include data for backward compatibility
      data: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error(error);
    
    // Handle validation errors
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(e => ({
        field: e.path,
        message: e.message
      }));
      return res.status(400).json({ 
        success: false, 
        error: 'Validation failed',
        details: errors
      });
    }
    
    // Handle duplicate key errors
    if (error.code === 11000) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email already exists' 
      });
    }
    
    res.status(500).json({ success: false, error: 'Server error' });
  }
};

// ==================== BOOTSTRAP SUPERADMIN (DEV-ONLY / SECRET) ====================
exports.bootstrapSuperAdmin = async (req, res) => {
  try {
    const { name, email, password, secret } = req.body;

    const bootstrapSecret = process.env.SUPERADMIN_BOOTSTRAP_SECRET || null;
    const allowBootstrap = process.env.ALLOW_BOOTSTRAP === 'true';

    // Prevent bootstrap if a superuser already exists
    const alreadySuper = await User.exists({ role: 'superuser' });
    if (alreadySuper) {
      return res.status(400).json({ success: false, message: 'A superuser already exists' });
    }

    // If SECRET is configured, require it. Otherwise require ALLOW_BOOTSTRAP=true
    if (bootstrapSecret) {
      if (!secret || secret !== bootstrapSecret) {
        return res.status(401).json({ success: false, message: 'Invalid bootstrap secret' });
      }
    } else if (!allowBootstrap) {
      return res.status(403).json({ success: false, message: 'Bootstrap endpoint disabled' });
    }

    // Create the superuser
    const user = await User.create({
      Name: name,
      email,
      password,
      role: 'superuser'
    });

    const token = generateToken(user);
    // create refresh token similar to registration
    const refreshToken = require('crypto').randomBytes(48).toString('hex');
    const hashedRefresh = require('crypto').createHash('sha256').update(refreshToken).digest('hex');
    const refreshExpiresAt = Date.now() + (parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS || '30') * 24 * 60 * 60 * 1000);

    user.refreshTokens = user.refreshTokens || [];
    user.refreshTokens.push({ token: hashedRefresh, createdAt: Date.now(), expiresAt: refreshExpiresAt, createdByIp: req.ip || '' });
    await user.save({ validateBeforeSave: false });

    setAuthCookie(res, token);
    setRefreshCookie(res, refreshToken);

    console.log('🆕 Superuser bootstrapped:', { email: user.email, id: user._id.toString() });

    return res.status(201).json({ success: true, message: 'Superuser created', token, user: { id: user._id, email: user.email, role: user.role } });
  } catch (error) {
    console.error('Bootstrap error:', error);
    if (error.name === 'ValidationError') {
      const errors = Object.values(error.errors).map(e => ({ field: e.path, message: e.message }));
      return res.status(400).json({ success: false, message: 'Validation failed', errors });
    }
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};

// ==================== LOGIN ====================
exports.login = async (req, res) => {
  try {
    const { password } = req.body;
    const safeEmail = req.body.email?.toString().trim().toLowerCase();

    // Check if user exists and select password
    const user = await User.findOne({ email: safeEmail }).select('+password');

    // Temporary debug logging for login troubleshooting
    console.log('LOGIN DEBUG:', {
      email: safeEmail,
      passwordLength: password?.length,
      userFound: !!user
    });

    if (!user) return res.status(401).json({ success: false, error: 'Invalid credentials' });

    // Check password
    const safePassword = password?.toString();
    const isMatch = await bcrypt.compare(safePassword, user.password);
    if (!isMatch) return res.status(401).json({ success: false, error: 'Invalid credentials' });

    // Update last login without triggering full validation
    await User.findByIdAndUpdate(
      user._id,
      { lastLogin: new Date() },
      { runValidators: false }
    );

    // Generate token
    const token = generateToken(user);
    
    // Create refresh token
    const refreshToken = crypto.randomBytes(48).toString('hex');
    const hashedRefresh = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const refreshExpiresAt = Date.now() + (parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS || '30') * 24 * 60 * 60 * 1000);

    user.refreshTokens = user.refreshTokens || [];
    user.refreshTokens.push({ token: hashedRefresh, createdAt: Date.now(), expiresAt: refreshExpiresAt, createdByIp: req.ip || '' });
    await user.save({ validateBeforeSave: false });

    // Set JWT token and refresh token cookie
    setAuthCookie(res, token);
    setRefreshCookie(res, refreshToken);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      token: token,
      refreshToken: refreshToken,
      user: {
        id: user._id,
        name: `${user.firstName} ${user.lastName}`.trim(),
        email: user.email,
        role: user.role
      },
      // Also include data for backward compatibility
      data: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        childrenIds: user.childrenIds,
        assignedPatients: user.assignedPatients,
        currentGoals: user.currentGoals,
        notifications: user.notifications,
        stats: user.stats,
        medicalHistory: user.medicalHistory
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
};

// ==================== GET PROFILE ====================
exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    res.status(200).json({
      success: true,
      data: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        fullName: user.fullName,
        email: user.email,
        role: user.role,
        phoneNumber: user.phoneNumber,
        dateOfBirth: user.dateOfBirth,
        gender: user.gender,
        childrenIds: user.childrenIds,
        assignedPatients: user.assignedPatients,
        currentGoals: user.currentGoals,
        notifications: user.notifications,
        stats: user.stats,
        medicalHistory: user.medicalHistory,
        age: user.age,
        profilePicture: user.profilePicture,
        isActive: user.isActive,
        isEmailVerified: user.isEmailVerified,
        isPhoneVerified: user.isPhoneVerified
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
};

// ==================== FORGOT PASSWORD ====================
const emailService = require('../utils/emailService');
const crypto = require('crypto');

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    // Validation
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required' 
      });
    }

    // Find user by email
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    console.log('🔍 forgotPassword: lookup for', email, 'found:', !!user);

    // Security: Don't reveal if email exists (prevents email enumeration attacks)
    // Always return success message regardless of whether user exists
    const successMessage = 'If an account exists with this email, a reset link has been sent to your email address.';

    if (!user) {
      // Add artificial delay to prevent timing attacks
      await new Promise(resolve => setTimeout(resolve, 100));
      return res.status(200).json({ 
        success: true, 
        message: successMessage
      });
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(200).json({ 
        success: true, 
        message: successMessage
      });
    }

    // Rate limiting: Prevent multiple reset requests while a token is still valid (10 minute window)
    if (user.passwordResetExpires && user.passwordResetExpires > Date.now()) {
      return res.status(429).json({
        success: false,
        message: 'Password reset request already sent. Please check your email or wait a few minutes before requesting again.'
      });
    }

    // Generate reset token
    const resetToken = user.getResetPasswordToken();
    await user.save({ validateBeforeSave: false });

    // Dev-only debug log: show token when running locally
    if (process.env.NODE_ENV === 'development') {
      console.log('🔐 forgotPassword: generated resetToken (dev):', resetToken);
    }
    // Send password reset email
    try {
      const emailResult = await emailService.sendPasswordResetEmail(user, resetToken);

      // Log the email send result for debugging
      console.log('📧 Password reset email result:', {
        to: user.email,
        success: emailResult.success,
        message: emailResult.message,
        error: emailResult.error,
        emailConfigured: emailService.isEmailConfigured()
      });
      
      if (!emailResult.success && process.env.NODE_ENV === 'production') {
        // In production, don't reveal email service issues
        console.error('Email sending failed:', emailResult.error);
        // Still return success to user for security
        return res.status(200).json({ 
          success: true, 
          message: successMessage
        });
      }

      // In development, log email details (and token is included in response below when email is not configured)
      if (process.env.NODE_ENV === 'development') {
        console.log('📧 Password reset email sent (dev):', {
          to: user.email,
          resetToken: resetToken, // Only in development
          emailConfigured: emailService.isEmailConfigured()
        });
      }

      // Flutter-friendly response format
      const response = {
        success: true,
        message: successMessage
      };

      // Only return token in development for testing (Flutter can use this for testing)
      if (process.env.NODE_ENV === 'development' && !emailService.isEmailConfigured()) {
        response.resetToken = resetToken;
        response.note = 'Email service not configured. Use this token for testing.';
        response.deepLink = `dottherapy://reset-password?token=${resetToken}`;
      }

      res.status(200).json(response);
    } catch (emailError) {
      console.error('Error sending password reset email:', emailError);
      
      // Clear the reset token if email failed
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });

      // In production, still return success to prevent email enumeration
      if (process.env.NODE_ENV === 'production') {
        return res.status(200).json({ 
          success: true, 
          message: successMessage
        });
      }

      // In development, return error details
      return res.status(500).json({ 
        success: false, 
        message: 'Failed to send reset email. Please try again later.',
        error: process.env.NODE_ENV === 'development' ? emailError.message : undefined
      });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'An error occurred. Please try again later.' 
    });
  }
};

// ==================== DEBUG: FORGOT PASSWORD (DEV ONLY) ====================
// Returns reset token directly for local testing (development only)
exports.forgotPasswordDebug = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, message: 'Email is required' });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    if (!user.isActive) return res.status(400).json({ success: false, message: 'Account inactive' });

    // Prevent repetitive token requests while a token is still valid
    if (user.passwordResetExpires && user.passwordResetExpires > Date.now()) {
      return res.status(429).json({ success: false, message: 'Password reset request already sent. Please check your email or wait a few minutes before requesting again.' });
    }

    const resetToken = user.getResetPasswordToken();
    await user.save({ validateBeforeSave: false });

    // Log debug info
    console.log('🔐 forgotPasswordDebug: generated token for', email, resetToken);

    return res.status(200).json({ success: true, resetToken, message: 'Debug token generated' });
  } catch (err) {
    console.error('forgotPasswordDebug error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};


// ==================== RESET PASSWORD ====================
exports.resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;

    // Validation
    if (!token || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Token and new password are required' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        message: 'Password must be at least 6 characters long' 
      });
    }

    // Hash the token to compare with stored hash
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    // Find user with valid reset token
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() } // Token not expired
    });

    if (!user) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid or expired reset token. Please request a new password reset.' 
      });
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(403).json({ 
        success: false, 
        message: 'Account is deactivated. Please contact support.' 
      });
    }

    // Update password
    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // Log password reset for security audit
    console.log('✅ Password reset successful:', {
      userId: user._id,
      email: user.email,
      timestamp: new Date().toISOString()
    });

    res.status(200).json({ 
      success: true, 
      message: 'Password has been reset successfully. You can now login with your new password.' 
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'An error occurred while resetting password. Please try again.' 
    });
  }
};

// ==================== LOGOUT ====================
exports.logout = async (req, res) => {
  try {
    // Update lastLogout without triggering full validation
    await User.findByIdAndUpdate(
      req.user.id,
      { lastLogout: new Date() },
      { runValidators: false }
    );

    // Remove refresh token from user's record if a refresh token was provided
    try {
      let providedToken = null;
      if (req.cookies && req.cookies.refreshToken) providedToken = req.cookies.refreshToken;
      else if (req.body && req.body.refreshToken) providedToken = req.body.refreshToken;

      if (providedToken) {
        const hashed = crypto.createHash('sha256').update(providedToken).digest('hex');
        await User.updateOne({ _id: req.user.id }, { $pull: { refreshTokens: { token: hashed } } });
      }
    } catch (err) {
      console.warn('Failed to remove refresh token during logout:', err.message || err);
    }

    // Clear the authentication cookie and refresh cookie
    clearAuthCookie(res);
    clearRefreshCookie(res);

    res.status(200).json({ 
      success: true, 
      message: 'Logged out successfully' 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Server error' });
  }
};
