const { body, validationResult } = require('express-validator');

// Handle validation errors
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const extractedErrors = errors.array().map(err => ({
      field: err.path,
      message: err.msg,
      value: err.value
    }));

    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: extractedErrors
    });
  }
  
  next();
};

// Helper: allow only specific keys on req.body
const allowOnlyBodyKeys = (allowedKeys) => (req, res, next) => {
  const keys = Object.keys(req.body || {});
  const extras = keys.filter(k => !allowedKeys.includes(k));
  if (extras.length > 0) {
    return res.status(400).json({
      success: false,
      message: 'Unexpected fields in request body',
      errors: extras.map(k => ({ field: k, message: 'Field is not allowed' }))
    });
  }
  next();
};

// Registration validation (supports both 'name' and 'firstName/lastName' formats)
const validateRegistration = [
  // Allow either 'name' OR 'firstName/lastName'
  body().custom((value) => {
    const hasName = !!value.name;
    const hasFirstName = !!value.firstName;
    const hasLastName = !!value.lastName;
    
    if (!hasName && (!hasFirstName || !hasLastName)) {
      throw new Error('Either "name" or both "firstName" and "lastName" are required');
    }
    if (hasName && (hasFirstName || hasLastName)) {
      throw new Error('Cannot provide both "name" and "firstName/lastName"');
    }
    return true;
  }),
  
  body('name')
    .optional()
    .isLength({ min: 2, max: 100 })
    .withMessage('Name must be between 2 and 100 characters')
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage('Name can only contain letters and spaces'),
    
  body('firstName')
    .optional()
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage('First name can only contain letters and spaces'),
    
  body('lastName')
    .optional()
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage('Last name can only contain letters and spaces'),
    
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
    
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
  
  body('role')
    .optional()
    // Accept common variants from frontend: 'super_admin', 'superadmin', 'admin', as well as canonical 'superuser'
    .isIn(['superuser', 'superadmin', 'super_admin', 'admin', 'hospital', 'therapist', 'child', 'children'])
    .withMessage('Invalid role'),
    
  handleValidationErrors
];

// Login validation
const validateLogin = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
    
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
    
  handleValidationErrors
];

// Password reset validation
const validatePasswordReset = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email')
    .normalizeEmail(),
    
  handleValidationErrors
];

// New password validation
const validateNewPassword = [
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, and one number'),
    
  body('confirmPassword')
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match');
      }
      return true;
    }),
    
  handleValidationErrors
];

// Update profile validation
const validateProfileUpdate = [
  body('firstName')
    .optional()
    .isLength({ min: 2, max: 50 })
    .withMessage('First name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage('First name can only contain letters and spaces'),
    
  body('lastName')
    .optional()
    .isLength({ min: 2, max: 50 })
    .withMessage('Last name must be between 2 and 50 characters')
    .matches(/^[a-zA-Z\s]+$/)
    .withMessage('Last name can only contain letters and spaces'),
    
  body('phone')
    .optional()
    .isMobilePhone()
    .withMessage('Please provide a valid phone number'),
    
  body('dateOfBirth')
    .optional()
    .isISO8601()
    .withMessage('Please provide a valid date')
    .custom((value) => {
      if (new Date(value) > new Date()) {
        throw new Error('Date of birth cannot be in the future');
      }
      return true;
    }),
    
  handleValidationErrors
];

// Progress validation
const validateProgressCreate = [
  allowOnlyBodyKeys([
    'programId', 'activityId', 'progressPercentage', 'completedTasks', 'notes',
    'milestone', 'customMilestone', 'score', 'timeSpent', 'difficulty', 'mood',
    'tags', 'isPublic'
  ]),
  body('programId')
    .notEmpty()
    .withMessage('Program ID is required')
    .isMongoId()
    .withMessage('Invalid program ID format'),
    
  body('activityId')
    .optional()
    .isMongoId()
    .withMessage('Invalid activity ID format'),
    
  body('progressPercentage')
    .notEmpty()
    .withMessage('Progress percentage is required')
    .isFloat({ min: 0, max: 100 })
    .withMessage('Progress percentage must be between 0 and 100'),
    
  body('completedTasks')
    .optional()
    .isArray()
    .withMessage('Completed tasks must be an array'),
    
  body('completedTasks.*')
    .optional()
    .isString()
    .isLength({ min: 1, max: 200 })
    .withMessage('Each completed task must be a string between 1 and 200 characters'),
    
  body('notes')
    .optional()
    .isString()
    .isLength({ max: 1000 })
    .withMessage('Notes must be less than 1000 characters'),
    
  body('milestone')
    .optional()
    .isIn(['started', 'quarter', 'half', 'three-quarters', 'completed', 'custom'])
    .withMessage('Invalid milestone value'),
    
  body('customMilestone')
    .optional()
    .isString()
    .isLength({ min: 1, max: 100 })
    .withMessage('Custom milestone must be between 1 and 100 characters'),
    
  body('score')
    .optional()
    .isFloat({ min: 0, max: 100 })
    .withMessage('Score must be between 0 and 100'),
    
  body('timeSpent')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Time spent must be a positive number'),
    
  body('difficulty')
    .optional()
    .isIn(['easy', 'medium', 'hard'])
    .withMessage('Difficulty must be easy, medium, or hard'),
    
  body('mood')
    .optional()
    .isIn(['excellent', 'good', 'okay', 'difficult', 'frustrated'])
    .withMessage('Invalid mood value'),
    
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array'),
    
  body('tags.*')
    .optional()
    .isString()
    .isLength({ min: 1, max: 50 })
    .withMessage('Each tag must be a string between 1 and 50 characters'),
    
  body('isPublic')
    .optional()
    .isBoolean()
    .withMessage('isPublic must be a boolean'),
    
  handleValidationErrors
];

// Progress update validation
const validateProgressUpdate = [
  allowOnlyBodyKeys([
    'progressPercentage', 'completedTasks', 'notes', 'milestone', 'customMilestone',
    'score', 'timeSpent', 'difficulty', 'mood', 'tags', 'isPublic', 'reviewNotes'
  ]),
  body('progressPercentage')
    .optional()
    .isFloat({ min: 0, max: 100 })
    .withMessage('Progress percentage must be between 0 and 100'),
    
  body('completedTasks')
    .optional()
    .isArray()
    .withMessage('Completed tasks must be an array'),
    
  body('completedTasks.*')
    .optional()
    .isString()
    .isLength({ min: 1, max: 200 })
    .withMessage('Each completed task must be a string between 1 and 200 characters'),
    
  body('notes')
    .optional()
    .isString()
    .isLength({ max: 1000 })
    .withMessage('Notes must be less than 1000 characters'),
    
  body('milestone')
    .optional()
    .isIn(['started', 'quarter', 'half', 'three-quarters', 'completed', 'custom'])
    .withMessage('Invalid milestone value'),
    
  body('customMilestone')
    .optional()
    .isString()
    .isLength({ min: 1, max: 100 })
    .withMessage('Custom milestone must be between 1 and 100 characters'),
    
  body('score')
    .optional()
    .isFloat({ min: 0, max: 100 })
    .withMessage('Score must be between 0 and 100'),
    
  body('timeSpent')
    .optional()
    .isFloat({ min: 0 })
    .withMessage('Time spent must be a positive number'),
    
  body('difficulty')
    .optional()
    .isIn(['easy', 'medium', 'hard'])
    .withMessage('Difficulty must be easy, medium, or hard'),
    
  body('mood')
    .optional()
    .isIn(['excellent', 'good', 'okay', 'difficult', 'frustrated'])
    .withMessage('Invalid mood value'),
    
  body('tags')
    .optional()
    .isArray()
    .withMessage('Tags must be an array'),
    
  body('tags.*')
    .optional()
    .isString()
    .isLength({ min: 1, max: 50 })
    .withMessage('Each tag must be a string between 1 and 50 characters'),
    
  body('isPublic')
    .optional()
    .isBoolean()
    .withMessage('isPublic must be a boolean'),
    
  body('reviewNotes')
    .optional()
    .isString()
    .isLength({ max: 500 })
    .withMessage('Review notes must be less than 500 characters'),
    
  handleValidationErrors
];

// Query parameter validation for progress endpoints
const validateProgressQuery = [
  body('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
    
  body('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
    
  body('programId')
    .optional()
    .isMongoId()
    .withMessage('Invalid program ID format'),
    
  body('activityId')
    .optional()
    .isMongoId()
    .withMessage('Invalid activity ID format'),
    
  body('milestone')
    .optional()
    .isIn(['started', 'quarter', 'half', 'three-quarters', 'completed', 'custom'])
    .withMessage('Invalid milestone value'),
    
  body('status')
    .optional()
    .isIn(['draft', 'submitted', 'reviewed', 'approved'])
    .withMessage('Invalid status value'),
    
  body('days')
    .optional()
    .isInt({ min: 1, max: 365 })
    .withMessage('Days must be between 1 and 365'),
    
  handleValidationErrors
];

module.exports = {
  validateRegistration,
  validateLogin,
  validatePasswordReset,
  validateNewPassword,
  validateProfileUpdate,
  validateProgressCreate,
  validateProgressUpdate,
  validateProgressQuery,
  handleValidationErrors,
  allowOnlyBodyKeys
};