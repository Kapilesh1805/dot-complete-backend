const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  // ==================== BASIC INFO ====================
  Name: { type: String, required: true, trim: true, maxlength: 50 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true,
  match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please provide a valid email'] },
  password: { type: String, required: true, minlength: 6, select: false },

  // ==================== ROLE & PERMISSIONS ====================
  role: { type: String, enum: ['superuser', 'hospital', 'therapist', 'child'], default: 'child' },
  hospitalId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },

  // ==================== CONTACT ====================
  phoneNumber: { type: String, trim: true, match: [/^[\+]?[1-9][\d]{0,15}$/, 'Please provide a valid phone number'], default: null },
  parentName: { type: String, trim: true, maxlength: 100, default: '' },
  
  // ==================== PERSONAL INFO ====================
  // Add firstName and lastName to support API/virtuals and prevent undefined values
  firstName: { type: String, trim: true, maxlength: 50, default: '' },
  lastName: { type: String, trim: true, maxlength: 50, default: '' },
  dateOfBirth: { type: Date, validate: { validator: d => d <= new Date(), message: 'Date of birth cannot be in the future' } },
  gender: {
    type: String,
    enum: ['male', 'female', 'other'],
    trim: true,
    lowercase: true,
    default: null,
    set: (value) => {
      if (value === undefined || value === null) return null;
      const normalized = String(value).trim().toLowerCase();
      if (!normalized) return null;
      if (normalized === 'prefer-not-to-say') return 'other'; // backward-compatible legacy value
      return ['male', 'female', 'other'].includes(normalized) ? normalized : null;
    }
  },
  // Condition / diagnostic field for children (free-text, stored on user record)
  condition: { type: String, trim: true, maxlength: 200, default: '' },

  // ==================== PROFILE & MEDIA ====================
  profilePicture: { type: String, default: '' },
  bio: { type: String, maxlength: 500 },

  // ==================== ADDRESS ====================
  address: {
    street: { type: String, default: '' },
    city: { type: String, default: '' },
    state: { type: String, default: '' },
    country: { type: String, default: '' },
    zipCode: { type: String, default: '' }
  },

  // ==================== ACCOUNT STATUS ====================
  isActive: { type: Boolean, default: true },
  isEmailVerified: { type: Boolean, default: false },
  isPhoneVerified: { type: Boolean, default: false },

  // ==================== RELATIONSHIPS ====================
  childrenIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  parentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  assignedPatients: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  assignedTherapist: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },

  // ==================== TIMESTAMPS ====================
  lastLogin: { type: Date },
  lastLogout: { type: Date },

  // ==================== THERAPY DATA ====================
  therapyStartDate: { type: Date },
  currentGoals: [{ type: mongoose.Schema.Types.ObjectId, ref: 'TherapyGoal' }],

  // ==================== NOTIFICATIONS ====================
  notifications: {
    email: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    push: { type: Boolean, default: true },
    activityReminders: { type: Boolean, default: true },
    progressUpdates: { type: Boolean, default: true }
  },
  deviceTokens: { type: [String], default: [] },

  // Refresh tokens (hashed) for rotating refresh token support
  refreshTokens: [{
    token: { type: String },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date },
    createdByIp: { type: String, default: '' }
  }],

  // ==================== SECURITY ====================
  passwordResetToken: String,
  passwordResetExpires: Date,
  emailVerificationToken: String,
  emailVerificationExpires: Date,

  // ==================== ACTIVITY TRACKING ====================
  stats: {
    totalActivitiesCompleted: { type: Number, default: 0 },
    totalTimeSpent: { type: Number, default: 0 },
    averageScore: { type: Number, default: 0 },
    currentStreak: { type: Number, default: 0 },
    longestStreak: { type: Number, default: 0 }
  },

  // ==================== MEDICAL HISTORY ====================
  medicalHistory: {
    currentLevel: { type: String, default: 'beginner' },
    totalActivitiesCompleted: { type: Number, default: 0 },
    totalTherapyHours: { type: Number, default: 0 }
  }

}, {
  timestamps: true,
  toJSON: { virtuals: true, transform: (doc, ret) => {
    delete ret.password;
    delete ret.passwordResetToken;
    delete ret.emailVerificationToken;
    return ret;
  }},
  toObject: { virtuals: true }
});

// ==================== VIRTUALS ====================
userSchema.virtual('fullName').get(function() { 
  // Prefer the legacy `Name` field if present, otherwise build from firstName/lastName
  if (this.Name && this.Name.trim().length > 0) return this.Name; 
  return `${this.firstName || ''} ${this.lastName || ''}`.trim();
});
userSchema.virtual('age').get(function() {
  if (!this.dateOfBirth) return null;
  const today = new Date();
  const birthDate = new Date(this.dateOfBirth);
  let age = today.getFullYear() - birthDate.getFullYear();
  if (today.getMonth() < birthDate.getMonth() || (today.getMonth() === birthDate.getMonth() && today.getDate() < birthDate.getDate())) age--;
  return age;
});

// ==================== INDEXES ====================
userSchema.index({ email: 1 });
userSchema.index({ role: 1 });
userSchema.index({ isActive: 1 });
userSchema.index({ assignedTherapist: 1 });
userSchema.index({ parentId: 1 });
userSchema.index({ deviceTokens: 1 });

// ==================== MIDDLEWARE ====================
userSchema.pre('validate', function(next) {
  // Normalize legacy/variant gender values before validation to avoid breaking existing users.
  if (this.gender !== undefined && this.gender !== null) {
    const normalized = String(this.gender).trim().toLowerCase();
    if (!normalized) {
      this.gender = null;
    } else if (normalized === 'prefer-not-to-say') {
      this.gender = 'other';
    } else if (!['male', 'female', 'other'].includes(normalized)) {
      this.gender = null;
    } else {
      this.gender = normalized;
    }
  }
  next();
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// ==================== INSTANCE METHODS ====================
userSchema.methods.comparePassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

userSchema.methods.getResetPasswordToken = function() {
  const resetToken = crypto.randomBytes(20).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  return resetToken;
};

userSchema.methods.getEmailVerificationToken = function() {
  const token = crypto.randomBytes(20).toString('hex');
  this.emailVerificationToken = crypto.createHash('sha256').update(token).digest('hex');
  this.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  return token;
};

module.exports = mongoose.model('User', userSchema);
