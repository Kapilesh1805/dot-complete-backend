const mongoose = require('mongoose');

const activitySchema = new mongoose.Schema({
  // ==================== BASIC INFO ====================
  name: { 
    type: String, 
    required: true, 
    trim: true, 
    maxlength: 100 
  },
  description: { 
    type: String, 
    required: true, 
    maxlength: 1000 
  },

  // ==================== ACTIVITY DETAILS ====================
  steps: [
    {
      stepNumber: { type: Number, required: true },
      description: { type: String, required: true, maxlength: 500 },
      _id: false
    }
  ],
  assistance: { 
    type: String, 
    default: null, 
    maxlength: 1000
  },
  durationMinutes: {
    type: Number,
    min: 1,
    max: 240,
    default: null
  },

  // ==================== MEDIA ====================
  mediaUrls: [
    {
      url: { type: String, required: true },
      type: { 
        type: String, 
        enum: ['image', 'video'], 
        required: true 
      },
      _id: false
    }
  ],

  // ==================== CREATOR INFO ====================
  createdBy: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  createdByRole: { 
    type: String, 
    enum: ['superuser', 'therapist'], 
    required: true 
  },

  // ==================== STATUS ====================
  isActive: { type: Boolean, default: true },

}, { timestamps: true });

// ==================== INDEXES ====================
activitySchema.index({ createdBy: 1 });
activitySchema.index({ isActive: 1 });
activitySchema.index({ createdAt: -1 });

module.exports = mongoose.model('Activity', activitySchema);
