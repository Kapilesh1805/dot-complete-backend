const mongoose = require('mongoose');

const activityAssignmentSchema = new mongoose.Schema({
  // ==================== ACTIVITY & CHILD ====================
  activityId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Activity', 
    required: true 
  },
  childId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },

  // ==================== ASSIGNMENT STATUS ====================
  completionStatus: { 
    type: String, 
    enum: ['pending', 'in-progress', 'submitted', 'completed', 'not-completed'],
    default: 'pending'
  },
  score: { 
    type: Number, 
    default: null,
    min: 0,
    max: 100
  },

  // ==================== COMPLETION DETAILS ====================
  completionVideoUrl: {
    type: String,
    default: null
  },

  // ==================== DATES ====================
  dueDate: { 
    type: Date, 
    default: null 
  },
  startedDate: { 
    type: Date, 
    default: null 
  },
  completedDate: { 
    type: Date, 
    default: null 
  },

  // ==================== STATUS ====================
  isActive: { type: Boolean, default: true },

  // ==================== THERAPIST ====================
  therapistId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Therapist' 
  },

  // ==================== ACTIVITY NAME ====================
  activityName: { 
    type: String, 
    required: true 
  },

  // ==================== VIDEO SUBMISSION ====================
  videoSubmitted: { 
    type: Boolean, 
    default: false 
  }

}, { timestamps: true });

// ==================== INDEXES ====================
activityAssignmentSchema.index({ childId: 1 });
activityAssignmentSchema.index({ activityId: 1 });
activityAssignmentSchema.index({ completionStatus: 1 });
activityAssignmentSchema.index({ dueDate: 1 });

// ==================== HELPER METHODS ====================
/**
 * Check if assignment is overdue (past due date and not completed)
 */
activityAssignmentSchema.methods.isOverdue = function() {
  if (!this.dueDate || this.completionStatus === 'completed') {
    return false;
  }
  return new Date() > this.dueDate;
};

/**
 * Get effective status (accounts for overdue assignments)
 */
activityAssignmentSchema.methods.getEffectiveStatus = function() {
  if (this.completionStatus === 'completed') {
    return 'completed';
  }
  if (this.isOverdue()) {
    return 'not-completed';
  }
  return this.completionStatus;
};

// ==================== STATICS ====================
/**
 * Auto-mark overdue pending assignments as not-completed
 */
activityAssignmentSchema.statics.markOverduePending = async function() {
  const now = new Date();
  const result = await this.updateMany(
    {
      dueDate: { $lt: now },
      completionStatus: { $in: ['pending', 'in-progress'] }
    },
    { completionStatus: 'not-completed' }
  );
  return result;
};

module.exports = mongoose.model('ActivityAssignment', activityAssignmentSchema);
