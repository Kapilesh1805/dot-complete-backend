const mongoose = require('mongoose');

const gameScoreSchema = new mongoose.Schema(
  {
    childId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true
    },
    gameType: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      index: true
    },
    score: {
      type: Number,
      required: true,
      min: 0
    },
    accuracy: {
      type: Number,
      required: true,
      min: 0,
      max: 100
    },
    timeSpent: {
      type: Number,
      required: true,
      min: 0
    },
    attempts: {
      type: Number,
      default: 0,
      min: 0
    },
    correctAnswers: {
      type: Number,
      default: 0,
      min: 0
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  },
  {
    timestamps: true
  }
);

gameScoreSchema.index({ childId: 1, gameType: 1, createdAt: -1 });

module.exports = mongoose.model('GameScore', gameScoreSchema);
