const express = require('express');
const mongoose = require('mongoose');

const { protect } = require('../../middleware/auth');
const User = require('../../models/User');
const GameScore = require('../../models/GameScore');

const router = express.Router();

const GAME_LIBRARY = [
  { type: 'colors', name: 'Colors', difficulty: 'easy' },
  { type: 'shapes', name: 'Shapes', difficulty: 'easy' },
  { type: 'flash-cards', name: 'Flash Cards', difficulty: 'easy' },
  { type: 'adl', name: 'ADL', difficulty: 'medium' },
  { type: 'coloring', name: 'Coloring', difficulty: 'easy' },
  { type: 'matching', name: 'Matching', difficulty: 'medium' },
  { type: 'puzzles', name: 'Puzzles', difficulty: 'medium' },
  { type: 'star-games', name: 'Star Games', difficulty: 'easy' },
  { type: 'identifying', name: 'Identifying', difficulty: 'easy' }
];

const GAME_QUESTIONS = {
  colors: [
    { id: 'c1', prompt: 'Tap RED', options: ['RED', 'BLUE', 'GREEN', 'YELLOW'], answer: 'RED' }
  ],
  shapes: [
    { id: 's1', prompt: 'Tap CIRCLE', options: ['CIRCLE', 'SQUARE', 'TRIANGLE', 'STAR'], answer: 'CIRCLE' }
  ],
  'flash-cards': [
    { id: 'fc1', prompt: 'Card: Apple', answer: 'Apple', image: '🍎' },
    { id: 'fc2', prompt: 'Card: Dog', answer: 'Dog', image: '🐶' },
    { id: 'fc3', prompt: 'Card: Car', answer: 'Car', image: '🚗' }
  ],
  adl: [
    {
      id: 'adl1',
      prompt: 'Order brushing steps',
      steps: [
        'Pick up toothbrush',
        'Put toothpaste on brush',
        'Brush teeth',
        'Rinse mouth',
        'Clean toothbrush'
      ]
    }
  ],
  coloring: [
    { id: 'clr1', prompt: 'Fill all regions', template: 'basic-smiley' }
  ],
  matching: [
    { id: 'm1', prompt: 'Match same symbols', grid: '4x4', pairs: 8 }
  ],
  puzzles: [
    { id: 'pz1', prompt: 'Complete 3x3 puzzle', grid: '3x3' }
  ],
  'star-games': [
    { id: 'sg1', prompt: 'Collect stars in 45 seconds', duration: 45 }
  ],
  identifying: [
    { id: 'id1', prompt: 'Find Apple', answer: 'Apple', options: ['Apple', 'Ball', 'Car', 'Fish'] },
    { id: 'id2', prompt: 'Find Dog', answer: 'Dog', options: ['Tree', 'Dog', 'Book', 'Sun'] }
  ]
};

router.get('/list', protect, async (req, res) => {
  return res.status(200).json({
    success: true,
    total: GAME_LIBRARY.length,
    data: GAME_LIBRARY
  });
});

router.get('/:type/questions', protect, async (req, res) => {
  const type = String(req.params.type || '').trim().toLowerCase();
  const normalizedType = type === 'flashcards' ? 'flash-cards' : type;
  const questions = GAME_QUESTIONS[normalizedType];

  if (!questions) {
    return res.status(404).json({
      success: false,
      message: `Questions not found for game type: ${type}`
    });
  }

  return res.status(200).json({
    success: true,
    gameType: normalizedType,
    total: questions.length,
    data: questions
  });
});

router.post('/score', protect, async (req, res) => {
  try {
    const {
      childId,
      gameType,
      score,
      accuracy,
      timeSpent,
      attempts = 0,
      correctAnswers = 0,
      metadata = {}
    } = req.body || {};

    if (!childId || !mongoose.Types.ObjectId.isValid(childId)) {
      return res.status(400).json({
        success: false,
        message: 'Valid childId is required'
      });
    }

    if (!gameType || typeof gameType !== 'string') {
      return res.status(400).json({
        success: false,
        message: 'gameType is required'
      });
    }

    const numericScore = Number(score);
    const numericAccuracy = Number(accuracy);
    const numericTimeSpent = Number(timeSpent);

    if (
      Number.isNaN(numericScore) ||
      Number.isNaN(numericAccuracy) ||
      Number.isNaN(numericTimeSpent)
    ) {
      return res.status(400).json({
        success: false,
        message: 'score, accuracy and timeSpent must be numeric values'
      });
    }

    if (req.user.role === 'child' && req.user.id.toString() !== childId.toString()) {
      return res.status(403).json({
        success: false,
        message: 'Children can only submit their own score'
      });
    }

    const child = await User.findOne({
      _id: childId,
      role: 'child',
      isActive: true
    }).select('_id');

    if (!child) {
      return res.status(404).json({
        success: false,
        message: 'Child not found'
      });
    }

    const doc = await GameScore.create({
      childId,
      gameType: String(gameType).trim().toLowerCase(),
      score: Math.max(0, numericScore),
      accuracy: Math.max(0, Math.min(100, numericAccuracy)),
      timeSpent: Math.max(0, numericTimeSpent),
      attempts: Math.max(0, Number(attempts) || 0),
      correctAnswers: Math.max(0, Number(correctAnswers) || 0),
      metadata: typeof metadata === 'object' && metadata != null ? metadata : {}
    });

    return res.status(201).json({
      success: true,
      message: 'Game score submitted successfully',
      data: {
        id: doc._id,
        childId: doc.childId,
        gameType: doc.gameType,
        score: doc.score,
        accuracy: doc.accuracy,
        timeSpent: doc.timeSpent,
        attempts: doc.attempts,
        correctAnswers: doc.correctAnswers,
        createdAt: doc.createdAt
      }
    });
  } catch (error) {
    console.error('Error submitting game score:', error);
    return res.status(500).json({
      success: false,
      message: 'Error submitting game score',
      error: error.message
    });
  }
});

module.exports = router;
