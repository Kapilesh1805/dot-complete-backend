const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const User = require('../../models/User');
const Activity = require('../../models/Activity');
const ActivityAssignment = require('../../models/ActivityAssignment');
const { getMissingActivities, getActivities } = require('../../controllers/activityController');

// ==================== MIDDLEWARE ====================
const { protect } = require('../../middleware/auth');
const { handleValidationErrors } = require('../../middleware/validation');

// ==================== ACTIVITY CREATION ====================

/**
 * @swagger
 * /api/activities:
 *   post:
 *     summary: Create a new activity (Admin or Therapist)
 *     tags: [Activities]
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - description
 *               - steps
 *             properties:
 *               name:
 *                 type: string
 *                 description: Activity name
 *                 example: Speech Therapy Activity
 *               description:
 *                 type: string
 *                 description: Detailed description
 *                 example: This activity helps improve pronunciation
 *               steps:
 *                 type: array
 *                 description: Array of steps
 *                 items:
 *                   type: object
 *                   properties:
 *                     stepNumber:
 *                       type: number
 *                     description:
 *                       type: string
 *               assistance:
 *                 type: string
 *                 description: Instructions for therapists
 *               mediaUrls:
 *                 type: array
 *                 items:
 *                   type: object
 *                   properties:
 *                     url:
 *                       type: string
 *                     type:
 *                       type: string
 *                       enum: ['image', 'video']
 *               dueDate:
 *                 type: string
 *                 format: date
 *                 description: Due date for activity assignment
 *     responses:
 *       201:
 *         description: Activity created and assigned successfully
 */
router.post('/', protect, [
  body('name').trim().notEmpty().withMessage('Activity name is required'),
  body('description').trim().notEmpty().withMessage('Description is required'),
  body('steps').isArray({ min: 1 }).withMessage('At least one step is required'),
  handleValidationErrors
], async (req, res) => {
  try {
    const { name, description, steps, assistance, mediaUrls, dueDate } = req.body;
    const userId = req.user.id;
    const userRole = req.user.role;

    // Only superuser and therapist can create activities
    if (userRole !== 'superuser' && userRole !== 'therapist') {
      return res.status(403).json({
        success: false,
        message: 'Only admin and therapist can create activities'
      });
    }

    // Create activity
    const activity = await Activity.create({
      name,
      description,
      steps: steps || [],
      assistance: assistance || null,
      mediaUrls: mediaUrls || [],
      createdBy: userId,
      createdByRole: userRole,
      isActive: true
    });

    // Auto-assign to children based on role
    let assignedCount = 0;

    if (userRole === 'superuser') {
      // Assign to ALL children
      const allChildren = await User.find({ role: 'child', isActive: true });
      
      const assignments = allChildren.map(child => ({
        activityId: activity._id,
        childId: child._id,
        dueDate: dueDate || null,
        completionStatus: 'pending'
      }));

      if (assignments.length > 0) {
        await ActivityAssignment.insertMany(assignments);
        assignedCount = assignments.length;
      }
    } else if (userRole === 'therapist') {
      // Assign to therapist's assigned children
      const therapist = await User.findById(userId);
      const assignedChildren = await User.find({ 
        role: 'child', 
        assignedTherapist: userId, 
        isActive: true 
      });

      const assignments = assignedChildren.map(child => ({
        activityId: activity._id,
        childId: child._id,
        dueDate: dueDate || null,
        completionStatus: 'pending'
      }));

      if (assignments.length > 0) {
        await ActivityAssignment.insertMany(assignments);
        assignedCount = assignments.length;
      }
    }

    res.status(201).json({
      success: true,
      message: `Activity created and assigned to ${assignedCount} children`,
      data: {
        activityId: activity._id,
        name: activity.name,
        description: activity.description,
        createdBy: activity.createdBy,
        createdByRole: activity.createdByRole,
        assignedTo: assignedCount
      }
    });
  } catch (error) {
    console.error('Error creating activity:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating activity',
      error: error.message
    });
  }
});

// ==================== ACTIVITY RETRIEVAL ====================

/**
 * @swagger
 * /api/activities:
 *   get:
 *     summary: Get all activities (created by admin or current therapist)
 *     tags: [Activities]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of activities
 */
router.get('/', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;

    let filter = { isActive: true };

    // Therapist sees only their activities
    if (userRole === 'therapist') {
      filter.createdBy = userId;
    }
    // Admin sees all activities

    const activities = await Activity.find(filter)
      .populate('createdBy', 'Name email role')
      .sort({ createdAt: -1 });

    const total = await Activity.countDocuments(filter);

    res.status(200).json({
      success: true,
      total,
      count: activities.length,
      data: activities
    });
  } catch (error) {
    console.error('Error fetching activities:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching activities',
      error: error.message
    });
  }
});

/**
 * @swagger
 * /api/activities/{id}:
 *   get:
 *     summary: Get activity details
 *     tags: [Activities]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *         required: true
 *         description: Activity ID
 *     responses:
 *       200:
 *         description: Activity details
 */
router.get('/:id', protect, async (req, res) => {
  try {
    const activity = await Activity.findById(req.params.id)
      .populate('createdBy', 'Name email role');

    if (!activity) {
      return res.status(404).json({
        success: false,
        message: 'Activity not found'
      });
    }

    // Count assignments
    const assignmentCount = await ActivityAssignment.countDocuments({ 
      activityId: req.params.id 
    });

    res.status(200).json({
      success: true,
      data: {
        ...activity.toObject(),
        assignedToChildrenCount: assignmentCount
      }
    });
  } catch (error) {
    console.error('Error fetching activity:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching activity',
      error: error.message
    });
  }
});

// ==================== MISSING AND ALL ACTIVITIES ====================

/**
 * @swagger
 * /api/activities/missing:
 *   get:
 *     summary: Get activities that are missing (not assigned to any child)
 *     tags: [Activities]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of missing activities
 */
router.get('/activities/missing', protect, getMissingActivities);

/**
 * @swagger
 * /api/activities/list:
 *   get:
 *     summary: Get all activities (Admin only)
 *     tags: [Activities]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of all activities
 */
router.get('/activities/list', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;

    // Only admin can access this route
    if (userRole !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Access denied. Admins only.'
      });
    }

    const activities = await Activity.find()
      .populate('createdBy', 'Name email role')
      .sort({ createdAt: -1 });

    const total = await Activity.countDocuments();

    res.status(200).json({
      success: true,
      total,
      count: activities.length,
      data: activities
    });
  } catch (error) {
    console.error('Error fetching activities list:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching activities list',
      error: error.message
    });
  }
});

module.exports = router;
