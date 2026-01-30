const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const User = require('../../models/User');
const Activity = require('../../models/Activity');
const ActivityAssignment = require('../../models/ActivityAssignment');

// ==================== MIDDLEWARE ====================
const { protect } = require('../../middleware/auth');
const { handleValidationErrors } = require('../../middleware/validation');

// ==================== THERAPIST ACTIVITY CREATION ====================

/**
 * @swagger
 * /api/therapist/activities:
 *   post:
 *     summary: Create activity and assign to therapist's children
 *     tags: [Therapist - Activities]
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
 *               description:
 *                 type: string
 *               steps:
 *                 type: array
 *               assistance:
 *                 type: string
 *               mediaUrls:
 *                 type: array
 *               dueDate:
 *                 type: string
 *                 format: date
 *     responses:
 *       201:
 *         description: Activity created and assigned
 */
router.post('/activities', protect, [
  body('name').trim().notEmpty().withMessage('Activity name is required'),
  body('description').trim().notEmpty().withMessage('Description is required'),
  body('steps').isArray({ min: 1 }).withMessage('At least one step is required'),
  handleValidationErrors
], async (req, res) => {
  try {
    const { name, description, steps, assistance, mediaUrls, dueDate } = req.body;
    const userId = req.user.id;
    const userRole = req.user.role;

    // Only therapist can use this endpoint
    if (userRole !== 'therapist') {
      return res.status(403).json({
        success: false,
        message: 'Only therapists can create activities from this endpoint'
      });
    }

    // Format steps properly (convert to objects with stepNumber and description)
    const formattedSteps = steps && steps.length > 0 
      ? steps.map((step, index) => ({
          stepNumber: index + 1,
          description: typeof step === 'string' ? step : step.description || ''
        }))
      : [];

    // Format mediaUrls properly (convert to objects with url and type)
    const formattedMediaUrls = mediaUrls && mediaUrls.length > 0
      ? mediaUrls.map(media => ({
          url: typeof media === 'string' ? media : media.url || '',
          type: (typeof media === 'string' ? 'image' : media.type) || 'image'
        }))
      : [];

    // Create activity
    const activity = await Activity.create({
      name,
      description,
      steps: formattedSteps,
      assistance: assistance || null,
      mediaUrls: formattedMediaUrls,
      createdBy: userId,
      createdByRole: userRole,
      isActive: true
    });

    // Assign to therapist's assigned children only
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
    }

    res.status(201).json({
      success: true,
      message: `Activity created and assigned to ${assignments.length} children`,
      data: {
        activityId: activity._id,
        name: activity.name,
        assignedTo: assignments.length
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

/**
 * @swagger
 * /api/therapist/activities:
 *   get:
 *     summary: Get therapist's activities
 *     tags: [Therapist - Activities]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of therapist activities
 */
router.get('/activities', protect, async (req, res) => {
  try {
    const userId = req.user.id;

    const activities = await Activity.find({ 
      createdBy: userId, 
      isActive: true 
    })
      .populate('createdBy', 'Name email')
      .sort({ createdAt: -1 });

    const total = await Activity.countDocuments({ 
      createdBy: userId, 
      isActive: true 
    });

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

// ==================== THERAPIST REPORTS ====================

/**
 * @swagger
 * /api/therapist/reports:
 *   get:
 *     summary: Get reports for therapist's assigned children
 *     tags: [Therapist - Reports]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Activity reports for assigned children
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 total:
 *                   type: number
 *                 data:
 *                   type: array
 */
router.get('/reports', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    const ActivityAssignment = require('../../models/ActivityAssignment');

    // Auto-mark overdue pending/in-progress assignments as not-completed
    await ActivityAssignment.markOverduePending();

    // Get therapist's assigned children
    const assignedChildren = await User.find({
      assignedTherapist: userId,
      role: 'child',
      isActive: true
    }).select('_id Name email');

    const reports = [];

    for (const child of assignedChildren) {
      const assignments = await ActivityAssignment.find({
        childId: child._id,
        isActive: true
      });

      // Count using effective status (accounts for overdue)
      const completed = assignments.filter(a => a.getEffectiveStatus() === 'completed').length;
      const pending = assignments.filter(a => a.getEffectiveStatus() === 'pending').length;
      const inProgress = assignments.filter(a => a.getEffectiveStatus() === 'in-progress').length;
      const notCompleted = assignments.filter(a => a.getEffectiveStatus() === 'not-completed').length;
      const totalActivities = assignments.length;
      const completionPercentage = totalActivities > 0 ? Math.round((completed / totalActivities) * 100) : 0;
      const averageScore = assignments.length > 0 
        ? Math.round(assignments.reduce((sum, a) => sum + (a.score || 0), 0) / assignments.length)
        : 0;

      reports.push({
        childId: child._id,
        childName: child.Name,
        childEmail: child.email,
        totalActivities,
        completed,
        pending,
        inProgress,
        notCompleted,
        completionPercentage,
        averageScore
      });
    }

    res.status(200).json({
      success: true,
      total: reports.length,
      data: reports
    });
  } catch (error) {
    console.error('Error fetching reports:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching reports',
      error: error.message
    });
  }
});

// ==================== THERAPIST CHILD MANAGEMENT ====================

/**
 * @swagger
 * /api/therapist/children:
 *   post:
 *     summary: Create a child profile and assign to therapist
 *     tags: [Therapist - Children]
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - childName
 *               - email
 *               - age
 *               - gender
 *               - condition
 *               - parentName
 *               - phoneNo
 *               - password
 *               - confirmPassword
 *             properties:
 *               childName:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               age:
 *                 type: number
 *               gender:
 *                 type: string
 *                 enum: [male, female, other]
 *               condition:
 *                 type: string
 *               parentName:
 *                 type: string
 *               phoneNo:
 *                 type: string
 *               password:
 *                 type: string
 *               confirmPassword:
 *                 type: string
 *     responses:
 *       201:
 *         description: Child profile created and assigned to therapist
 */
router.post('/children', protect, [
  body('childName').trim().notEmpty().withMessage('Child name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('age').isInt({ min: 1, max: 18 }).withMessage('Age must be between 1 and 18'),
  body('gender').isIn(['male', 'female', 'other']).withMessage('Valid gender is required'),
  body('condition').trim().notEmpty().withMessage('Condition is required'),
  body('parentName').trim().notEmpty().withMessage('Parent name is required'),
  body('phoneNo').trim().notEmpty().withMessage('Phone number is required'),
  body('password').isLength({ min: 6 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain uppercase, lowercase, and number'),
  body('confirmPassword').notEmpty().withMessage('Confirm password is required'),
  handleValidationErrors
], async (req, res) => {
  try {
    const {
      childName,
      email,
      age,
      gender,
      condition,
      parentName,
      phoneNo,
      password,
      confirmPassword
    } = req.body;

    const therapistId = req.user.id;

    // Check if passwords match
    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }

    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Email already in use'
      });
    }

    // Create child user
    const child = await User.create({
      Name: childName,
      firstName: childName.split(' ')[0] || childName,
      lastName: childName.split(' ').slice(1).join(' ') || '',
      email,
      password,
      role: 'child',
      age,
      gender,
      phoneNumber: phoneNo,
      assignedTherapist: therapistId,
      isActive: true,
      isEmailVerified: true,
      medicalHistory: {
        currentLevel: 'beginner',
        totalActivitiesCompleted: 0,
        totalTherapyHours: 0
      }
    });

    // Populate therapist details
    await child.populate('assignedTherapist', 'Name email specialization');

    res.status(201).json({
      success: true,
      message: 'Child profile created and assigned to therapist',
      data: {
        childId: child._id,
        childName: child.Name,
        email: child.email,
        age: child.age,
        gender: child.gender,
        condition: condition,
        parentName: parentName,
        phoneNo: phoneNo,
        assignedTherapist: child.assignedTherapist
      }
    });
  } catch (error) {
    console.error('Error creating child profile:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating child profile',
      error: error.message
    });
  }
});

// ==================== INCOMPLETE ACTIVITIES ====================

/**
 * @swagger
 * /api/therapist/incomplete-activities:
 *   get:
 *     tags:
 *       - Therapist - Reports
 *     summary: Get incomplete activities of therapist's assigned children
 *     description: View all not-completed and overdue activities for children assigned to this therapist
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Successfully retrieved incomplete activities
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 total:
 *                   type: integer
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       childId:
 *                         type: string
 *                       childName:
 *                         type: string
 *                       childEmail:
 *                         type: string
 *                       activityName:
 *                         type: string
 *                       status:
 *                         type: string
 *                       dueDate:
 *                         type: string
 *                       daysOverdue:
 *                         type: integer
 *       403:
 *         description: Forbidden - User is not a therapist
 *       500:
 *         description: Server error
 */
router.get('/incomplete-activities', protect, async (req, res) => {
  try {
    const userId = req.user.id;

    if (req.user.role !== 'therapist') {
      return res.status(403).json({
        success: false,
        message: 'Only therapists can access this endpoint'
      });
    }

    // Auto-mark overdue pending/in-progress assignments as not-completed
    await ActivityAssignment.markOverduePending();

    // Get therapist's assigned children
    const assignedChildren = await User.find({
      assignedTherapist: userId,
      role: 'child',
      isActive: true
    }).select('_id Name email');

    const incompleteActivities = [];

    for (const child of assignedChildren) {
      const assignments = await ActivityAssignment.find({
        childId: child._id,
        isActive: true
      })
        .populate('activityId', 'name dueDate')
        .lean();

      for (const assignment of assignments) {
        const effectiveStatus = assignment.completionStatus === 'pending' || assignment.completionStatus === 'in-progress'
          ? (assignment.activityId?.dueDate && new Date(assignment.activityId.dueDate) < new Date() ? 'not-completed' : assignment.completionStatus)
          : assignment.completionStatus;

        if (effectiveStatus === 'not-completed' || assignment.completionStatus === 'not-completed') {
          const dueDate = assignment.activityId?.dueDate ? new Date(assignment.activityId.dueDate) : null;
          const today = new Date();
          const daysOverdue = dueDate ? Math.floor((today - dueDate) / (1000 * 60 * 60 * 24)) : 0;

          incompleteActivities.push({
            childId: child._id,
            childName: child.Name,
            childEmail: child.email,
            activityName: assignment.activityId?.name || 'Unknown Activity',
            status: effectiveStatus,
            dueDate: dueDate,
            daysOverdue: daysOverdue > 0 ? daysOverdue : 0,
            assignmentId: assignment._id
          });
        }
      }
    }

    res.status(200).json({
      success: true,
      total: incompleteActivities.length,
      data: incompleteActivities
    });
  } catch (error) {
    console.error('Error fetching incomplete activities:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching incomplete activities',
      error: error.message
    });
  }
});

module.exports = router;
