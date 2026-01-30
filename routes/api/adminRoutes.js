const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const User = require('../../models/User');
const Activity = require('../../models/Activity');
const ActivityAssignment = require('../../models/ActivityAssignment');

// ==================== MIDDLEWARE ====================
const { protect } = require('../../middleware/auth');
const { handleValidationErrors } = require('../../middleware/validation');

// ==================== HELPER FUNCTION ====================
const setAuthCookie = (res, token) => {
  const isProduction = process.env.NODE_ENV === 'production';
  const cookieOptions = {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  };
  if (!isProduction) {
    cookieOptions.secure = false;
  }
  res.cookie('authToken', token, cookieOptions);
};

const generateToken = (user) => {
  return require('jsonwebtoken').sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET || 'secretkey',
    { expiresIn: '7d' }
  );
};

// ==================== THERAPIST MANAGEMENT ====================

/**
 * @swagger
 * /api/admin/therapists:
 *   get:
 *     summary: Get all therapists with total count
 *     tags: [Admin - Therapists]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of all therapists
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 total:
 *                   type: number
 *                   description: Total number of therapists
 *                 count:
 *                   type: number
 *                 data:
 *                   type: array
 *   post:
 *     summary: Create a new therapist account
 *     tags: [Admin - Therapists]
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
 *               - email
 *               - password
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               qualification:
 *                 type: string
 *               experience:
 *                 type: string
 *               specialization:
 *                 type: string
 *               phoneNumber:
 *                 type: string
 *     responses:
 *       201:
 *         description: Therapist created successfully
 */
router.get('/therapists', protect, async (req, res) => {
  try {
    const therapists = await User.find({ role: 'therapist', isActive: true })
      .select('-password -passwordResetToken -emailVerificationToken')
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments({ role: 'therapist', isActive: true });

    res.status(200).json({
      success: true,
      total,
      count: therapists.length,
      data: therapists
    });
  } catch (error) {
    console.error('Error fetching therapists:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching therapists',
      error: error.message
    });
  }
});

router.post('/therapists', protect, [
  body('name').trim().notEmpty().withMessage('Name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 6 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain uppercase, lowercase, and number'),
  handleValidationErrors
], async (req, res) => {
  try {
    const { name, email, password, qualification, experience, specialization, phoneNumber, gender, dateOfBirth } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Email already registered'
      });
    }

    // Split name into firstName and lastName
    const nameParts = name.trim().split(' ');
    const firstName = nameParts[0] || '';
    const lastName = nameParts.slice(1).join(' ') || '';

    // Create therapist
    const therapist = await User.create({
      Name: name,
      firstName,
      lastName,
      email,
      password,
      role: 'therapist',
      qualification: qualification || null,
      experience: experience || null,
      specialization: specialization || null,
      phoneNumber: phoneNumber || null,
      gender: gender || null,
      dateOfBirth: dateOfBirth || null,
      isActive: true,
      isEmailVerified: true
    });

    const token = generateToken(therapist);
    setAuthCookie(res, token);

    res.status(201).json({
      success: true,
      message: 'Therapist created successfully',
      data: {
        id: therapist._id,
        name: therapist.Name,
        email: therapist.email,
        role: therapist.role,
        qualification: therapist.qualification,
        experience: therapist.experience,
        specialization: therapist.specialization
      }
    });
  } catch (error) {
    console.error('Error creating therapist:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating therapist',
      error: error.message
    });
  }
});

// ==================== CHILD MANAGEMENT ====================

/**
 * @swagger
 * /api/admin/children:
 *   get:
 *     summary: Get all children with total count
 *     tags: [Admin - Children]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of all children
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 total:
 *                   type: number
 *                   description: Total number of children
 *                 count:
 *                   type: number
 *                 data:
 *                   type: array
 *   post:
 *     summary: Create a new child account
 *     tags: [Admin - Children]
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
 *               - email
 *               - password
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               gender:
 *                 type: string
 *               dateOfBirth:
 *                 type: string
 *                 format: date
 *               phoneNumber:
 *                 type: string
 *               assignedTherapist:
 *                 type: string
 *                 description: Therapist ID
 *     responses:
 *       201:
 *         description: Child created successfully
 */
router.get('/children', protect, async (req, res) => {
  try {
    const children = await User.find({ role: 'child', isActive: true })
      .select('-password -passwordResetToken -emailVerificationToken')
      .populate('assignedTherapist', 'Name email')
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments({ role: 'child', isActive: true });

    res.status(200).json({
      success: true,
      total,
      count: children.length,
      data: children
    });
  } catch (error) {
    console.error('Error fetching children:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching children',
      error: error.message
    });
  }
});

router.post('/children', protect, [
  body('name').trim().notEmpty().withMessage('Name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 6 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain uppercase, lowercase, and number'),
  handleValidationErrors
], async (req, res) => {
  try {
    const { name, email, password, gender, dateOfBirth, phoneNumber, assignedTherapist } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Email already registered'
      });
    }

    // Split name into firstName and lastName
    const nameParts = name.trim().split(' ');
    const firstName = nameParts[0] || '';
    const lastName = nameParts.slice(1).join(' ') || '';

    // Create child
    const child = await User.create({
      Name: name,
      firstName,
      lastName,
      email,
      password,
      role: 'child',
      gender: gender || null,
      dateOfBirth: dateOfBirth || null,
      phoneNumber: phoneNumber || null,
      assignedTherapist: assignedTherapist || null,
      isActive: true,
      isEmailVerified: true
    });

    const token = generateToken(child);
    setAuthCookie(res, token);

    res.status(201).json({
      success: true,
      message: 'Child created successfully',
      data: {
        id: child._id,
        name: child.Name,
        email: child.email,
        role: child.role,
        gender: child.gender,
        dateOfBirth: child.dateOfBirth,
        assignedTherapist: child.assignedTherapist
      }
    });
  } catch (error) {
    console.error('Error creating child:', error);
    res.status(500).json({
      success: false,
      message: 'Error creating child',
      error: error.message
    });
  }
});


// ==================== UNASSIGNED CHILDREN MANAGEMENT ====================

/**
 * @swagger
 * /api/admin/children/unassigned:
 *   get:
 *     summary: Get all unassigned children (without therapist)
 *     tags: [Admin - Children]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of unassigned children with total count
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 total:
 *                   type: number
 *                   description: Total number of unassigned children
 *                 count:
 *                   type: number
 *                 data:
 *                   type: array
 */
router.get('/children/unassigned', protect, async (req, res) => {
  try {
    const unassignedChildren = await User.find({ 
      role: 'child', 
      isActive: true, 
      assignedTherapist: null 
    })
      .select('-password -passwordResetToken -emailVerificationToken')
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments({ 
      role: 'child', 
      isActive: true, 
      assignedTherapist: null 
    });

    res.status(200).json({
      success: true,
      total,
      count: unassignedChildren.length,
      data: unassignedChildren
    });
  } catch (error) {
    console.error('Error fetching unassigned children:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching unassigned children',
      error: error.message
    });
  }
});

/**
 * @swagger
 * /api/admin/children/{id}/assign-therapist:
 *   put:
 *     summary: Assign a therapist to a child
 *     tags: [Admin - Children]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *         required: true
 *         description: Child ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - therapistId
 *             properties:
 *               therapistId:
 *                 type: string
 *                 description: ID of the therapist to assign
 *           example:
 *             therapistId: 60d5ec49c1234567890abcde
 *     responses:
 *       200:
 *         description: Therapist assigned successfully
 *       404:
 *         description: Child or therapist not found
 */
router.put('/children/:id/assign-therapist', protect, [
  body('therapistId').notEmpty().withMessage('Therapist ID is required'),
  handleValidationErrors
], async (req, res) => {
  try {
    const { id } = req.params;
    const { therapistId } = req.body;

    // Find child
    const child = await User.findById(id);
    if (!child || child.role !== 'child') {
      return res.status(404).json({
        success: false,
        message: 'Child not found'
      });
    }

    // Find therapist
    const therapist = await User.findById(therapistId);
    if (!therapist || therapist.role !== 'therapist') {
      return res.status(404).json({
        success: false,
        message: 'Therapist not found'
      });
    }

    // Update child's assigned therapist (use findByIdAndUpdate to avoid full validation)
    const updatedChild = await User.findByIdAndUpdate(
      id,
      { assignedTherapist: therapistId },
      { new: true, runValidators: false }
    ).populate('assignedTherapist', 'Name email specialization qualification');

    res.status(200).json({
      success: true,
      message: 'Therapist assigned successfully',
      data: {
        id: updatedChild._id,
        name: updatedChild.Name,
        email: updatedChild.email,
        role: updatedChild.role,
        assignedTherapist: updatedChild.assignedTherapist
      }
    });
  } catch (error) {
    console.error('Error assigning therapist:', error);
    res.status(500).json({
      success: false,
      message: 'Error assigning therapist',
      error: error.message
    });
  }
});

// ==================== UNASSIGNED CHILDREN MANAGEMENT ====================

/**
 * @swagger
 * /api/admin/children/unassigned:
 *   get:
 *     summary: Get all unassigned children (without therapist)
 *     tags: [Admin - Children]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of unassigned children with total count
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 total:
 *                   type: number
 *                   description: Total number of unassigned children
 *                 count:
 *                   type: number
 *                 data:
 *                   type: array
 */
router.get('/children/unassigned', protect, async (req, res) => {
  try {
    const unassignedChildren = await User.find({ 
      role: 'child', 
      isActive: true, 
      assignedTherapist: null 
    })
      .select('-password -passwordResetToken -emailVerificationToken')
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments({ 
      role: 'child', 
      isActive: true, 
      assignedTherapist: null 
    });

    res.status(200).json({
      success: true,
      total,
      count: unassignedChildren.length,
      data: unassignedChildren
    });
  } catch (error) {
    console.error('Error fetching unassigned children:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching unassigned children',
      error: error.message
    });
  }
});

/**
 * @swagger
 * /api/admin/children/{id}/assign-therapist:
 *   put:
 *     summary: Assign a therapist to a child
 *     tags: [Admin - Children]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *         required: true
 *         description: Child ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - therapistId
 *             properties:
 *               therapistId:
 *                 type: string
 *                 description: ID of the therapist to assign
 *           example:
 *             therapistId: 60d5ec49c1234567890abcde
 *     responses:
 *       200:
 *         description: Therapist assigned successfully
 *       404:
 *         description: Child or therapist not found
 */
router.put('/children/:id/assign-therapist', protect, [
  body('therapistId').notEmpty().withMessage('Therapist ID is required'),
  handleValidationErrors
], async (req, res) => {
  try {
    const { id } = req.params;
    const { therapistId } = req.body;

    // Find child
    const child = await User.findById(id);
    if (!child || child.role !== 'child') {
      return res.status(404).json({
        success: false,
        message: 'Child not found'
      });
    }

    // Find therapist
    const therapist = await User.findById(therapistId);
    if (!therapist || therapist.role !== 'therapist') {
      return res.status(404).json({
        success: false,
        message: 'Therapist not found'
      });
    }

    // Update child's assigned therapist (use findByIdAndUpdate to avoid full validation)
    const updatedChild = await User.findByIdAndUpdate(
      id,
      { assignedTherapist: therapistId },
      { new: true, runValidators: false }
    ).populate('assignedTherapist', 'Name email specialization qualification');

    res.status(200).json({
      success: true,
      message: 'Therapist assigned successfully',
      data: {
        id: updatedChild._id,
        name: updatedChild.Name,
        email: updatedChild.email,
        role: updatedChild.role,
        assignedTherapist: updatedChild.assignedTherapist
      }
    });
  } catch (error) {
    console.error('Error assigning therapist:', error);
    res.status(500).json({
      success: false,
      message: 'Error assigning therapist',
      error: error.message
    });
  }
});
// ==================== USER MANAGEMENT ====================

/**
 * @swagger
 * /api/admin/users:
 *   get:
 *     summary: Get users filtered by role
 *     tags: [Admin - Users]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: query
 *         name: role
 *         schema:
 *           type: string
 *           enum: ['therapist', 'child']
 *         description: Filter by user role
 *     responses:
 *       200:
 *         description: Filtered list of users
 */
router.get('/users', protect, async (req, res) => {
  try {
    const { role } = req.query;
    const filter = { isActive: true };
    
    if (role) {
      filter.role = role;
    }

    const users = await User.find(filter)
      .select('-password -passwordResetToken -emailVerificationToken')
      .sort({ createdAt: -1 });
    
    const total = await User.countDocuments(filter);

    res.status(200).json({
      success: true,
      total,
      count: users.length,
      filter: role ? { role } : 'all active users',
      data: users
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching users',
      error: error.message
    });
  }
});

/**
 * @swagger
 * /api/admin/user/{id}:
 *   get:
 *     summary: Get specific user profile
 *     tags: [Admin - Users]
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *         required: true
 *         description: User ID
 *     responses:
 *       200:
 *         description: User profile retrieved
 */
router.get('/user/:id', protect, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('-password -passwordResetToken -emailVerificationToken')
      .populate('assignedTherapist', 'Name email');
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user',
      error: error.message
    });
  }
});

// ==================== ADMIN ACTIVITY MANAGEMENT ====================

/**
 * @swagger
 * /api/admin/activities:
 *   post:
 *     summary: Create activity and assign to all children
 *     tags: [Admin - Activities]
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
 *         description: Activity created and assigned to all children
 */
router.post('/activities', protect, [
  body('name').trim().notEmpty().withMessage('Activity name is required'),
  body('description').trim().notEmpty().withMessage('Description is required'),
  body('steps').isArray({ min: 1 }).withMessage('At least one step is required'),
  handleValidationErrors
], async (req, res) => {
  try {
    const Activity = require('../../models/Activity');
    const ActivityAssignment = require('../../models/ActivityAssignment');
    
    const { name, description, steps, assistance, mediaUrls, dueDate } = req.body;
    const userId = req.user.id;
    const userRole = req.user.role;

    // Only superuser (admin) can use this endpoint
    if (userRole !== 'superuser') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can create activities from this endpoint'
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

    // Assign to all children
    const allChildren = await User.find({ 
      role: 'child', 
      isActive: true 
    });

    const assignments = allChildren.map(child => ({
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
 * /api/admin/activities:
 *   get:
 *     summary: Get all activities
 *     tags: [Admin - Activities]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of all activities
 */
router.get('/activities', protect, async (req, res) => {
  try {
    const Activity = require('../../models/Activity');
    
    const activities = await Activity.find({ isActive: true })
      .populate('createdBy', 'Name email role')
      .sort({ createdAt: -1 });

    const total = await Activity.countDocuments({ isActive: true });

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

// ==================== ADMIN REPORTS ====================

/**
 * @swagger
 * /api/admin/reports:
 *   get:
 *     summary: Get activity reports for all children
 *     tags: [Admin - Reports]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Activity reports for all children
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
    const Activity = require('../../models/Activity');
    const ActivityAssignment = require('../../models/ActivityAssignment');
    
    // Auto-mark overdue pending/in-progress assignments as not-completed
    await ActivityAssignment.markOverduePending();

    // Get all children
    const allChildren = await User.find({
      role: 'child',
      isActive: true
    }).select('_id Name email');

    const reports = [];

    for (const child of allChildren) {
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

// ==================== INCOMPLETE ACTIVITIES ====================

/**
 * @swagger
 * /api/admin/incomplete-activities:
 *   get:
 *     tags:
 *       - Admin - Reports
 *     summary: Get incomplete activities of all children
 *     description: View all not-completed and overdue activities across all children in the system
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
 *                       therapistName:
 *                         type: string
 *                       therapistEmail:
 *                         type: string
 *       403:
 *         description: Forbidden - User is not an admin
 *       500:
 *         description: Server error
 */
router.get('/incomplete-activities', protect, async (req, res) => {
  try {
    if (req.user.role !== 'superuser' && req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Only admins can access this endpoint'
      });
    }

    // Auto-mark overdue pending/in-progress assignments as not-completed
    await ActivityAssignment.markOverduePending();

    // Get all children
    const allChildren = await User.find({
      role: 'child',
      isActive: true
    }).select('_id Name email assignedTherapist').populate('assignedTherapist', 'Name email');

    const incompleteActivities = [];

    for (const child of allChildren) {
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
            therapistName: child.assignedTherapist?.Name || 'Not Assigned',
            therapistEmail: child.assignedTherapist?.email || 'N/A',
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
