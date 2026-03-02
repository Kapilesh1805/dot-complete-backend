const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const User = require('../../models/User');
const Activity = require('../../models/Activity');
const ActivityAssignment = require('../../models/ActivityAssignment');

// ==================== MIDDLEWARE ====================
const { protect } = require('../../middleware/auth');
const { handleValidationErrors } = require('../../middleware/validation');

const ensureActivityImageDir = (dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
};

const activityImageUploadDir = path.join(process.cwd(), 'uploads', 'activity-images');
ensureActivityImageDir(activityImageUploadDir);

const activityImageStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, activityImageUploadDir),
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    const safeBase = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${timestamp}_${safeBase}`);
  }
});

const activityImageFileFilter = (req, file, cb) => {
  const allowed = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/gif'];
  if (allowed.includes(file.mimetype)) return cb(null, true);
  cb(new Error('Invalid file type. Only PNG/JPEG/WEBP/GIF are allowed.'));
};

const uploadActivityImage = multer({
  storage: activityImageStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: activityImageFileFilter
});

const parseArrayField = (value) => {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return [];
    try {
      const parsed = JSON.parse(trimmed);
      return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
      return [];
    }
  }
  return [];
};

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

const ADMIN_ROLES = ['superuser', 'admin'];
const IN_PROGRESS_STATUSES = ['in-progress', 'submitted'];
const PENDING_STATUSES = ['pending', 'not-completed'];
const DEFAULT_REPORT_STATS = Object.freeze({
  total: 0,
  completed: 0,
  inProgress: 0,
  pending: 0,
  completionRate: 0,
  lastActivityDate: null
});

const toPositiveInt = (value, fallback) => {
  const parsed = parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return parsed;
};

const toBooleanQuery = (value, fallback = true) => {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'boolean') return value;
  const normalized = String(value).trim().toLowerCase();
  return !['false', '0', 'no'].includes(normalized);
};

const toIsoOrNull = (value) => {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
};

const MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;

const toDaysOverdue = (dueDate, now) => {
  if (!dueDate) return 0;
  const due = new Date(dueDate);
  if (Number.isNaN(due.getTime())) return 0;
  const diffMs = now.getTime() - due.getTime();
  if (diffMs <= 0) return 0;
  return Math.max(1, Math.floor(diffMs / MILLISECONDS_PER_DAY));
};

const buildOverdueAssignmentFilter = (now, extraFilter = {}) => ({
  isActive: true,
  dueDate: { $ne: null, $lt: now },
  completionStatus: { $ne: 'completed' },
  ...extraFilter
});

const mapAssignmentToOverdueAlert = (assignment, now) => {
  const child = assignment.childId;
  const childId = child && typeof child === 'object' && child._id
    ? child._id.toString()
    : assignment.childId?.toString() || '';

  const therapist = child && typeof child === 'object' && child.assignedTherapist
    ? child.assignedTherapist
    : null;

  const therapistId = therapist && typeof therapist === 'object' && therapist._id
    ? therapist._id.toString()
    : '';

  const activity = assignment.activityId;
  const activityId = activity && typeof activity === 'object' && activity._id
    ? activity._id.toString()
    : assignment.activityId?.toString() || '';

  return {
    assignmentId: assignment._id?.toString() || '',
    childId,
    childName: child && typeof child === 'object' && child.Name ? child.Name : 'Unknown Child',
    activityId,
    activityName: assignment.activityName || (activity && typeof activity === 'object' ? activity.name : '') || 'Unknown Activity',
    therapistId,
    therapistName: therapist && typeof therapist === 'object' && therapist.Name ? therapist.Name : 'Not Assigned',
    dueDate: toIsoOrNull(assignment.dueDate) || '',
    daysOverdue: toDaysOverdue(assignment.dueDate, now),
    completionStatus: (assignment.completionStatus || 'pending').toString()
  };
};

const buildRecentActivityMessage = (status, childName) => {
  const safeName = childName || 'Unknown Child';
  switch (status) {
    case 'completed':
      return `Child ${safeName} completed an activity`;
    case 'in-progress':
      return `Child ${safeName} started an activity`;
    case 'submitted':
      return `Activity submitted by ${safeName}`;
    case 'not-completed':
      return `Activity not completed by ${safeName}`;
    case 'pending':
      return `Pending activity for ${safeName}`;
    default:
      return `Activity updated for ${safeName}`;
  }
};

const buildChildStatsMap = async (childIds) => {
  if (!childIds.length) return new Map();

  const aggregated = await ActivityAssignment.aggregate([
    {
      $match: {
        isActive: true,
        childId: { $in: childIds }
      }
    },
    {
      $group: {
        _id: '$childId',
        total: { $sum: 1 },
        completed: {
          $sum: {
            $cond: [{ $eq: ['$completionStatus', 'completed'] }, 1, 0]
          }
        },
        inProgress: {
          $sum: {
            $cond: [{ $in: ['$completionStatus', IN_PROGRESS_STATUSES] }, 1, 0]
          }
        },
        pending: {
          $sum: {
            $cond: [{ $in: ['$completionStatus', PENDING_STATUSES] }, 1, 0]
          }
        },
        // Keep this date independent from automatic overdue status updates.
        lastActivityDate: {
          $max: {
            $ifNull: [
              '$completedDate',
              {
                $ifNull: ['$startedDate', '$createdAt']
              }
            ]
          }
        }
      }
    }
  ]);

  const statsMap = new Map();
  for (const row of aggregated) {
    const total = row.total || 0;
    const completed = row.completed || 0;
    const inProgress = row.inProgress || 0;
    const pending = row.pending || 0;
    const completionRate = total > 0 ? Math.round((completed / total) * 100) : 0;
    statsMap.set(row._id.toString(), {
      total,
      completed,
      inProgress,
      pending,
      completionRate,
      lastActivityDate: row.lastActivityDate || null
    });
  }
  return statsMap;
};

// ==================== THERAPIST MANAGEMENT ====================

// Middleware: enforce admin-only for assign-therapist admin endpoints
// This ensures any PUT to /admin/children/:id/assign-therapist must be done by a superuser
router.use('/children/:id/assign-therapist', protect, (req, res, next) => {
  if (req.user.role !== 'superuser') {
    return res.status(403).json({ success: false, message: 'Only admin can assign therapist to this child' });
  }
  next();
});

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
    const normalizedGender = typeof gender === 'string'
      ? (() => {
          const g = gender.trim().toLowerCase();
          if (!g) return null;
          if (g === 'prefer-not-to-say') return 'other';
          return ['male', 'female', 'other'].includes(g) ? g : null;
        })()
      : null;
    const normalizedPhone = phoneNumber ?? req.body.contactNo ?? null;

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
      phoneNumber: normalizedPhone,
      gender: normalizedGender,
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
    const { name, email, password, gender, dateOfBirth, phoneNumber, assignedTherapist, parentName, condition } = req.body; 

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
      parentName: parentName || '',
      condition: condition || null,
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
        condition: child.condition,
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

// Update user (admin)
router.put('/user/:id', protect, [
  // email is optional but must be valid if provided
  body('email').optional().isEmail().normalizeEmail().withMessage('Valid email is required'),
  handleValidationErrors
], async (req, res) => {
  try {
    const { id } = req.params;

    // Debug logging: help trace incoming update requests and auth method
    console.log(`PUT /api/admin/user/${id} - headers.authorization: ${req.headers.authorization ? 'present' : 'absent'}, cookie.authToken: ${req.cookies && req.cookies.authToken ? 'present' : 'absent'}`);
    console.log('Update payload keys:', Object.keys(req.body));

    // Allow only specific updatable fields from admin
    const allowed = ['Name','name','firstName','lastName','age','gender','condition','contactNo','phoneNumber','email','address','qualification','experience','specialization','parentName','dateOfBirth'];
    const updates = {};
    for (const field of allowed) {
      if (req.body[field] !== undefined) updates[field] = req.body[field];
    }

    // Map friendly frontend keys to schema fields (legacy `Name` is the canonical name field in the User schema)
    if (req.body.name !== undefined && updates.Name === undefined) {
      updates.Name = req.body.name;
      // remove lowercase name to avoid creating a new field
      delete updates.name;
    }

    // Parent name mapping
    if (req.body.parentName !== undefined && updates.parentName === undefined) {
      updates.parentName = req.body.parentName;
    }

    // Condition mapping (also accept 'grade' as a friendly field)
    if (req.body.condition !== undefined && updates.condition === undefined) {
      updates.condition = req.body.condition;
    }
    if (req.body.grade !== undefined && updates.condition === undefined) {
      updates.condition = req.body.grade;
      delete updates.grade;
    }

    // Common parent/contact keys from frontend
    if (req.body.parentContact !== undefined && updates.phoneNumber === undefined) {
      updates.phoneNumber = req.body.parentContact;
    }

    // Map therapist/admin contact keys to canonical phoneNumber so phone is persisted
    if (req.body.contactNo !== undefined && updates.phoneNumber === undefined) {
      updates.phoneNumber = req.body.contactNo;
      // remove contactNo to avoid creating an extra field
      delete updates.contactNo;
    }
    if (req.body.contact !== undefined && updates.phoneNumber === undefined) {
      updates.phoneNumber = req.body.contact;
      delete updates.contact;
    }

    // Log final updates for debugging
    console.log('Final update object being applied:', updates);

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ success: false, message: 'No update fields provided' });
    }

    const updatedUser = await User.findByIdAndUpdate(id, updates, { new: true, runValidators: false })
      .select('-password -passwordResetToken -emailVerificationToken')
      .populate('assignedTherapist', 'Name email');

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.status(200).json({
      success: true,
      message: 'User updated successfully',
      data: updatedUser
    });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ success: false, message: 'Error updating user', error: error.message });
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
router.post('/activities', protect, uploadActivityImage.single('image'), [
  body('name').trim().notEmpty().withMessage('Activity name is required'),
  body('description').trim().notEmpty().withMessage('Description is required'),
  body('steps').custom((value) => {
    const parsedSteps = parseArrayField(value);
    if (!Array.isArray(parsedSteps) || parsedSteps.length < 1) {
      throw new Error('At least one step is required');
    }
    return true;
  }),
  handleValidationErrors
], async (req, res) => {
  try {
    const Activity = require('../../models/Activity');
    const ActivityAssignment = require('../../models/ActivityAssignment');
    
    const { name, description, assistance, dueDate } = req.body;
    const steps = parseArrayField(req.body.steps);
    const mediaUrls = parseArrayField(req.body.mediaUrls);
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
    const formattedSteps = steps
      .map((step, index) => {
        const descriptionText = typeof step === 'string'
          ? step.trim()
          : (step && typeof step.description === 'string' ? step.description.trim() : '');
        return {
          stepNumber: index + 1,
          description: descriptionText
        };
      })
      .filter((step) => step.description.length > 0);

    if (!formattedSteps.length) {
      return res.status(400).json({
        success: false,
        message: 'At least one step is required'
      });
    }

    // Format mediaUrls properly (convert to objects with url and type)
    const formattedMediaUrls = mediaUrls
      .map((media) => {
        const url = typeof media === 'string'
          ? media.trim()
          : (media && typeof media.url === 'string' ? media.url.trim() : '');
        if (!url) return null;
        const type = (media && typeof media === 'object' && media.type === 'video')
          ? 'video'
          : 'image';
        return { url, type };
      })
      .filter(Boolean);

    if (req.file) {
      const imageUrl = `${req.protocol}://${req.get('host')}/uploads/activity-images/${req.file.filename}`;
      formattedMediaUrls.unshift({ url: imageUrl, type: 'image' });
    }

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
      activityName: activity.name,
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
        mediaUrls: activity.mediaUrls,
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

    const activityIds = activities
      .map((activity) => activity?._id)
      .filter(Boolean);

    let dueDateByActivityId = new Map();
    if (activityIds.length) {
      const assignmentDueDates = await ActivityAssignment.aggregate([
        {
          $match: {
            isActive: true,
            activityId: { $in: activityIds },
            dueDate: { $ne: null }
          }
        },
        { $sort: { dueDate: 1 } },
        {
          $group: {
            _id: '$activityId',
            dueDate: { $first: '$dueDate' }
          }
        }
      ]);

      dueDateByActivityId = new Map(
        assignmentDueDates.map((row) => [row._id?.toString(), row.dueDate]),
      );
    }

    const activitiesWithDueDate = activities.map((activity) => {
      const serialized = activity.toObject();
      const assignmentDueDate =
          dueDateByActivityId.get(activity._id?.toString()) ?? null;
      const finalDueDate = assignmentDueDate;

      return {
        ...serialized,
        dueDate: finalDueDate,
        due_date: finalDueDate,
      };
    });

    res.status(200).json({
      success: true,
      total,
      count: activitiesWithDueDate.length,
      data: activitiesWithDueDate
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

router.get('/dashboard-summary', protect, async (req, res) => {
  try {
    if (!ADMIN_ROLES.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Only admins can access this endpoint'
      });
    }

    const recentLimit = Math.min(toPositiveInt(req.query.recentLimit, 6), 10);

    const [
      totalTherapists,
      totalChildren,
      activePrograms,
      pendingPrograms,
      recentAssignments
    ] = await Promise.all([
      User.countDocuments({ role: 'therapist', isActive: true }),
      User.countDocuments({ role: 'child', isActive: true }),
      ActivityAssignment.countDocuments({
        isActive: true,
        completionStatus: { $in: IN_PROGRESS_STATUSES }
      }),
      ActivityAssignment.countDocuments({
        isActive: true,
        completionStatus: { $in: PENDING_STATUSES }
      }),
      ActivityAssignment.find({ isActive: true })
        .select('completionStatus updatedAt createdAt childId')
        .populate('childId', 'Name')
        .sort({ updatedAt: -1 })
        .limit(recentLimit)
        .lean()
    ]);

    const recentActivities = recentAssignments.map((assignment) => {
      const child = assignment.childId;
      const childName = child && typeof child === 'object' && child.Name
        ? child.Name
        : 'Unknown Child';
      const type = (assignment.completionStatus || 'updated').toString();
      return {
        type,
        message: buildRecentActivityMessage(type, childName),
        timestamp: toIsoOrNull(assignment.updatedAt || assignment.createdAt || new Date())
      };
    });

    res.status(200).json({
      success: true,
      data: {
        stats: {
          totalTherapists,
          totalChildren,
          activePrograms,
          pendingPrograms
        },
        recentActivities
      }
    });
  } catch (error) {
    console.error('Error fetching dashboard summary:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching dashboard summary',
      error: error.message
    });
  }
});

router.get('/reports/children-summary', protect, async (req, res) => {
  try {
    if (!ADMIN_ROLES.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Only admins can access this endpoint'
      });
    }

    await ActivityAssignment.markOverduePending();

    const page = toPositiveInt(req.query.page, 1);
    const limit = Math.min(toPositiveInt(req.query.limit, 10), 100);
    const skip = (page - 1) * limit;

    const childFilter = {
      role: 'child',
      isActive: true
    };

    const total = await User.countDocuments(childFilter);

    const children = await User.find(childFilter)
      .select('_id Name assignedTherapist')
      .populate('assignedTherapist', 'Name')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const childIds = children.map((child) => child._id);
    const statsMap = await buildChildStatsMap(childIds);

    const data = children.map((child) => {
      const childId = child._id.toString();
      const stats = statsMap.get(childId) || DEFAULT_REPORT_STATS;
      const therapist = child.assignedTherapist;
      return {
        childId,
        childName: child.Name || 'Unknown',
        therapistId: therapist?._id ? therapist._id.toString() : null,
        therapistName: therapist?.Name || 'Not Assigned',
        stats: {
          total: stats.total,
          completed: stats.completed,
          inProgress: stats.inProgress,
          pending: stats.pending,
          completionRate: stats.completionRate
        },
        lastActivityDate: toIsoOrNull(stats.lastActivityDate)
      };
    });

    res.status(200).json({
      success: true,
      total,
      page,
      limit,
      data
    });
  } catch (error) {
    console.error('Error fetching children summary reports:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching children summary reports',
      error: error.message
    });
  }
});

router.get('/reports/child/:childId', protect, async (req, res) => {
  try {
    if (!ADMIN_ROLES.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Only admins can access this endpoint'
      });
    }

    const { childId } = req.params;
    const includeActivities = toBooleanQuery(req.query.includeActivities, true);
    if (!mongoose.Types.ObjectId.isValid(childId)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid child ID'
      });
    }

    await ActivityAssignment.markOverduePending();

    const child = await User.findOne({
      _id: childId,
      role: 'child',
      isActive: true
    })
      .select('_id Name email assignedTherapist')
      .populate('assignedTherapist', 'Name email')
      .lean();

    if (!child) {
      return res.status(404).json({
        success: false,
        message: 'Child not found'
      });
    }

    const statsMap = await buildChildStatsMap([child._id]);
    const stats = statsMap.get(child._id.toString()) || DEFAULT_REPORT_STATS;

    let activities = [];
    if (includeActivities) {
      const assignments = await ActivityAssignment.find({
        childId: child._id,
        isActive: true
      })
        .populate('activityId', 'name description')
        .sort({ createdAt: -1 })
        .lean();

      activities = assignments.map((assignment) => ({
        assignmentId: assignment._id.toString(),
        activityId: assignment.activityId?._id ? assignment.activityId._id.toString() : assignment.activityId?.toString() || null,
        activityName: assignment.activityName || assignment.activityId?.name || 'Unknown Activity',
        description: assignment.activityId?.description || '',
        completionStatus: assignment.completionStatus,
        score: assignment.score ?? null,
        dueDate: toIsoOrNull(assignment.dueDate),
        startedDate: toIsoOrNull(assignment.startedDate),
        completedDate: toIsoOrNull(assignment.completedDate),
        videoSubmitted: assignment.videoSubmitted === true
      }));
    }

    res.status(200).json({
      success: true,
      data: {
        childId: child._id.toString(),
        childName: child.Name || 'Unknown',
        childEmail: child.email || '',
        therapistId: child.assignedTherapist?._id ? child.assignedTherapist._id.toString() : null,
        therapistName: child.assignedTherapist?.Name || 'Not Assigned',
        therapistEmail: child.assignedTherapist?.email || null,
        stats: {
          total: stats.total,
          completed: stats.completed,
          inProgress: stats.inProgress,
          pending: stats.pending,
          completionRate: stats.completionRate
        },
        lastActivityDate: toIsoOrNull(stats.lastActivityDate),
        activities
      }
    });
  } catch (error) {
    console.error('Error fetching child report detail:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching child report detail',
      error: error.message
    });
  }
});

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

// ==================== ADMIN ALERTS ====================

router.get('/alerts/overdue', protect, async (req, res) => {
  try {
    if (!ADMIN_ROLES.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: 'Only admins can access this endpoint'
      });
    }

    const now = new Date();
    const page = toPositiveInt(req.query.page, 1);
    const limit = Math.min(toPositiveInt(req.query.limit, 20), 100);
    const skip = (page - 1) * limit;

    const filter = buildOverdueAssignmentFilter(now);
    const total = await ActivityAssignment.countDocuments(filter);

    const assignments = await ActivityAssignment.find(filter)
      .select('_id childId activityId activityName dueDate completionStatus')
      .populate({
        path: 'childId',
        select: 'Name assignedTherapist',
        populate: {
          path: 'assignedTherapist',
          select: 'Name'
        }
      })
      .populate('activityId', 'name')
      .sort({ dueDate: 1, createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const data = assignments.map((assignment) => mapAssignmentToOverdueAlert(assignment, now));

    res.status(200).json({
      success: true,
      total,
      data
    });
  } catch (error) {
    console.error('Error fetching admin overdue alerts:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching overdue alerts',
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

// ------------------ ADMIN: Assign therapist and create assignments ------------------
router.put('/children/:id/assign-therapist-with-activities', protect, [
  body('therapistId').notEmpty().withMessage('Therapist ID is required'),
  handleValidationErrors
], async (req, res) => {
  try {
    const { id } = req.params;
    const { therapistId } = req.body;

    // Find child
    const child = await User.findById(id);
    if (!child || child.role !== 'child') {
      return res.status(404).json({ success: false, message: 'Child not found' });
    }

    // Find therapist
    const therapist = await User.findById(therapistId);
    if (!therapist || therapist.role !== 'therapist') {
      return res.status(404).json({ success: false, message: 'Therapist not found' });
    }

    // Authorization: only superuser (admin) can assign therapists
    if (req.user.role !== 'superuser') {
      return res.status(403).json({ success: false, message: 'Only admin can assign therapist to this child' });
    }

    // Update child's assigned therapist
    const updatedChild = await User.findByIdAndUpdate(id, { assignedTherapist: therapistId }, { new: true, runValidators: false }).populate('assignedTherapist', 'Name email');

    // Add child to therapist.assignedPatients set
    await User.findByIdAndUpdate(therapistId, { $addToSet: { assignedPatients: updatedChild._id } });

    // Auto-assign existing therapist-created activities to this child if not already assigned
    const therapistActivities = await Activity.find({ createdBy: therapistId, createdByRole: 'therapist', isActive: true });

    const assignmentsToCreate = [];
    for (const act of therapistActivities) {
      const exists = await ActivityAssignment.exists({ activityId: act._id, childId: updatedChild._id });
      if (!exists) {
        assignmentsToCreate.push({ activityId: act._id, childId: updatedChild._id, dueDate: act.dueDate || null, completionStatus: 'pending' });
      }
    }

    let assignedCount = 0;
    if (assignmentsToCreate.length > 0) {
      const inserted = await ActivityAssignment.insertMany(assignmentsToCreate);
      assignedCount = inserted.length;
    }

    res.status(200).json({ success: true, message: 'Therapist assigned and activities created', data: { id: updatedChild._id, name: updatedChild.Name, assignedTherapist: updatedChild.assignedTherapist, assignedActivitiesCreated: assignedCount } });
  } catch (error) {
    console.error('Error assigning therapist with activities:', error);
    res.status(500).json({ success: false, message: 'Error assigning therapist', error: error.message });
  }
});

module.exports = router;
