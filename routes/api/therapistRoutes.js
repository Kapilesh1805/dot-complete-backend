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

const mapAssignmentToOverdueAlert = (assignment, now, fallbackTherapist) => {
  const child = assignment.childId;
  const childId = child && typeof child === 'object' && child._id
    ? child._id.toString()
    : assignment.childId?.toString() || '';

  const therapist = child && typeof child === 'object' && child.assignedTherapist
    ? child.assignedTherapist
    : null;

  const therapistId = therapist && typeof therapist === 'object' && therapist._id
    ? therapist._id.toString()
    : fallbackTherapist.id;

  const therapistName = therapist && typeof therapist === 'object' && therapist.Name
    ? therapist.Name
    : fallbackTherapist.name;

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
    therapistName,
    dueDate: toIsoOrNull(assignment.dueDate) || '',
    daysOverdue: toDaysOverdue(assignment.dueDate, now),
    completionStatus: (assignment.completionStatus || 'pending').toString()
  };
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
    const { name, description, assistance, dueDate } = req.body;
    const steps = parseArrayField(req.body.steps);
    const mediaUrls = parseArrayField(req.body.mediaUrls);
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

    let parsedDueDate = null;
    if (dueDate) {
      const parsed = new Date(dueDate);
      if (!Number.isNaN(parsed.getTime())) {
        parsedDueDate = parsed;
      }
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

    // Assign to therapist's assigned children only
    const assignedChildren = await User.find({ 
      role: 'child', 
      assignedTherapist: userId, 
      isActive: true 
    });

    const assignmentPayloads = assignedChildren.map((child) => ({
      activityId: activity._id,
      childId: child._id,
      dueDate: parsedDueDate ? parsedDueDate.toISOString() : null,
    }));
    console.log('Assign activity payload:', assignmentPayloads);
    console.log('Saving assignment dueDate:', parsedDueDate);

    const assignments = assignedChildren.map((child) => ({
      activityId: activity._id,
      activityName: activity.name,
      childId: child._id,
      dueDate: parsedDueDate || null,
      completionStatus: 'pending',
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

router.delete('/activities/:activityId', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    const { activityId } = req.params;

    if (req.user.role !== 'therapist') {
      return res.status(403).json({
        success: false,
        message: 'Only therapists can delete activities'
      });
    }

    if (!mongoose.Types.ObjectId.isValid(activityId)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid activity ID'
      });
    }

    const activity = await Activity.findOne({
      _id: activityId,
      createdBy: userId,
      isActive: true
    });

    if (!activity) {
      return res.status(404).json({
        success: false,
        message: 'Activity not found'
      });
    }

    activity.isActive = false;
    await activity.save();

    const assignmentUpdateResult = await ActivityAssignment.updateMany(
      { activityId: activity._id, isActive: true },
      { $set: { isActive: false } }
    );

    const deactivatedAssignments = assignmentUpdateResult.modifiedCount ?? assignmentUpdateResult.nModified ?? 0;

    return res.status(200).json({
      success: true,
      message: 'Activity deleted successfully',
      data: {
        activityId: activity._id.toString(),
        deactivatedAssignments
      }
    });
  } catch (error) {
    console.error('Error deleting therapist activity:', error);
    return res.status(500).json({
      success: false,
      message: 'Error deleting activity',
      error: error.message
    });
  }
});

// ==================== THERAPIST REPORTS ====================

/**
 * @swagger
 * /api/therapist/submissions:
 *   get:
 *     summary: Get submitted activity videos from therapist's assigned children
 *     tags: [Therapist - Activities]
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: List of submissions
 */
router.get('/submissions', protect, async (req, res) => {
  try {
    const userId = req.user.id;
    if (req.user.role !== 'therapist') {
      return res.status(403).json({ success: false, message: 'Only therapists can access submissions' });
    }

    const assignedChildren = await User.find({
      assignedTherapist: userId,
      role: 'child',
      isActive: true
    }).select('_id Name');
    const childIds = assignedChildren.map((child) => child._id);
    console.log('THERAPIST DEBUG:', {
      therapistId: userId,
      childIds
    });

    if (!childIds.length) {
      return res.status(200).json({ success: true, total: 0, data: [] });
    }

    // Temporary diagnostics to identify which filter removes records.
    const baseFilter = {
      childId: { $in: childIds },
      isActive: true
    };
    const videoFilter = {
      ...baseFilter,
      completionVideoUrl: { $nin: [null, ''] }
    };
    const relaxedStatusFilter = {
      ...videoFilter,
      completionStatus: { $in: ['submitted', 'pending', 'not-completed'] }
    };
    const strictSubmittedFilter = {
      ...videoFilter,
      completionStatus: 'submitted'
    };

    const [totalForChildren, activeForChildren, withVideo, relaxedStatusMatches, strictSubmittedMatches] = await Promise.all([
      ActivityAssignment.countDocuments({ childId: { $in: childIds } }),
      ActivityAssignment.countDocuments(baseFilter),
      ActivityAssignment.countDocuments(videoFilter),
      ActivityAssignment.countDocuments(relaxedStatusFilter),
      ActivityAssignment.countDocuments(strictSubmittedFilter)
    ]);
    console.log('THERAPIST SUBMISSION FILTER DEBUG:', {
      totalForChildren,
      activeForChildren,
      withVideo,
      relaxedStatusMatches,
      strictSubmittedMatches
    });

    const submissions = await ActivityAssignment.find({
      childId: { $in: childIds },
      isActive: true,
      completionStatus: 'submitted',
      completionVideoUrl: { $nin: [null, ''] }
    })
      .populate('childId', 'Name')
      .populate('activityId', 'name')
      .sort({ updatedAt: -1 });
    console.log('SUBMISSIONS FOUND:', submissions.length);

    const payload = submissions.map((assignment) => ({
      assignmentId: assignment._id?.toString() || '',
      childId: assignment.childId?._id?.toString() || assignment.childId?.toString() || '',
      childName:
        (assignment.childId &&
          typeof assignment.childId === 'object' &&
          assignment.childId.Name) ||
        'Unknown Child',
      activityId: assignment.activityId?._id?.toString() || assignment.activityId?.toString() || '',
      activityName:
        assignment.activityName ||
        (assignment.activityId &&
          typeof assignment.activityId === 'object' &&
          assignment.activityId.name) ||
        'Unknown Activity',
      completionVideoUrl: assignment.completionVideoUrl || '',
      submittedAt: toIsoOrNull(assignment.updatedAt) || toIsoOrNull(assignment.createdAt),
      completionStatus: (assignment.completionStatus || 'pending').toString()
    }));

    return res.status(200).json({
      success: true,
      total: payload.length,
      data: payload
    });
  } catch (error) {
    console.error('Error fetching submissions:', error);
    return res.status(500).json({ success: false, message: 'Error fetching submissions', error: error.message });
  }
});

router.put('/activities/:assignmentId/approve', protect, async (req, res) => {
  try {
    const therapistId = req.user.id;
    if (req.user.role !== 'therapist') {
      return res.status(403).json({
        success: false,
        message: 'Only therapists can approve activity submissions'
      });
    }

    const { assignmentId } = req.params;
    if (!mongoose.Types.ObjectId.isValid(assignmentId)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid assignment id'
      });
    }

    const assignment = await ActivityAssignment.findById(assignmentId);
    if (!assignment || !assignment.isActive) {
      return res.status(404).json({
        success: false,
        message: 'Activity assignment not found'
      });
    }

    const child = await User.findOne({
      _id: assignment.childId,
      role: 'child',
      isActive: true,
      assignedTherapist: therapistId
    }).select('_id');

    if (!child) {
      return res.status(403).json({
        success: false,
        message: 'You are not allowed to approve this submission'
      });
    }

    if (assignment.completionStatus !== 'submitted') {
      return res.status(400).json({
        success: false,
        message: 'Only submitted activities can be approved'
      });
    }

    assignment.completionStatus = 'completed';
    assignment.completedDate = new Date();
    await assignment.save();

    return res.status(200).json({
      success: true,
      message: 'Activity approved successfully',
      data: {
        assignmentId: assignment._id?.toString() || '',
        completionStatus: assignment.completionStatus,
        completedDate: toIsoOrNull(assignment.completedDate)
      }
    });
  } catch (error) {
    console.error('Error approving activity submission:', error);
    return res.status(500).json({
      success: false,
      message: 'Error approving activity submission',
      error: error.message
    });
  }
});

/**
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
router.get('/reports/children-summary', protect, async (req, res) => {
  try {
    const therapistId = req.user.id;

    if (req.user.role !== 'therapist') {
      return res.status(403).json({
        success: false,
        message: 'Only therapists can access this endpoint'
      });
    }

    await ActivityAssignment.markOverduePending();

    const page = toPositiveInt(req.query.page, 1);
    const limit = Math.min(toPositiveInt(req.query.limit, 10), 100);
    const skip = (page - 1) * limit;

    const childFilter = {
      role: 'child',
      isActive: true,
      assignedTherapist: therapistId
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
        therapistId: therapist?._id ? therapist._id.toString() : therapistId,
        therapistName: therapist?.Name || 'Therapist',
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
    console.error('Error fetching therapist children summary reports:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching children summary reports',
      error: error.message
    });
  }
});

// Keep static therapist routes above parameterized routes.
router.get('/children', protect, async (req, res) => {
  try {
    console.log('Therapist children route hit');
    const therapistId = req.user.id;

    if (req.user.role !== 'therapist') {
      return res.status(403).json({
        success: false,
        message: 'Only therapists can access this endpoint'
      });
    }

    const children = await User.find({
      assignedTherapist: req.user.id,
      role: 'child',
      isActive: true
    })
      .select('_id Name firstName lastName email gender parentName phoneNumber age dateOfBirth condition assignedTherapist createdAt updatedAt')
      .populate('assignedTherapist', 'Name email')
      .sort({ createdAt: -1 });

    return res.status(200).json({
      success: true,
      total: children.length,
      data: children
    });
  } catch (error) {
    console.error('Error fetching therapist children:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching therapist children',
      error: error.message
    });
  }
});

router.get('/reports/child/:childId', protect, async (req, res) => {
  try {
    const therapistId = req.user.id;

    if (req.user.role !== 'therapist') {
      return res.status(403).json({
        success: false,
        message: 'Only therapists can access this endpoint'
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
      isActive: true,
      assignedTherapist: therapistId
    })
      .select('_id Name email assignedTherapist')
      .populate('assignedTherapist', 'Name email')
      .lean();

    if (!child) {
      return res.status(404).json({
        success: false,
        message: 'Child not found for this therapist'
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
        therapistId: child.assignedTherapist?._id ? child.assignedTherapist._id.toString() : therapistId,
        therapistName: child.assignedTherapist?.Name || 'Therapist',
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
    console.error('Error fetching therapist child report detail:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching child report detail',
      error: error.message
    });
  }
});

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
  body('email')
    .isEmail()
    .withMessage('Valid email is required')
    .normalizeEmail(),
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
      dateOfBirth,
      password,
      confirmPassword
    } = req.body;

    console.log('Assigned therapist:', req.user.id);

    const safeChildName = childName?.toString().trim() || '';
    const safeEmail = email?.toString().trim().toLowerCase();
    const safeParentName = parentName?.toString().trim() || '';
    const safePhoneNo = phoneNo?.toString().trim() || '';
    const safeCondition = condition?.toString().trim() || '';

    if (!safeEmail || !safeEmail.includes('@')) {
      return res.status(400).json({
        success: false,
        message: 'Invalid email format'
      });
    }

    // Check if passwords match
    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }

    // Check if email already exists
    const existingUser = await User.findOne({ email: safeEmail });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Email already in use'
      });
    }

    console.log('CHILD CREATED WITH PASSWORD LENGTH:', password?.length);

    // Create child user
    const child = await User.create({
      Name: safeChildName,
      firstName: safeChildName.split(' ')[0] || safeChildName,
      lastName: safeChildName.split(' ').slice(1).join(' ') || '',
      email: safeEmail,
      password,
      role: 'child',
      age,
      gender,
      parentName: safeParentName,
      condition: safeCondition,
      phoneNumber: safePhoneNo,
      dateOfBirth: typeof dateOfBirth === 'string' && dateOfBirth.trim().length
        ? dateOfBirth.trim()
        : null,
      assignedTherapist: req.user.id,
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
        dateOfBirth: child.dateOfBirth,
        condition: safeCondition,
        parentName: safeParentName,
        phoneNo: safePhoneNo,
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

// One-time manual migration script (run in Mongo shell once):
// db.users.updateMany(
//   { role: 'child', email: { $not: /@/ } },
//   { $set: { isActive: false } }
// );

// ==================== THERAPIST ALERTS ====================

router.get('/alerts/overdue', protect, async (req, res) => {
  try {
    const therapistId = req.user.id;

    if (req.user.role !== 'therapist') {
      return res.status(403).json({
        success: false,
        message: 'Only therapists can access this endpoint'
      });
    }

    const now = new Date();
    const page = toPositiveInt(req.query.page, 1);
    const limit = Math.min(toPositiveInt(req.query.limit, 20), 100);
    const skip = (page - 1) * limit;

    const assignedChildren = await User.find({
      role: 'child',
      isActive: true,
      assignedTherapist: therapistId
    })
      .select('_id')
      .lean();

    const childIds = assignedChildren.map((child) => child._id);
    if (!childIds.length) {
      return res.status(200).json({
        success: true,
        total: 0,
        data: []
      });
    }

    const filter = buildOverdueAssignmentFilter(now, {
      childId: { $in: childIds }
    });

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

    const fallbackTherapist = {
      id: therapistId?.toString() || '',
      name: req.user.Name || 'Therapist'
    };

    const data = assignments.map((assignment) =>
      mapAssignmentToOverdueAlert(assignment, now, fallbackTherapist)
    );

    res.status(200).json({
      success: true,
      total,
      data
    });
  } catch (error) {
    console.error('Error fetching therapist overdue alerts:', error);
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
