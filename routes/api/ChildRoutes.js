const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const User = require('../../models/User');
const Activity = require('../../models/Activity');
const ActivityAssignment = require('../../models/ActivityAssignment');

// ==================== MIDDLEWARE ====================
const { protect } = require('../../middleware/auth');
const { handleValidationErrors } = require('../../middleware/validation');

// ==================== CHILD ACTIVITIES ====================

/**
 * @swagger
 * /api/child/activities:
 *   get:
 *     tags:
 *       - Child - Activities
 *     summary: Get all assigned activities for a child
 *     description: Retrieves all active activities assigned to the authenticated child with full details
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Successfully retrieved activities
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
 *       403:
 *         description: Forbidden - User is not a child
 *       500:
 *         description: Server error
 */
router.get('/activities', protect, async (req, res) => {
  try {
    const childId = req.user.id;

    if (req.user.role !== 'child') {
      return res.status(403).json({
        success: false,
        message: 'Only children can access this endpoint'
      });
    }

    const assignments = await ActivityAssignment.find({
      childId,
      isActive: true
    })
      .populate({
        path: 'activityId',
        select: 'name description steps assistance mediaUrls dueDate createdAt'
      })
      .sort({ createdAt: -1 });

    const activities = assignments
      .filter((assignment) => assignment.activityId)
      .map((assignment) => {
        const assistance = assignment.activityId.assistance || null;
        const dueDate = assignment.dueDate || assignment.activityId.dueDate || null;

        return {
          assignmentId: assignment._id,
          activityId: assignment.activityId._id,
          name: assignment.activityId.name,
          description: assignment.activityId.description,
          steps: assignment.activityId.steps,
          assistance,
          assistanceModification: assistance ? [assistance] : [],
          assistance_modification: assistance,
          mediaUrls: assignment.activityId.mediaUrls,
          dueDate,
          due_date: dueDate,
          completionStatus: assignment.getEffectiveStatus(),
          score: assignment.score,
          completionVideoUrl: assignment.completionVideoUrl,
          startedDate: assignment.startedDate,
          completedDate: assignment.completedDate,
          isOverdue: assignment.isOverdue()
        };
      });

    res.status(200).json({
      success: true,
      total: activities.length,
      data: activities
    });
  } catch (error) {
    console.error('Error fetching child activities:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching activities',
      error: error.message
    });
  }
});

/**
 * @swagger
 * /api/child/activities/{assignmentId}/submit:
 *   put:
 *     tags:
 *       - Child - Activities
 *     summary: Submit completed activity with video proof
 *     description: Marks an activity as completed with video URL and optional score
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: assignmentId
 *         required: true
 *         schema:
 *           type: string
 *         description: The activity assignment ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - completionVideoUrl
 *             properties:
 *               completionVideoUrl:
 *                 type: string
 *                 format: url
 *               score:
 *                 type: integer
 *                 minimum: 0
 *                 maximum: 100
 *     responses:
 *       200:
 *         description: Activity submitted successfully
 *       400:
 *         description: Invalid URL or activity already completed
 *       403:
 *         description: Forbidden - User is not a child
 *       404:
 *         description: Activity assignment not found
 *       500:
 *         description: Server error
 */
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Setup storage for child activity uploads (make sure this is available to routes below)
const ensureDir = (dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
};

const videoUploadDir = path.join(process.cwd(), 'uploads', 'child-activity-videos');
ensureDir(videoUploadDir);

const videoStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, videoUploadDir),
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    const safeBase = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${timestamp}_${safeBase}`);
  }
});

const videoFileFilter = (req, file, cb) => {
  const allowed = ['video/mp4','video/quicktime','video/x-msvideo','video/x-matroska','audio/mpeg'];
  if (allowed.includes(file.mimetype)) return cb(null, true);
  cb(new Error('Invalid file type. Only MP4/QuickTime/AVI/MKV or MP3 are allowed.'));
};

const uploadVideo = multer({ storage: videoStorage, limits: { fileSize: 200 * 1024 * 1024 }, fileFilter: videoFileFilter });

router.put('/activities/:assignmentId/submit', protect, async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const { videoUrl } = req.body || {};

    if (req.user.role !== 'child') {
      return res.status(403).json({
        success: false,
        message: 'Only children can submit activities'
      });
    }

    const assignment = await ActivityAssignment.findById(assignmentId);

    if (!assignment) {
      return res.status(404).json({ success: false, message: 'Activity assignment not found' });
    }

    if (!assignment.isActive) {
      return res.status(404).json({ success: false, message: 'Activity assignment not found' });
    }

    if (assignment.childId?.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'You are not allowed to submit for this assignment'
      });
    }

    if (!videoUrl || typeof videoUrl !== 'string') {
      return res.status(400).json({
        success: false,
        message: 'Video URL is required'
      });
    }
    const normalizedVideoUrl = videoUrl.trim();
    if (!normalizedVideoUrl) {
      return res.status(400).json({
        success: false,
        message: 'Video URL is required'
      });
    }

    assignment.completionVideoUrl = normalizedVideoUrl;
    assignment.completionStatus = 'submitted';
    if (!assignment.startedDate) {
      assignment.startedDate = new Date();
    }
    await assignment.save();

    return res.status(200).json({
      success: true,
      message: 'Video link submitted successfully',
      data: {
        assignmentId: assignment._id,
        completionStatus: assignment.completionStatus,
        completionVideoUrl: assignment.completionVideoUrl
      }
    });
  } catch (error) {
    console.error('Error submitting activity:', error);
    res.status(500).json({ success: false, message: 'Error submitting activity', error: error.message });
  }
});

/**
 * @swagger
 * /api/child/activities/{assignmentId}/start:
 *   put:
 *     tags:
 *       - Child - Activities
 *     summary: Start an activity
 *     description: Marks an activity as in-progress and records the start date
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: assignmentId
 *         required: true
 *         schema:
 *           type: string
 *         description: The activity assignment ID
 *     responses:
 *       200:
 *         description: Activity started successfully
 *       400:
 *         description: Activity is already in progress or completed
 *       403:
 *         description: Forbidden - User is not a child
 *       404:
 *         description: Activity assignment not found
 *       500:
 *         description: Server error
 */
router.put('/activities/:assignmentId/start', protect, async (req, res) => {
  try {
    const childId = req.user.id;
    const { assignmentId } = req.params;

    if (req.user.role !== 'child') {
      return res.status(403).json({
        success: false,
        message: 'Only children can start activities'
      });
    }

    const assignment = await ActivityAssignment.findOne({
      _id: assignmentId,
      childId,
      isActive: true
    });

    if (!assignment) {
      return res.status(404).json({
        success: false,
        message: 'Activity assignment not found'
      });
    }

    if (assignment.completionStatus !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Activity is already in progress or completed'
      });
    }

    const updatedAssignment = await ActivityAssignment.findByIdAndUpdate(
      assignmentId,
      {
        completionStatus: 'in-progress',
        startedDate: new Date()
      },
      { new: true, runValidators: false }
    ).populate('activityId', 'name');

    res.status(200).json({
      success: true,
      message: 'Activity started',
      data: {
        assignmentId: updatedAssignment._id,
        activityName: updatedAssignment.activityId.name,
        completionStatus: updatedAssignment.completionStatus,
        startedDate: updatedAssignment.startedDate
      }
    });
  } catch (error) {
    console.error('Error starting activity:', error);
    res.status(500).json({
      success: false,
      message: 'Error starting activity',
      error: error.message
    });
  }
});

// ==================== CHILD REPORTS ====================

// -------------------- Video Upload for Activity Completion --------------------
/**
 * @swagger
 * /api/child/activities/{assignmentId}/upload:
 *   post:
 *     tags:
 *       - Child - Activities
 *     summary: Upload a completed activity video
 *     description: Accepts multipart/form-data with a single file field `videoFile` and returns a publicly accessible URL for the uploaded video.
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: path
 *         name: assignmentId
 *         required: true
 *         schema:
 *           type: string
 *         description: The activity assignment ID
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               videoFile:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: File uploaded successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 url:
 *                   type: string
 */
// video upload storage / multer configuration moved above to be available to submit endpoint

router.post('/activities/:assignmentId/upload', protect, uploadVideo.single('videoFile'), async (req, res) => {
  try {
    // Only children can upload for their assignments
    if (req.user.role !== 'child') {
      return res.status(403).json({ success: false, message: 'Only children can upload activity videos' });
    }

    const { assignmentId } = req.params;
    const assignment = await ActivityAssignment.findById(assignmentId);
    if (!assignment) {
      return res.status(404).json({ success: false, message: 'Activity assignment not found' });
    }

    const assignmentChildId =
      (assignment.childId && assignment.childId.toString()) ||
      (assignment.child && assignment.child.toString()) ||
      '';
    if (assignmentChildId !== req.user.id) {
      return res.status(403).json({ success: false, message: 'You are not allowed to upload for this assignment' });
    }

    if (!assignment.isActive) {
      return res.status(404).json({ success: false, message: 'Activity assignment not found' });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Video file is required' });
    }

    const publicUrl = `${req.protocol}://${req.get('host')}/uploads/child-activity-videos/${req.file.filename}`;
    assignment.completionVideoUrl = publicUrl;
    assignment.completionStatus = 'submitted';
    if (!assignment.startedDate) {
      assignment.startedDate = new Date();
    }
    await assignment.save();

    console.log('UPLOAD DEBUG:', {
      assignmentId,
      status: assignment.completionStatus,
      video: assignment.completionVideoUrl
    });

    return res.status(200).json({
      success: true,
      message: 'Video uploaded successfully',
      data: {
        assignmentId: assignment._id,
        completionStatus: assignment.completionStatus,
        completionVideoUrl: assignment.completionVideoUrl
      },
      url: publicUrl
    });
  } catch (error) {
    console.error('Error uploading video:', error);
    res.status(500).json({ success: false, message: 'Error uploading video', error: error.message });
  }
});

/**
 * @swagger
 * /api/child/report:
 *   get:
 *     tags:
 *       - Child - Report
 *     summary: Get child's personal progress report
 *     description: Retrieves authenticated child's progress report showing activity completion status, scores, and performance metrics
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Successfully retrieved child progress report
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 *                   properties:
 *                     childId:
 *                       type: string
 *                     childName:
 *                       type: string
 *                     childEmail:
 *                       type: string
 *                     totalActivities:
 *                       type: integer
 *                     completed:
 *                       type: integer
 *                     pending:
 *                       type: integer
 *                     inProgress:
 *                       type: integer
 *                     notCompleted:
 *                       type: integer
 *                     completionPercentage:
 *                       type: integer
 *                       example: 60
 *                     averageScore:
 *                       type: number
 *                       example: 85
 *                     activities:
 *                       type: array
 *                       items:
 *                         type: object
 *                         properties:
 *                           assignmentId:
 *                             type: string
 *                           activityName:
 *                             type: string
 *                           completionStatus:
 *                             type: string
 *                           score:
 *                             type: number
 *                           completedDate:
 *                             type: string
 *                             format: date-time
 *       403:
 *         description: Forbidden - User is not a child
 *       500:
 *         description: Server error
 */
router.get('/report', protect, async (req, res) => {
  try {
    const childId = req.user.id;

    if (req.user.role !== 'child') {
      return res.status(403).json({
        success: false,
        message: 'Only children can access this endpoint'
      });
    }

    // Auto-mark overdue pending/in-progress assignments as not-completed
    await ActivityAssignment.markOverduePending();

    // Get child's basic info
    const child = await User.findById(childId).select('Name email');

    if (!child) {
      return res.status(404).json({
        success: false,
        message: 'Child profile not found'
      });
    }

    // Get all active assignments for the child
    const assignments = await ActivityAssignment.find({
      childId,
      isActive: true
    })
      .populate('activityId', 'name dueDate')
      .sort({ createdAt: -1 });

    // Calculate statistics using effective status (accounts for overdue)
    const completed = assignments.filter(a => a.getEffectiveStatus() === 'completed').length;
    const pending = assignments.filter(a => a.getEffectiveStatus() === 'pending').length;
    const inProgress = assignments.filter(a => a.getEffectiveStatus() === 'in-progress').length;
    const notCompleted = assignments.filter(a => a.getEffectiveStatus() === 'not-completed').length;
    const totalActivities = assignments.length;
    const completionPercentage = totalActivities > 0 ? Math.round((completed / totalActivities) * 100) : 0;
    const averageScore = assignments.length > 0 
      ? Math.round(assignments.reduce((sum, a) => sum + (a.score || 0), 0) / assignments.length)
      : 0;

    // Map activity details
    const activities = assignments.map(assignment => ({
      assignmentId: assignment._id,
      activityName: assignment.activityId?.name || 'Unknown Activity',
      completionStatus: assignment.getEffectiveStatus(),
      score: assignment.score || null,
      dueDate: assignment.activityId?.dueDate || null,
      completedDate: assignment.completedDate,
      startedDate: assignment.startedDate,
      isOverdue: assignment.isOverdue()
    }));

    res.status(200).json({
      success: true,
      data: {
        childId,
        childName: child.Name,
        childEmail: child.email,
        totalActivities,
        completed,
        pending,
        inProgress,
        notCompleted,
        completionPercentage,
        averageScore,
        activities
      }
    });
  } catch (error) {
    console.error('Error fetching child report:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching report',
      error: error.message
    });
  }
});

module.exports = router;
