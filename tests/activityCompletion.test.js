const request = require('supertest');
const app = require('../server');
const mongoose = require('mongoose');
const User = require('../models/User');
const HomeProgram = require('../models/HomeProgram');
const ActivityAssignment = require('../models/ActivityAssignment');
const Activity = require('../models/Activity');
const Progress = require('../models/Progress');

// Test data
let testChild, testTherapist, testActivity, testProgram, testAssignment, authToken, therapistToken;

describe('Activity Completion Tracking API', () => {
  beforeAll(async () => {
    // Create test users
    testChild = await User.create({
      firstName: 'Test',
      lastName: 'Child',
      email: 'testchild@example.com',
      password: 'password123',
      role: 'child',
      isEmailVerified: true
    });

    testTherapist = await User.create({
      firstName: 'Test',
      lastName: 'Therapist',
      email: 'testtherapist@example.com',
      password: 'password123',
      role: 'therapist',
      isEmailVerified: true,
      assignedPatients: [testChild._id]
    });

    // Create test activity
    testActivity = await Activity.create({
      title: 'Test Math Activity',
      description: 'Basic addition and subtraction',
      category: 'math',
      difficulty: 'medium',
      createdBy: testTherapist._id,
      status: 'published'
    });

    // Create test program
    testProgram = await HomeProgram.create({
      childId: testChild._id,
      assignedBy: testTherapist._id,
      title: 'Test Program',
      description: 'Test program for completion tracking',
      items: [{
        activityId: testActivity._id,
        targetFrequencyPerWeek: 3,
        notes: 'Test activity'
      }],
      status: 'active'
    });

    // Create test assignment
    testAssignment = await ActivityAssignment.create({
      childId: testChild._id,
      activityId: testActivity._id,
      assignedBy: testTherapist._id,
      status: 'completed',
      progress: {
        completionPercent: 100,
        score: 85,
        submittedAt: new Date(),
        notesFromParent: 'Great work!'
      }
    });

    // Create test progress entry
    await Progress.create({
      userId: testChild._id,
      programId: testProgram._id,
      activityId: testActivity._id,
      progressPercentage: 75,
      completedTasks: ['Task 1', 'Task 2'],
      notes: 'Making good progress',
      milestone: 'three-quarters',
      score: 80,
      timeSpent: 30,
      difficulty: 'medium',
      mood: 'good'
    });

    // Complete program item
    const program = await HomeProgram.findById(testProgram._id);
    const item = program.items[0];
    item.completions.push({
      completedAt: new Date(),
      score: 90,
      notes: 'Excellent work!'
    });
    item.status = 'completed';
    await program.save();

    // Get auth tokens
    const childLogin = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'testchild@example.com',
        password: 'password123'
      });

    const therapistLogin = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'testtherapist@example.com',
        password: 'password123'
      });

    authToken = childLogin.body.token;
    therapistToken = therapistLogin.body.token;
  });

  afterAll(async () => {
    // Clean up test data
    await User.deleteMany({ email: { $in: ['testchild@example.com', 'testtherapist@example.com'] } });
    await Activity.deleteMany({ title: 'Test Math Activity' });
    await HomeProgram.deleteMany({ title: 'Test Program' });
    await ActivityAssignment.deleteMany({ childId: testChild._id });
    await Progress.deleteMany({ userId: testChild._id });
    await mongoose.connection.close();
  });

  describe('GET /api/progress/:userId/activity-completion', () => {
    it('should get activity completion statistics for a child', async () => {
      const response = await request(app)
        .get(`/api/progress/${testChild._id}/activity-completion`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.child._id).toBe(testChild._id.toString());
      expect(response.body.data.statistics).toBeDefined();
      expect(response.body.data.statistics.totalActivitiesAssigned).toBeGreaterThan(0);
      expect(response.body.data.statistics.completedAssignments).toBeGreaterThan(0);
      expect(response.body.data.statistics.totalProgramActivities).toBeGreaterThan(0);
      expect(response.body.data.statistics.completedProgramActivities).toBeGreaterThan(0);
      expect(response.body.data.statistics.completionRate).toBeGreaterThan(0);
      expect(response.body.data.recentCompletions).toBeInstanceOf(Array);
      expect(response.body.data.activityBreakdown).toBeDefined();
    });

    it('should filter by date range', async () => {
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - 7);
      const endDate = new Date();

      const response = await request(app)
        .get(`/api/progress/${testChild._id}/activity-completion`)
        .query({
          startDate: startDate.toISOString(),
          endDate: endDate.toISOString()
        })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.statistics).toBeDefined();
    });

    it('should filter by program ID', async () => {
      const response = await request(app)
        .get(`/api/progress/${testChild._id}/activity-completion`)
        .query({ programId: testProgram._id })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.statistics).toBeDefined();
    });

    it('should deny access to unauthorized users', async () => {
      const unauthorizedUser = await User.create({
        firstName: 'Unauthorized',
        lastName: 'User',
        email: 'unauthorized@example.com',
        password: 'password123',
        role: 'child',
        isEmailVerified: true
      });

      const unauthorizedLogin = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'unauthorized@example.com',
          password: 'password123'
        });

      const response = await request(app)
        .get(`/api/progress/${testChild._id}/activity-completion`)
        .set('Authorization', `Bearer ${unauthorizedLogin.body.token}`)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Access denied');

      // Clean up
      await User.deleteOne({ _id: unauthorizedUser._id });
    });
  });

  describe('GET /api/progress/children/completion-summary', () => {
    it('should get completion summary for all children (therapist)', async () => {
      const response = await request(app)
        .get('/api/progress/children/completion-summary')
        .set('Authorization', `Bearer ${therapistToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.children).toBeInstanceOf(Array);
      expect(response.body.data.pagination).toBeDefined();
      expect(response.body.data.summary).toBeDefined();
      expect(response.body.data.children.length).toBeGreaterThan(0);
    });

    it('should support pagination', async () => {
      const response = await request(app)
        .get('/api/progress/children/completion-summary')
        .query({ page: 1, limit: 5 })
        .set('Authorization', `Bearer ${therapistToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.pagination.currentPage).toBe(1);
      expect(response.body.data.pagination.totalPages).toBeGreaterThan(0);
    });

    it('should support sorting', async () => {
      const response = await request(app)
        .get('/api/progress/children/completion-summary')
        .query({ sortBy: 'completionRate', sortOrder: 'desc' })
        .set('Authorization', `Bearer ${therapistToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.children).toBeInstanceOf(Array);
    });

    it('should deny access to regular users', async () => {
      const response = await request(app)
        .get('/api/progress/children/completion-summary')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(403);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Access denied');
    });
  });

  describe('GET /api/progress/:userId/activity-details', () => {
    it('should get detailed activity completion information', async () => {
      const response = await request(app)
        .get(`/api/progress/${testChild._id}/activity-details`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.child._id).toBe(testChild._id.toString());
      expect(response.body.data.timeline).toBeInstanceOf(Array);
      expect(response.body.data.activityStatistics).toBeInstanceOf(Array);
      expect(response.body.data.assignments).toBeInstanceOf(Array);
      expect(response.body.data.programs).toBeInstanceOf(Array);
      expect(response.body.data.progressEntries).toBeInstanceOf(Array);
    });

    it('should filter by activity category', async () => {
      const response = await request(app)
        .get(`/api/progress/${testChild._id}/activity-details`)
        .query({ category: 'math' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.filters.category).toBe('math');
    });

    it('should filter by assignment status', async () => {
      const response = await request(app)
        .get(`/api/progress/${testChild._id}/activity-details`)
        .query({ status: 'completed' })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.filters.status).toBe('completed');
    });

    it('should filter by program ID', async () => {
      const response = await request(app)
        .get(`/api/progress/${testChild._id}/activity-details`)
        .query({ programId: testProgram._id })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.filters.programId).toBe(testProgram._id.toString());
    });

    it('should filter by activity ID', async () => {
      const response = await request(app)
        .get(`/api/progress/${testChild._id}/activity-details`)
        .query({ activityId: testActivity._id })
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.filters.activityId).toBe(testActivity._id.toString());
    });
  });

  describe('Data Integration', () => {
    it('should correctly aggregate data from all sources', async () => {
      const response = await request(app)
        .get(`/api/progress/${testChild._id}/activity-completion`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const stats = response.body.data.statistics;
      
      // Should have data from assignments
      expect(stats.totalActivitiesAssigned).toBeGreaterThan(0);
      expect(stats.completedAssignments).toBeGreaterThan(0);
      
      // Should have data from programs
      expect(stats.totalProgramActivities).toBeGreaterThan(0);
      expect(stats.completedProgramActivities).toBeGreaterThan(0);
      
      // Should have data from progress entries
      expect(stats.totalProgressEntries).toBeGreaterThan(0);
      
      // Should calculate completion rate correctly
      const totalActivities = stats.totalActivitiesAssigned + stats.totalProgramActivities;
      const completedActivities = stats.completedAssignments + stats.completedProgramActivities;
      const expectedCompletionRate = totalActivities > 0 ? (completedActivities / totalActivities) * 100 : 0;
      
      expect(stats.completionRate).toBeCloseTo(expectedCompletionRate, 1);
    });

    it('should provide activity breakdown by category', async () => {
      const response = await request(app)
        .get(`/api/progress/${testChild._id}/activity-completion`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const breakdown = response.body.data.activityBreakdown;
      expect(breakdown).toBeDefined();
      expect(typeof breakdown).toBe('object');
      
      // Should have math category since we created a math activity
      if (breakdown.math) {
        expect(breakdown.math.total).toBeGreaterThan(0);
        expect(breakdown.math.completed).toBeGreaterThan(0);
      }
    });

    it('should provide recent completions timeline', async () => {
      const response = await request(app)
        .get(`/api/progress/${testChild._id}/activity-completion`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const recentCompletions = response.body.data.recentCompletions;
      expect(recentCompletions).toBeInstanceOf(Array);
      expect(recentCompletions.length).toBeGreaterThan(0);
      
      // Should have both assignment and program completions
      const types = recentCompletions.map(c => c.type);
      expect(types).toContain('assignment');
      expect(types).toContain('program');
    });
  });

  describe('Performance and Edge Cases', () => {
    it('should handle empty data gracefully', async () => {
      // Create a new child with no activities
      const emptyChild = await User.create({
        firstName: 'Empty',
        lastName: 'Child',
        email: 'empty@example.com',
        password: 'password123',
        role: 'child',
        isEmailVerified: true
      });

      const emptyChildLogin = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'empty@example.com',
          password: 'password123'
        });

      const response = await request(app)
        .get(`/api/progress/${emptyChild._id}/activity-completion`)
        .set('Authorization', `Bearer ${emptyChildLogin.body.token}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.statistics.completionRate).toBe(0);
      expect(response.body.data.recentCompletions).toEqual([]);

      // Clean up
      await User.deleteOne({ _id: emptyChild._id });
    });

    it('should handle invalid user ID', async () => {
      const fakeId = new mongoose.Types.ObjectId();
      const response = await request(app)
        .get(`/api/progress/${fakeId}/activity-completion`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.data.statistics.completionRate).toBe(0);
    });
  });

  // New tests for Missing Activity List and Activity List APIs
  describe('Activity List and Missing Activity List APIs', () => {
    // Test: Get Missing Activities
    describe('GET /api/activities/missing', () => {
      it('should return a list of missing activities', async () => {
        const response = await request(app).get('/api/activities/missing');
        expect(response.status).toBe(200);
        expect(Array.isArray(response.body)).toBe(true);
      });

      it('should return a list of missing activities where videoSubmitted is false', async () => {
        // Mock data
        await ActivityAssignment.create({
          activityName: 'Speech Therapy',
          completionStatus: 'in-progress',
          dueDate: new Date('2026-02-01'),
          videoSubmitted: false,
          childId: 'child_001',
        });

        const response = await request(app).get('/api/activities/missing');
        expect(response.status).toBe(200);
        expect(Array.isArray(response.body)).toBe(true);
        expect(response.body[0].videoSubmitted).toBe(false);
      });
    });

    // Test: Get All Activities
    describe('GET /api/activities/list', () => {
      it('should return a list of all activities', async () => {
        const response = await request(app).get('/api/activities/list');
        expect(response.status).toBe(200);
        expect(Array.isArray(response.body)).toBe(true);
      });
    });
  });
});
