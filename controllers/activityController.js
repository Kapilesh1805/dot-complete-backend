const ActivityAssignment = require('../models/ActivityAssignment');

// Controller: Get Missing Activities
exports.getMissingActivities = async (req, res) => {
  try {
    const { therapistId, childId } = req.query;

    const filter = {
      completionStatus: { $ne: 'completed' },
      videoSubmitted: false,
      ...(therapistId && { therapistId }),
      ...(childId && { childId }),
    };

    const missingActivities = await ActivityAssignment.find(filter).populate('childId', 'name age gender');

    res.status(200).json(missingActivities);
  } catch (error) {
    console.error('Error fetching missing activities:', error);
    res.status(500).json({ error: 'Failed to fetch missing activities' });
  }
};

// Controller: Get All Activities
exports.getActivities = async (req, res) => {
  try {
    const { therapistId, childId } = req.query;

    const filter = {
      ...(therapistId && { therapistId }),
      ...(childId && { childId }),
    };

    const activities = await ActivityAssignment.find(filter).populate('childId', 'name age gender');

    res.status(200).json(activities);
  } catch (error) {
    console.error('Error fetching activities:', error);
    res.status(500).json({ error: 'Failed to fetch activities' });
  }
};