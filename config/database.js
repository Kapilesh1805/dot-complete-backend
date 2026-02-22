const mongoose = require('mongoose');

const connectDB = async () => {
  // Retry logic: try to connect multiple times to handle transient network issues
  const options = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  };

  const maxAttempts = 5;
  let attempt = 0;

  while (attempt < maxAttempts) {
    attempt++;
    try {
      console.log(`🔄 Connecting to MongoDB Atlas... (Attempt ${attempt}/${maxAttempts})`);
      const conn = await mongoose.connect(process.env.MONGO_URI, options);

      console.log('✅ MongoDB Atlas Connected Successfully!');
      console.log(`📍 Host: ${conn.connection.host}`);
      console.log(`🗄️  Database: ${conn.connection.name}`);
      return;
    } catch (error) {
      console.error(`❌ MongoDB Connection Error (attempt ${attempt}):`, error.message);
      if (attempt < maxAttempts) {
        const waitMs = 2000 * attempt; // exponential-ish backoff
        console.log(`🔁 Retrying in ${waitMs / 1000}s...`);
        await new Promise(res => setTimeout(res, waitMs));
        continue;
      } else {
        console.error('❌ All connection attempts failed. Please verify MONGO_URI and network connectivity.');
        // Exit process with failure
        process.exit(1);
      }
    }
  }
};

// Handle MongoDB connection events
mongoose.connection.on('connected', () => {
  console.log('📡 Mongoose connected to MongoDB Atlas');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ Mongoose connection error:', err.message);
});

let _reconnectAttempts = 0;
const _maxReconnectAttempts = 5;

mongoose.connection.on('disconnected', async () => {
  console.log('⚠️ Mongoose disconnected from MongoDB Atlas');

  if (_reconnectAttempts >= _maxReconnectAttempts) {
    console.error('❌ Maximum reconnection attempts reached after disconnect. Exiting process.');
    process.exit(1);
  }

  _reconnectAttempts++;
  const waitMs = 3000 * _reconnectAttempts;
  console.log(`🔁 Attempting reconnection (${_reconnectAttempts}/${_maxReconnectAttempts}) in ${waitMs / 1000}s...`);
  await new Promise(res => setTimeout(res, waitMs));
  try {
    await connectDB();
    console.log('🔌 Reconnection to MongoDB successful.');
    _reconnectAttempts = 0; // reset on success
  } catch (err) {
    console.error('❌ Reconnection attempt failed:', err.message || err);
  }
});

// Graceful close on app termination
process.on('SIGINT', async () => {
  try {
    await mongoose.connection.close();
    console.log('🔌 MongoDB Atlas connection closed through app termination');
    process.exit(0);
  } catch (err) {
    console.error('❌ Error closing MongoDB connection:', err);
    process.exit(1);
  }
});

module.exports = connectDB;