const mongoose = require('mongoose');

const NetworkSchema = new mongoose.Schema({
  ssid: {
    type: String,
    required: true,
    trim: true
  },
  bssid: {
    type: String,
    required: true,
    unique: true,
    uppercase: true
  },
  rssi: {
    type: Number,
    required: true
  },
  channel: {
    type: Number,
    required: true
  },
  encType: {
    type: String,
    required: true,
    enum: ['Open', 'WEP', 'WPA', 'WPA2', 'WPA3', 'Unknown']
  },
  firstSeen: {
    type: Date,
    default: Date.now
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  seenCount: {
    type: Number,
    default: 1
  },
  status: {
    type: String,
    enum: ['trusted', 'unknown', 'suspicious'],
    default: 'unknown'
  },
  history: [{
    rssi: Number,
    timestamp: {
      type: Date,
      default: Date.now
    }
  }],
  deviceId: {
    type: String,
    default: 'ESP8266_001'
  }
}, {
  timestamps: true
});

// Index for faster queries
NetworkSchema.index({ bssid: 1 });
NetworkSchema.index({ lastSeen: -1 });
NetworkSchema.index({ status: 1 });

module.exports = mongoose.model('Network', NetworkSchema);
