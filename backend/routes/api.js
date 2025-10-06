const express = require('express');
const ThreatDetector = require('../services/threatDetection');
const Network = require('../models/Network');
const router = express.Router();

// Middleware to validate API key
const validateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.headers['authorization'];
  
  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({ 
      error: 'Unauthorized: Invalid or missing API key' 
    });
  }
  
  next();
};

// POST /api/scan - Receive scan data from ESP8266
// POST /api/scan - Receive scan data from ESP8266 with threat analysis
router.post('/scan', validateApiKey, async (req, res) => {
  try {
    const { networks, deviceId = 'ESP8266_001' } = req.body;
    
    if (!networks || !Array.isArray(networks)) {
      return res.status(400).json({ 
        error: 'Invalid payload: networks array required' 
      });
    }

    console.log(`Received ${networks.length} networks from ${deviceId}`);
    
    const results = {
      processed: 0,
      updated: 0,
      created: 0,
      threats: [],
      errors: []
    };

    // Get all existing networks for threat analysis
    const allNetworks = await Network.find({});

    for (const networkData of networks) {
      try {
        const { ssid, bssid, rssi, channel, encType } = networkData;
        
        if (!bssid) {
          results.errors.push(`Missing BSSID for network: ${ssid}`);
          continue;
        }

        // Upsert logic: update if exists, create if new
        const filter = { bssid: bssid.toUpperCase() };
        const update = {
          ssid: ssid || 'Hidden Network',
          rssi,
          channel,
          encType: encType || 'Unknown',
          lastSeen: new Date(),
          deviceId,
          $inc: { seenCount: 1 },
          $push: {
            history: {
              rssi,
              timestamp: new Date(),
              $slice: -20 // Keep only last 20 entries
            }
          }
        };

        const options = {
          upsert: true,
          new: true,
          setDefaultsOnInsert: true
        };

        const network = await Network.findOneAndUpdate(filter, update, options);
        
        // Perform threat analysis
        const threatAssessment = ThreatDetector.assessThreat(
          network, 
          allNetworks, 
          network.history || []
        );

        // Auto-update network status based on threat level
        let autoStatus = network.status;
        if (threatAssessment.isHarmful && network.status === 'unknown') {
          autoStatus = 'suspicious';
          await Network.findByIdAndUpdate(network._id, { status: 'suspicious' });
        }

        // Store threat assessment results
        if (threatAssessment.threats.length > 0) {
          results.threats.push({
            ssid: network.ssid,
            bssid: network.bssid,
            riskLevel: threatAssessment.riskLevel,
            harmScore: threatAssessment.harmScore,
            threats: threatAssessment.threats,
            recommendation: threatAssessment.recommendation,
            isHarmful: threatAssessment.isHarmful
          });

          console.log(`⚠️  THREAT DETECTED: ${network.ssid} (${network.bssid}) - Risk: ${threatAssessment.riskLevel}, Score: ${threatAssessment.harmScore}`);
        }
        
        if (network.seenCount === 1) {
          results.created++;
        } else {
          results.updated++;
        }
        
        results.processed++;

      } catch (error) {
        results.errors.push(`Error processing ${networkData.bssid}: ${error.message}`);
      }
    }

    // Log threat summary
    if (results.threats.length > 0) {
      console.log(`🚨 SECURITY ALERT: ${results.threats.length} threats detected in this scan`);
      
      const criticalThreats = results.threats.filter(t => t.riskLevel === 'critical').length;
      const highThreats = results.threats.filter(t => t.riskLevel === 'high').length;
      
      if (criticalThreats > 0) console.log(`❌ CRITICAL THREATS: ${criticalThreats}`);
      if (highThreats > 0) console.log(`⚠️  HIGH THREATS: ${highThreats}`);
    }

    res.json({
      success: true,
      message: `Processed ${results.processed} networks`,
      securitySummary: {
        threatsDetected: results.threats.length,
        criticalThreats: results.threats.filter(t => t.riskLevel === 'critical').length,
        highThreats: results.threats.filter(t => t.riskLevel === 'high').length,
        harmfulNetworks: results.threats.filter(t => t.isHarmful).length
      },
      ...results
    });

  } catch (error) {
    console.error('Scan endpoint error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message 
    });
  }
});

// GET /api/networks - Get all networks for dashboard
router.get('/networks', async (req, res) => {
  try {
    const { 
      status, 
      search,
      limit = 100,
      sortBy = 'lastSeen',
      order = 'desc'
    } = req.query;

    let filter = {};
    
    if (status && status !== 'all') {
      filter.status = status;
    }
    
    if (search) {
      filter.$or = [
        { ssid: { $regex: search, $options: 'i' } },
        { bssid: { $regex: search, $options: 'i' } }
      ];
    }

    const networks = await Network.find(filter)
      .sort({ [sortBy]: order === 'desc' ? -1 : 1 })
      .limit(parseInt(limit))
      .select('-__v');

    res.json({
      success: true,
      count: networks.length,
      networks
    });

  } catch (error) {
    console.error('Networks endpoint error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch networks',
      message: error.message 
    });
  }
});

// PATCH /api/networks/:id/status - Update network status
router.patch('/networks/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    if (!['trusted', 'unknown', 'suspicious'].includes(status)) {
      return res.status(400).json({ 
        error: 'Invalid status. Must be: trusted, unknown, or suspicious' 
      });
    }

    const network = await Network.findByIdAndUpdate(
      id,
      { status },
      { new: true, select: '-__v' }
    );

    if (!network) {
      return res.status(404).json({ error: 'Network not found' });
    }

    res.json({
      success: true,
      message: 'Network status updated',
      network
    });

  } catch (error) {
    console.error('Status update error:', error);
    res.status(500).json({ 
      error: 'Failed to update status',
      message: error.message 
    });
  }
});

// GET /api/stats - Get dashboard statistics
router.get('/stats', async (req, res) => {
  try {
    const stats = await Network.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    const totalNetworks = await Network.countDocuments();
    const recentlyActive = await Network.countDocuments({
      lastSeen: { $gte: new Date(Date.now() - 10 * 60 * 1000) } // Last 10 minutes
    });

    const statusCounts = {
      trusted: 0,
      unknown: 0,
      suspicious: 0
    };

    stats.forEach(stat => {
      statusCounts[stat._id] = stat.count;
    });

    res.json({
      success: true,
      stats: {
        total: totalNetworks,
        recentlyActive,
        ...statusCounts
      }
    });

  } catch (error) {
    console.error('Stats endpoint error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch statistics',
      message: error.message 
    });
  }
});
// GET /api/threats - Get threat analysis for all networks
router.get('/threats', async (req, res) => {
  try {
    const networks = await Network.find({}).select('-__v');
    const threats = [];

    for (const network of networks) {
      const threatAssessment = ThreatDetector.assessThreat(
        network, 
        networks, 
        network.history || []
      );

      if (threatAssessment.threats.length > 0 || threatAssessment.harmScore > 0) {
        threats.push(threatAssessment);
      }
    }

    // Sort by harm score (highest first)
    threats.sort((a, b) => b.harmScore - a.harmScore);

    res.json({
      success: true,
      totalNetworks: networks.length,
      threatsAnalyzed: threats.length,
      summary: {
        critical: threats.filter(t => t.riskLevel === 'critical').length,
        high: threats.filter(t => t.riskLevel === 'high').length,
        medium: threats.filter(t => t.riskLevel === 'medium').length,
        low: threats.filter(t => t.riskLevel === 'low').length,
        harmful: threats.filter(t => t.isHarmful).length
      },
      threats
    });

  } catch (error) {
    console.error('Threats endpoint error:', error);
    res.status(500).json({ 
      error: 'Failed to analyze threats',
      message: error.message 
    });
  }
});

module.exports = router;
