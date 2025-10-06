const threatPatterns = {
  // Suspicious SSID patterns
  suspiciousSSIDs: [
    /free.?wifi/i,
    /guest.?network/i,
    /open.?wifi/i,
    /wifi.?free/i,
    /hotspot/i,
    /android.?ap/i,
    /iphone.?hotspot/i,
    /mobile.?hotspot/i
  ],
  
  // Evil Twin Attack Detection
  evilTwinIndicators: [
    'linksys', 'netgear', 'tp-link', 'dlink', 'asus'
  ],
  
  // Deauth Attack Patterns
  deauthPatterns: {
    rapidSignalChanges: 20, // dBm change in short time
    abnormalChannelHopping: 3, // channels changed quickly
    highSeenCount: 100 // seen too frequently
  }
};

class ThreatDetector {
  static assessThreat(network, allNetworks, historicalData = []) {
    const threats = [];
    let riskLevel = 'low';
    let harmScore = 0;

    // 1. Suspicious SSID Detection
    const ssidThreat = this.checkSuspiciousSSID(network.ssid);
    if (ssidThreat) {
      threats.push(ssidThreat);
      harmScore += 30;
    }

    // 2. Evil Twin Detection
    const evilTwin = this.detectEvilTwin(network, allNetworks);
    if (evilTwin) {
      threats.push(evilTwin);
      harmScore += 50;
    }

    // 3. Open Network Security Risk
    const openNetworkRisk = this.checkOpenNetwork(network);
    if (openNetworkRisk) {
      threats.push(openNetworkRisk);
      harmScore += 25;
    }

    // 4. Abnormal Signal Pattern Detection
    const signalAnomaly = this.detectSignalAnomalies(network, historicalData);
    if (signalAnomaly) {
      threats.push(signalAnomaly);
      harmScore += 35;
    }

    // 5. Channel Interference Detection
    const channelThreat = this.detectChannelThreats(network, allNetworks);
    if (channelThreat) {
      threats.push(channelThreat);
      harmScore += 20;
    }

    // 6. MAC Address Analysis
    const macThreat = this.analyzeMACAddress(network.bssid);
    if (macThreat) {
      threats.push(macThreat);
      harmScore += 15;
    }

    // Determine overall risk level
    if (harmScore >= 70) riskLevel = 'critical';
    else if (harmScore >= 40) riskLevel = 'high';
    else if (harmScore >= 20) riskLevel = 'medium';

    return {
      networkId: network._id,
      ssid: network.ssid,
      bssid: network.bssid,
      riskLevel,
      harmScore,
      threats,
      recommendation: this.getRecommendation(riskLevel, threats),
      isHarmful: harmScore >= 40,
      timestamp: new Date()
    };
  }

  static checkSuspiciousSSID(ssid) {
    if (!ssid || ssid === 'Hidden Network') return null;

    for (const pattern of threatPatterns.suspiciousSSIDs) {
      if (pattern.test(ssid)) {
        return {
          type: 'suspicious_ssid',
          severity: 'medium',
          description: `Potentially deceptive network name: "${ssid}"`,
          details: 'This SSID pattern is commonly used by attackers for social engineering'
        };
      }
    }
    return null;
  }

  static detectEvilTwin(network, allNetworks) {
    // Look for multiple networks with same/similar SSID but different BSSID
    const similarNetworks = allNetworks.filter(n => 
      n.ssid === network.ssid && n.bssid !== network.bssid
    );

    if (similarNetworks.length > 0) {
      // Check if one has weaker security
      const hasWeakerSecurity = similarNetworks.some(n => 
        (network.encType === 'Open' && n.encType !== 'Open') ||
        (network.encType === 'WEP' && ['WPA', 'WPA2', 'WPA3'].includes(n.encType))
      );

      if (hasWeakerSecurity || network.encType === 'Open') {
        return {
          type: 'evil_twin',
          severity: 'high',
          description: `Potential Evil Twin attack detected for "${network.ssid}"`,
          details: `Found ${similarNetworks.length + 1} networks with same name but different security levels`
        };
      }
    }
    return null;
  }

  static checkOpenNetwork(network) {
    if (network.encType === 'Open') {
      return {
        type: 'open_network',
        severity: 'medium',
        description: 'Unsecured wireless network detected',
        details: 'Open networks can be used for man-in-the-middle attacks and data interception'
      };
    }
    return null;
  }

  static detectSignalAnomalies(network, historicalData) {
    if (historicalData.length < 5) return null;

    const recentSignals = historicalData.slice(-10).map(h => h.rssi);
    const avgSignal = recentSignals.reduce((a, b) => a + b, 0) / recentSignals.length;
    const signalVariation = Math.max(...recentSignals) - Math.min(...recentSignals);

    // Detect unusual signal strength changes
    if (signalVariation > threatPatterns.deauthPatterns.rapidSignalChanges) {
      return {
        type: 'signal_anomaly',
        severity: 'medium',
        description: 'Unusual signal strength fluctuations detected',
        details: `Signal variation of ${signalVariation}dBm may indicate deauth attacks or jamming`
      };
    }

    // Detect abnormally high seen count (possible spam/flooding)
    if (network.seenCount > threatPatterns.deauthPatterns.highSeenCount) {
      return {
        type: 'high_frequency',
        severity: 'medium',
        description: 'Abnormally high detection frequency',
        details: 'This network appears unusually often, may indicate probe flooding'
      };
    }

    return null;
  }

  static detectChannelThreats(network, allNetworks) {
    const sameChannelNetworks = allNetworks.filter(n => n.channel === network.channel);
    
    // Too many networks on same channel (potential jamming)
    if (sameChannelNetworks.length > 15) {
      return {
        type: 'channel_congestion',
        severity: 'low',
        description: `High network density on channel ${network.channel}`,
        details: `${sameChannelNetworks.length} networks detected on same channel`
      };
    }
    return null;
  }

  static analyzeMACAddress(bssid) {
    if (!bssid) return null;

    const macPrefix = bssid.substring(0, 8).toUpperCase();
    
    // Check for randomized/fake MAC addresses
    const suspiciousPrefixes = [
      '02:00:00', // Locally administered
      'AA:BB:CC', // Obviously fake
      '00:11:22', // Test patterns
      '12:34:56'  // Sequential patterns
    ];

    if (suspiciousPrefixes.some(prefix => macPrefix.startsWith(prefix))) {
      return {
        type: 'suspicious_mac',
        severity: 'low',
        description: 'Potentially spoofed MAC address detected',
        details: 'MAC address pattern suggests possible device identity masking'
      };
    }
    return null;
  }

  static getRecommendation(riskLevel, threats) {
    const recommendations = {
      critical: 'IMMEDIATE ACTION REQUIRED: Block this network and investigate immediately. High probability of malicious activity.',
      high: 'CAUTION: Avoid connecting to this network. Monitor closely and consider blocking.',
      medium: 'WARNING: Exercise caution. Verify network legitimacy before connecting.',
      low: 'INFO: Minor security concerns detected. Standard security practices recommended.'
    };

    let specific = [];
    threats.forEach(threat => {
      switch(threat.type) {
        case 'evil_twin':
          specific.push('Verify with network administrator which is the legitimate network');
          break;
        case 'open_network':
          specific.push('Use VPN if connection is necessary');
          break;
        case 'suspicious_ssid':
          specific.push('Verify network legitimacy with venue staff');
          break;
        case 'signal_anomaly':
          specific.push('Monitor for deauth attacks or jamming attempts');
          break;
      }
    });

    return {
      general: recommendations[riskLevel],
      specific: specific.length > 0 ? specific : ['Follow standard WiFi security practices']
    };
  }
}

module.exports = ThreatDetector;
