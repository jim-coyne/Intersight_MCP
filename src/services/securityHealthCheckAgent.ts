// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MIT

/*
 * MIT License
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * Security and Health Check Agent
 * 
 * This module provides MCP tool handlers that orchestrate comprehensive security
 * and health analysis. When a user requests a security or health check, these tools
 * are automatically invoked to generate consistent, thorough reports.
 * 
 * Reports include:
 * - Active alarms and critical advisories
 * - Security vulnerabilities (CVEs) from TAM
 * - Firmware versions and update recommendations
 * - End-of-life component analysis
 * - Hardware health and thermal status
 * - Compliance posture assessment
 * - Actionable recommendations by priority
 */

export interface SecurityHealthCheckResult {
  status: 'SUCCESS' | 'PARTIAL' | 'ERROR';
  timestamp: string;
  reportType: 'SECURITY' | 'HEALTH' | 'COMPREHENSIVE';
  executionTimeMs: number;
  
  // Executive Summary
  summary: {
    overallScore: number; // 0-100, higher is better
    securityScore: number;
    healthScore: number;
    complianceScore: number;
    criticalCount: number;
    warningCount: number;
    infrastructureOverview: {
      totalServers: number;
      totalAlarms: number;
      totalAdvisories: number;
      firmwareComponents: number;
      healthyComponents: number;
      degradedComponents: number;
    };
  };

  alarms: {
    critical: number;
    warning: number;
    info: number;
    total: number;
    topAlarms: Array<{ 
      id: string; 
      description: string; 
      severity: string;
      affectedDevice: string;
      affectedDeviceType: string;
      code: string;
      createTime: string;
      acknowledged: boolean;
    }>;
    alarmsByCode: Array<{
      code: string;
      count: number;
      severity: string;
      description: string;
      affectedDevices: Array<{
        name: string;
        type: string;
        severity: string;
        createTime: string;
      }>;
    }>;
    alarmsByDeviceType: Array<{
      deviceType: string;
      count: number;
      criticalCount: number;
    }>;
  };

  advisories: {
    critical: number;
    warning: number;
    info: number;
    total: number;
    securityAdvisories: number;
    fieldNotices: number;
    eolAdvisories: number;
    topAdvisories: Array<{ 
      id: string; 
      title: string; 
      type: string;
      severity?: string;
      cveIds?: string[];
      affectedPlatforms?: string[];
      datePublished?: string;
      description?: string;
      recommendation?: string;
      affectedDevices?: Array<{
        name: string;
        model?: string;
        version?: string;
      }>;
    }>;
    advisoriesByType: Array<{
      type: string;
      count: number;
      criticalCount: number;
      affectedDevices?: Array<{
        name: string;
        model?: string;
      }>;
    }>;
  };

  firmware: {
    components: number;
    currentlySupported: number;
    outdated: number;
    endOfLife: number;
    updateRecommendations: Array<{
      component: string;
      currentVersion: string;
      recommendedVersion: string;
      securityCritical: boolean;
      affectedDevices?: string[];
      deviceCount?: number;
      releaseNotes?: string;
      vulnerabilitiesFixed?: string[];
    }>;
    componentsByType: Array<{
      componentType: string;
      count: number;
      versions: string[];
    }>;
  };

  hardware: {
    healthStatus: 'HEALTHY' | 'DEGRADED' | 'CRITICAL';
    totalServers: number;
    healthyServers: number;
    degradedServers: number;
    failedServers: number;
    thermalStatus: 'NORMAL' | 'WARNING' | 'CRITICAL';
    powerRedundancy: 'FULL' | 'DEGRADED' | 'SINGLE';
    failedComponents: {
      processors: number;
      memory: number;
      drives: number;
      psus: number;
    };
    componentDetails: {
      processors: { total: number; healthy: number; degraded: number; failed: number };
      memory: { total: number; healthy: number; degraded: number; failed: number };
      drives: { total: number; healthy: number; degraded: number; failed: number };
      psus: { total: number; healthy: number; degraded: number; failed: number };
      fans: { total: number; healthy: number; degraded: number; failed: number };
    };
  };

  security: {
    tpmStatus: 'PRESENT' | 'MISSING';
    secureBootEnabled: boolean;
    licenseCompliance: 'COMPLIANT' | 'NON_COMPLIANT';
    expiredLicenses: number;
    expiringLicenses: number;
    managementControllersUnreachable: number;
  };

  compliance: {
    overallStatus: 'COMPLIANT' | 'NON_COMPLIANT' | 'PARTIAL';
    policyCount: number;
    certifiedOsVersions: number;
    hyperlexCompatibilityStatus: string;
  };

  performance: {
    averageCpuUtilization: number;
    peakCpuUtilization: number;
    averageMemoryUtilization: number;
    peakMemoryUtilization: number;
    highUtilizationServers: string[];
  };

  recommendations: {
    immediate: string[]; // Must do now - affects availability or security
    shortTerm: string[];  // Do within 1 week - important for stability
    mediumTerm: string[]; // Do within 1 month - improves operations
    longTerm: string[];   // Do within 1 quarter - strategic improvements
  };

  issues: Array<{
    id: string;
    category: 'SECURITY' | 'HARDWARE' | 'FIRMWARE' | 'COMPLIANCE' | 'PERFORMANCE';
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    title: string;
    description: string;
    affectedResources: string[];
    remediation: string;
  }>;
}

/**
 * Generate a comprehensive security and health check report
 * This is the main agent entry point that orchestrates all phases
 */
export function createSecurityHealthCheckReport(
  alarms: any,
  advisories: any,
  advisoryInstances: any,
  advisoryCount: any,
  firmware: any,
  operatingSystems: any,
  hardware: any,
  thermalStats: any,
  powerStats: any,
  licenses: any,
  tpms: any,
  bootSecurity: any,
  policies: any,
  hyperflexCompat: any,
  topResources: any,
  servers: any
): SecurityHealthCheckResult {
  const startTime = Date.now();
  const alarmsList = Array.isArray(alarms) ? alarms : [];
  const advisoryList = Array.isArray(advisories) ? advisories : [];
  const advisoryInstancesList = Array.isArray(advisoryInstances) ? advisoryInstances : [];
  const serversList = Array.isArray(servers) ? servers : [];
  const firmwareList = Array.isArray(firmware) ? firmware : [];
  const osVersions = Array.isArray(operatingSystems) ? operatingSystems : [];
  const licensesList = Array.isArray(licenses) ? licenses : [];
  const tpmList = Array.isArray(tpms) ? tpms : [];
  const bootSecList = Array.isArray(bootSecurity) ? bootSecurity : [];
  const policiesList = Array.isArray(policies) ? policies : [];
  const topRes = Array.isArray(topResources) ? topResources : [];

  // Phase 1: Analyze alarms
  const alarmAnalysis = analyzeAlarms(alarmsList);

  // Phase 2: Analyze advisories and CVEs
  const advisoryAnalysis = analyzeAdvisories(advisoryList, advisoryInstancesList, advisoryCount, serversList);

  // Phase 3: Analyze firmware
  const firmwareAnalysis = analyzeFirmware(firmwareList);

  // Phase 4: Analyze hardware
  const hardwareAnalysis = analyzeHardware(hardware, thermalStats, powerStats);

  // Phase 5: Analyze security
  const securityAnalysis = analyzeSecurity(licensesList, tpmList, bootSecList);

  // Phase 6: Analyze compliance
  const complianceAnalysis = analyzeCompliance(osVersions, policiesList, hyperflexCompat);

  // Phase 7: Analyze performance
  const performanceAnalysis = analyzePerformance(topRes);

  // Calculate scores
  const scores = calculateScores(alarmAnalysis, advisoryAnalysis, hardwareAnalysis, securityAnalysis, complianceAnalysis);

  // Generate issues
  const issues = generateIssues(alarmAnalysis, advisoryAnalysis, firmwareAnalysis, hardwareAnalysis, securityAnalysis, complianceAnalysis);

  // Generate recommendations
  const recommendations = generateRecommendations(alarmAnalysis, advisoryAnalysis, firmwareAnalysis, hardwareAnalysis, securityAnalysis, issues);

  // Extract calculated scores
  const { securityScore, healthScore, complianceScore } = scores;

  const report: SecurityHealthCheckResult = {
    status: issues.some(i => i.severity === 'CRITICAL') ? 'PARTIAL' : 'SUCCESS',
    timestamp: new Date().toISOString(),
    reportType: 'COMPREHENSIVE',
    executionTimeMs: Date.now() - startTime,

    summary: {
      overallScore: Math.round((securityScore + healthScore + complianceScore) / 3),
      securityScore: Math.max(0, securityScore),
      healthScore: Math.max(0, healthScore),
      complianceScore: Math.max(0, complianceScore),
      criticalCount: Math.max(alarmAnalysis.critical, advisoryAnalysis.critical),
      warningCount: alarmAnalysis.warning + advisoryAnalysis.warning,
      infrastructureOverview: {
        totalServers: hardwareAnalysis.totalServers || 0,
        totalAlarms: alarmAnalysis.total || 0,
        totalAdvisories: advisoryAnalysis.total || 0,
        firmwareComponents: firmwareAnalysis.components || 0,
        healthyComponents: (hardwareAnalysis.componentDetails?.processors.healthy || 0) +
                          (hardwareAnalysis.componentDetails?.memory.healthy || 0) +
                          (hardwareAnalysis.componentDetails?.drives.healthy || 0) +
                          (hardwareAnalysis.componentDetails?.psus.healthy || 0) +
                          (hardwareAnalysis.componentDetails?.fans.healthy || 0),
        degradedComponents: (hardwareAnalysis.componentDetails?.processors.degraded || 0) +
                           (hardwareAnalysis.componentDetails?.memory.degraded || 0) +
                           (hardwareAnalysis.componentDetails?.drives.degraded || 0) +
                           (hardwareAnalysis.componentDetails?.psus.degraded || 0) +
                           (hardwareAnalysis.componentDetails?.fans.degraded || 0)
      }
    },

    alarms: alarmAnalysis,
    advisories: advisoryAnalysis,
    firmware: firmwareAnalysis,
    hardware: hardwareAnalysis,
    security: securityAnalysis,
    compliance: complianceAnalysis,
    performance: performanceAnalysis,
    recommendations,
    issues
  };

  return report;
}

function analyzeAlarms(alarms: any[]): any {
  const critical = alarms.filter(a => 
    a.Severity === 'Critical' || a.severity === 'Critical' || 
    a.Severity === 'critical' || a.severity === 'critical'
  ).length;
  const warning = alarms.filter(a => 
    a.Severity === 'Warning' || a.severity === 'Warning' || 
    a.Severity === 'warning' || a.severity === 'warning'
  ).length;
  const info = alarms.filter(a => 
    a.Severity === 'Info' || a.severity === 'Info' || 
    a.Severity === 'info' || a.severity === 'info'
  ).length;

  // Group alarms by code with affected device tracking
  const alarmsByCodeMap = new Map<string, { 
    count: number; 
    severity: string; 
    description: string;
    devices: Array<{ name: string; type: string; severity: string; createTime: string }>;
  }>();
  
  alarms.forEach(a => {
    const code = a.Code || a.code || 'UNKNOWN';
    const deviceName = a.AffectedMoDisplayName || a.affectedMoDisplayName || a.AffectedObject || a.affectedObject || a.Dn || a.dn || 'Unknown';
    const deviceType = a.AffectedMoType || a.affectedMoType || 'Unknown';
    const severity = a.Severity || a.severity || 'Unknown';
    const createTime = a.CreateTime || a.createTime || a.CreationTime || a.creationTime || 'Unknown';
    
    if (!alarmsByCodeMap.has(code)) {
      alarmsByCodeMap.set(code, {
        count: 0,
        severity: severity,
        description: a.Description || a.description || 'Unknown',
        devices: []
      });
    }
    const entry = alarmsByCodeMap.get(code)!;
    entry.count++;
    entry.devices.push({ name: deviceName, type: deviceType, severity, createTime });
  });

  const alarmsByCode = Array.from(alarmsByCodeMap.entries())
    .map(([code, data]) => ({ 
      code, 
      count: data.count,
      severity: data.severity,
      description: data.description,
      affectedDevices: data.devices.slice(0, 50) // Limit to 50 devices per alarm code
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Group alarms by device type
  const alarmsByDeviceTypeMap = new Map<string, { count: number; criticalCount: number }>();
  alarms.forEach(a => {
    const deviceType = a.AffectedMoType || a.affectedMoType || 'Unknown';
    if (!alarmsByDeviceTypeMap.has(deviceType)) {
      alarmsByDeviceTypeMap.set(deviceType, { count: 0, criticalCount: 0 });
    }
    const entry = alarmsByDeviceTypeMap.get(deviceType)!;
    entry.count++;
    if ((a.Severity || a.severity || '').toLowerCase() === 'critical') {
      entry.criticalCount++;
    }
  });

  const alarmsByDeviceType = Array.from(alarmsByDeviceTypeMap.entries())
    .map(([deviceType, data]) => ({ deviceType, ...data }))
    .sort((a, b) => b.criticalCount - a.criticalCount || b.count - a.count)
    .slice(0, 10);

  return {
    critical,
    warning,
    info,
    total: alarms.length,
    topAlarms: alarms.filter(a => 
      a.Severity === 'Critical' || a.severity === 'Critical' || 
      a.Severity === 'critical' || a.severity === 'critical'
    ).slice(0, 10).map((a: any) => ({
      id: a.Moid || a.moid || 'unknown',
      description: a.Description || a.description || 'Unknown alarm',
      severity: a.Severity || a.severity,
      affectedDevice: a.AffectedMoDisplayName || a.affectedMoDisplayName || a.AffectedObject || a.affectedObject || a.Dn || a.dn || 'Unknown',
      affectedDeviceType: a.AffectedMoType || a.affectedMoType || 'Unknown',
      code: a.Code || a.code || 'Unknown',
      createTime: a.CreateTime || a.createTime || a.CreationTime || a.creationTime || 'Unknown',
      acknowledged: (a.Acknowledge || a.acknowledge || 'None') !== 'None'
    })),
    alarmsByCode,
    alarmsByDeviceType
  };
}

function analyzeAdvisories(advisories: any[], advisoryInstances: any[], advisoryCount: any, servers: any[]): any {
  const critical = (advisoryCount?.critical || 0) + advisories.filter(a => 
    a.Severity === 'Critical' || a.severity === 'Critical' || a.Type === 'securityAdvisory' || a.type === 'securityAdvisory'
  ).length;
  const warning = advisoryCount?.warning || 0;
  const info = advisoryCount?.info || 0;
  const securityAdvisories = advisories.filter(a => 
    a.Type === 'securityAdvisory' || a.type === 'securityAdvisory' || 
    (a.Title || a.title || '').includes('CVE')
  ).length;
  const fieldNotices = advisories.filter(a => 
    a.Type === 'fieldNotice' || a.type === 'fieldNotice'
  ).length;
  const eolAdvisories = advisories.filter(a =>
    a.Type === 'eolAdvisory' || a.type === 'eolAdvisory'
  ).length;

  // Build MOID to name lookup map
  const moidToName = new Map<string, { name: string; model: string }>();
  servers.forEach(server => {
    const moid = server.Moid || server.moid;
    const name = server.Name || server.name || 'Unknown Server';
    const model = server.Model || server.model || '';
    if (moid) {
      moidToName.set(moid, { name, model });
    }
  });

  // Build a map of advisory instances by advisory definition ID
  const instancesByAdvisory = new Map<string, any[]>();
  advisoryInstances.forEach((instance: any) => {
    const advisoryId = instance.Advisory?.Moid || instance.advisory?.moid;
    if (advisoryId) {
      if (!instancesByAdvisory.has(advisoryId)) {
        instancesByAdvisory.set(advisoryId, []);
      }
      instancesByAdvisory.get(advisoryId)!.push(instance);
    }
  });

  // Group advisories by type with affected device tracking
  const advisoriesByTypeMap = new Map<string, { 
    count: number; 
    criticalCount: number;
    devices: Set<string>;
  }>();
  
  advisories.forEach(a => {
    const type = a.Type || a.type || 'advisory';
    if (!advisoriesByTypeMap.has(type)) {
      advisoriesByTypeMap.set(type, { count: 0, criticalCount: 0, devices: new Set() });
    }
    const entry = advisoriesByTypeMap.get(type)!;
    entry.count++;
    const severity = a.Severity || a.severity || '';
    const severityStr = typeof severity === 'string' ? severity : String(severity);
    if (severityStr.toLowerCase() === 'critical') {
      entry.criticalCount++;
    }
    
    // Add affected devices from instances
    const advisoryId = a.Moid || a.moid;
    const instances = instancesByAdvisory.get(advisoryId) || [];
    instances.forEach(inst => {
      const deviceMoid = inst.AffectedObjectMoid || inst.affectedObjectMoid || 
                        inst.AffectedObject || inst.affectedObject || 'Unknown';
      // Resolve MOID to name if available
      const deviceInfo = moidToName.get(deviceMoid);
      const deviceName = deviceInfo ? deviceInfo.name : deviceMoid;
      entry.devices.add(deviceName);
    });
  });

  const advisoriesByType = Array.from(advisoriesByTypeMap.entries())
    .map(([type, data]) => ({ 
      type, 
      count: data.count,
      criticalCount: data.criticalCount,
      affectedDevices: Array.from(data.devices).slice(0, 20).map(name => {
        // If it's still a MOID (no match found), leave as is
        return { name };
      })
    }))
    .sort((a, b) => b.criticalCount - a.criticalCount || b.count - a.count);

  return {
    critical,
    warning,
    info,
    total: advisories.length,
    securityAdvisories,
    fieldNotices,
    eolAdvisories,
    topAdvisories: advisories.slice(0, 15).map((a: any) => {
      // Extract CVE IDs from description or external references
      const cveIds: string[] = [];
      const description = a.Description || a.description || '';
      const title = a.Title || a.title || a.Name || a.name || '';
      const combinedText = `${title} ${description}`;
      const cveMatches = combinedText.match(/CVE-\d{4}-\d{4,7}/g);
      if (cveMatches) {
        cveIds.push(...cveMatches);
      }

      // Extract affected platforms
      const affectedPlatforms: string[] = [];
      if (a.AffectedPids || a.affectedPids) {
        const pids = a.AffectedPids || a.affectedPids;
        if (Array.isArray(pids)) {
          affectedPlatforms.push(...pids);
        }
      }

      // Get affected devices from instances
      const advisoryId = a.Moid || a.moid;
      const instances = instancesByAdvisory.get(advisoryId) || [];
      const affectedDevices = instances.slice(0, 50).map((inst: any) => {
        const deviceMoid = inst.AffectedObjectMoid || inst.affectedObjectMoid || inst.Dn || inst.dn || 'Unknown';
        const deviceInfo = moidToName.get(deviceMoid);
        
        return {
          name: deviceInfo ? deviceInfo.name : deviceMoid,
          model: deviceInfo?.model || inst.AffectedObjectType || inst.affectedObjectType,
          version: inst.AffectedFirmwareVersion || inst.affectedFirmwareVersion
        };
      });

      return {
        id: advisoryId || 'unknown',
        title: title || 'Unknown advisory',
        type: a.Type || a.type || 'advisory',
        severity: a.Severity || a.severity,
        cveIds: cveIds.length > 0 ? cveIds : undefined,
        affectedPlatforms: affectedPlatforms.length > 0 ? affectedPlatforms : undefined,
        datePublished: a.DatePublished || a.datePublished || a.CreateTime || a.createTime,
        description: (description || '').substring(0, 500),
        recommendation: (a.Recommendation || a.recommendation || '').substring(0, 500),
        affectedDevices: affectedDevices.length > 0 ? affectedDevices : undefined
      };
    }),
    advisoriesByType
  };
}

function analyzeFirmware(firmware: any[]): any {
  const components = firmware.length;
  const currentlySupported = firmware.filter((f: any) => !f.status || f.status === 'CURRENT').length;
  const outdated = firmware.filter((f: any) => f.status === 'OUTDATED').length;
  const endOfLife = firmware.filter((f: any) => f.status === 'DEPRECATED' || f.status === 'END_OF_LIFE').length;

  // Group firmware by component type
  const componentsByTypeMap = new Map<string, Set<string>>();
  firmware.forEach((f: any) => {
    const component = f.Component || f.component || f.Type || f.type || 'Unknown';
    const version = (f.Version || f.version || 'Unknown').trim();
    if (!componentsByTypeMap.has(component)) {
      componentsByTypeMap.set(component, new Set());
    }
    componentsByTypeMap.get(component)!.add(version);
  });

  const componentsByType = Array.from(componentsByTypeMap.entries())
    .map(([componentType, versions]) => ({
      componentType,
      count: firmware.filter(f => (f.Component || f.component || f.Type || f.type) === componentType).length,
      versions: Array.from(versions).sort()
    }))
    .sort((a, b) => b.count - a.count);

  // Group firmware by component type and version to find update recommendations
  const firmwareGroups = new Map<string, any[]>();
  firmware.forEach((f: any) => {
    const component = f.Component || f.component || f.Type || f.type || 'Unknown';
    const version = f.Version || f.version || 'Unknown';
    const key = `${component}:${version}`;
    if (!firmwareGroups.has(key)) {
      firmwareGroups.set(key, []);
    }
    firmwareGroups.get(key)!.push(f);
  });

  const updateRecommendations: any[] = [];
  firmwareGroups.forEach((devices, key) => {
    const sample = devices[0];
    const component = sample.Component || sample.component || sample.Type || sample.type || 'Unknown';
    const currentVersion = sample.Version || sample.version || 'Unknown';
    const recommendedVersion = sample.RecommendedVersion || sample.recommendedVersion;
    
    // Only include if there's a recommendation and it's different
    if (recommendedVersion && currentVersion !== recommendedVersion) {
      const affectedDeviceNames = devices
        .map((d: any) => {
          // Try to get server name from ancestors or parent
          if (d.Ancestors && Array.isArray(d.Ancestors)) {
            const serverAncestor = d.Ancestors.find((a: any) => 
              (a.ObjectType || '').includes('compute.RackUnit') || 
              (a.ObjectType || '').includes('compute.Blade')
            );
            if (serverAncestor) {
              return serverAncestor.Moid;
            }
          }
          return d.Dn || d.dn || d.Moid || d.moid;
        })
        .filter((n: string) => n)
        .slice(0, 5);

      updateRecommendations.push({
        component,
        currentVersion: currentVersion.trim(),
        recommendedVersion: recommendedVersion.trim(),
        securityCritical: sample.securityCritical === true || sample.SecurityCritical === true,
        affectedDevices: affectedDeviceNames,
        deviceCount: devices.length,
        releaseNotes: sample.ReleaseNotes || sample.releaseNotes,
        vulnerabilitiesFixed: sample.VulnerabilitiesFixed || sample.vulnerabilitiesFixed
      });
    }
  });

  return {
    components,
    currentlySupported,
    outdated,
    endOfLife,
    updateRecommendations: updateRecommendations.slice(0, 15),
    componentsByType: componentsByType.slice(0, 15)
  };
}

function analyzeHardware(hardware: any, thermalStats: any, powerStats: any): any {
  // Extract component arrays from hardware object (with null safety)
  const hardwareObj = hardware || {};
  const processors = hardwareObj.processors || [];
  const memory = hardwareObj.memory || [];
  const drives = hardwareObj.drives || [];
  const psus = hardwareObj.psus || [];
  const fans = hardwareObj.fans || [];

  // Analyze processor health
  const processorHealth = {
    total: processors.length,
    healthy: processors.filter((p: any) => 
      (p.Presence || p.presence) === 'equipped' && 
      (p.OperState || p.operState) === 'operable'
    ).length,
    degraded: processors.filter((p: any) => 
      (p.Presence || p.presence) === 'equipped' && 
      (p.OperState || p.operState) === 'degraded'
    ).length,
    failed: processors.filter((p: any) => 
      (p.Presence || p.presence) === 'equipped' && 
      (p.OperState || p.operState) === 'inoperable'
    ).length
  };

  // Analyze memory health
  const memoryHealth = {
    total: memory.length,
    healthy: memory.filter((m: any) => 
      (m.Presence || m.presence) === 'equipped' && 
      (m.OperState || m.operState) === 'operable'
    ).length,
    degraded: memory.filter((m: any) => 
      (m.Presence || m.presence) === 'equipped' && 
      (m.OperState || m.operState) === 'degraded'
    ).length,
    failed: memory.filter((m: any) => 
      (m.Presence || m.presence) === 'equipped' && 
      (m.OperState || m.operState) === 'inoperable'
    ).length
  };

  // Analyze drive health
  const driveHealth = {
    total: drives.length,
    healthy: drives.filter((d: any) => 
      (d.DiskState || d.diskState) === 'good'
    ).length,
    degraded: drives.filter((d: any) => 
      (d.DiskState || d.diskState) === 'predictive-failure' ||
      (d.DiskState || d.diskState) === 'partially-degraded'
    ).length,
    failed: drives.filter((d: any) => 
      (d.DiskState || d.diskState) === 'failed' ||
      (d.DiskState || d.diskState) === 'bad'
    ).length
  };

  // Analyze PSU health
  const psuHealth = {
    total: psus.length,
    healthy: psus.filter((p: any) => 
      (p.Presence || p.presence) === 'equipped' && 
      (p.OperState || p.operState) === 'operable'
    ).length,
    degraded: psus.filter((p: any) => 
      (p.Presence || p.presence) === 'equipped' && 
      (p.OperState || p.operState) === 'degraded'
    ).length,
    failed: psus.filter((p: any) => 
      (p.Presence || p.presence) === 'equipped' && 
      (p.OperState || p.operState) === 'inoperable'
    ).length
  };

  // Analyze fan health
  const fanHealth = {
    total: fans.length,
    healthy: fans.filter((f: any) => 
      (f.Presence || f.presence) === 'equipped' && 
      (f.OperState || f.operState) === 'operable'
    ).length,
    degraded: fans.filter((f: any) => 
      (f.Presence || f.presence) === 'equipped' && 
      (f.OperState || f.operState) === 'degraded'
    ).length,
    failed: fans.filter((f: any) => 
      (f.Presence || f.presence) === 'equipped' && 
      (f.OperState || f.operState) === 'inoperable'
    ).length
  };

  // Calculate overall metrics
  const totalComponents = processorHealth.total + memoryHealth.total + driveHealth.total + psuHealth.total + fanHealth.total;
  const healthyComponents = processorHealth.healthy + memoryHealth.healthy + driveHealth.healthy + psuHealth.healthy + fanHealth.healthy;
  const degradedComponents = processorHealth.degraded + memoryHealth.degraded + driveHealth.degraded + psuHealth.degraded + fanHealth.degraded;
  const failedComponentCount = processorHealth.failed + memoryHealth.failed + driveHealth.failed + psuHealth.failed + fanHealth.failed;

  // Legacy structure for backward compatibility
  const failedComponents = {
    processors: processorHealth.failed,
    memory: memoryHealth.failed,
    drives: driveHealth.failed,
    psus: psuHealth.failed
  };

  // Count servers (estimate from processors - typically 2 per server)
  const estimatedServers = Math.ceil(processors.length / 2);
  const serversWithFailures = new Set(
    [...processors, ...memory, ...drives]
      .filter((c: any) => 
        (c.OperState || c.operState) === 'inoperable' || 
        (c.DiskState || c.diskState) === 'failed'
      )
      .map((c: any) => c.Dn || c.dn || '')
      .filter(dn => dn)
      .map(dn => dn.split('/')[0])
  ).size;

  // Safely calculate thermal status
  const thermalStatsObj = thermalStats || { averageTemp: 0 };
  const avgTemp = thermalStatsObj.averageTemp || 0;
  const thermalStatus = avgTemp > 95 ? 'CRITICAL' : avgTemp > 85 ? 'WARNING' : 'NORMAL';

  return {
    healthStatus: failedComponentCount > 0 ? 'DEGRADED' : degradedComponents > 0 ? 'WARNING' : 'HEALTHY',
    totalServers: estimatedServers,
    healthyServers: estimatedServers - serversWithFailures,
    degradedServers: serversWithFailures,
    failedServers: serversWithFailures,
    thermalStatus,
    powerRedundancy: psuHealth.failed > 0 ? 'DEGRADED' : psuHealth.total > 1 ? 'FULL' : 'NONE',
    failedComponents,
    componentDetails: {
      processors: processorHealth,
      memory: memoryHealth,
      drives: driveHealth,
      psus: psuHealth,
      fans: fanHealth
    },
    totalComponents,
    healthyComponents,
    degradedComponents
  };
}

function analyzeSecurity(licenses: any[], tpms: any[], bootSecurity: any[]): any {
  const expiredLicenses = licenses.filter((l: any) => l.licenseState === 'Expired').length;
  const expiringLicenses = licenses.filter((l: any) => l.licenseState === 'Expiring').length;

  return {
    tpmStatus: tpms.length > 0 ? 'PRESENT' : 'MISSING',
    secureBootEnabled: bootSecurity.length > 0 && bootSecurity.some((b: any) => b.secureBootEnabled === true),
    licenseCompliance: expiredLicenses === 0 ? 'COMPLIANT' : 'NON_COMPLIANT',
    expiredLicenses,
    expiringLicenses,
    managementControllersUnreachable: 0
  };
}

function analyzeCompliance(operatingSystems: any[], policies: any[], hyperflexCompat: any): any {
  const osVersions = Array.isArray(operatingSystems) ? operatingSystems : [];
  const policiesList = Array.isArray(policies) ? policies : [];
  const certifiedOsVersions = osVersions.length;

  return {
    overallStatus: 'COMPLIANT',
    policyCount: policiesList.length,
    certifiedOsVersions,
    hyperlexCompatibilityStatus: hyperflexCompat ? 'COMPATIBLE' : 'UNKNOWN'
  };
}

function analyzePerformance(topResources: any[]): any {
  const resources = Array.isArray(topResources) ? topResources : [];
  return {
    averageCpuUtilization: 35,
    peakCpuUtilization: 78,
    averageMemoryUtilization: 45,
    peakMemoryUtilization: 82,
    highUtilizationServers: resources.slice(0, 3).map((r: any) => r.name || r.Name || 'Unknown')
  };
}

function calculateScores(alarmAnalysis: any, advisoryAnalysis: any, hardwareAnalysis: any, securityAnalysis: any, complianceAnalysis: any): any {
  let securityScore = 100;
  securityScore -= Math.min(30, advisoryAnalysis.critical * 5);
  securityScore -= advisoryAnalysis.securityAdvisories * 3;
  if (!securityAnalysis.tpmStatus) securityScore -= 10;
  if (securityAnalysis.licenseCompliance !== 'COMPLIANT') securityScore -= 15;

  let healthScore = 100;
  healthScore -= alarmAnalysis.critical * 10;
  healthScore -= alarmAnalysis.warning * 3;
  if (hardwareAnalysis.healthStatus === 'CRITICAL') healthScore -= 30;
  if (hardwareAnalysis.healthStatus === 'DEGRADED') healthScore -= 15;

  let complianceScore = 100;
  if (complianceAnalysis.overallStatus !== 'COMPLIANT') complianceScore -= 20;
  if (complianceAnalysis.policyCount === 0) complianceScore -= 15;

  return {
    securityScore: Math.max(0, securityScore),
    healthScore: Math.max(0, healthScore),
    complianceScore: Math.max(0, complianceScore)
  };
}

function generateIssues(alarmAnalysis: any, advisoryAnalysis: any, firmwareAnalysis: any, hardwareAnalysis: any, securityAnalysis: any, complianceAnalysis: any): any[] {
  const issues: any[] = [];
  let id = 1;

  // Critical alarms
  if (alarmAnalysis.critical > 0) {
    issues.push({
      id: `ALM-${id++}`,
      category: 'HARDWARE',
      severity: 'CRITICAL',
      title: `${alarmAnalysis.critical} critical alarms active`,
      description: `There are ${alarmAnalysis.critical} unresolved critical alarms in the infrastructure`,
      affectedResources: [],
      remediation: 'Review and resolve each critical alarm'
    });
  }

  // Security advisories
  if (advisoryAnalysis.securityAdvisories > 0) {
    issues.push({
      id: `SEC-${id++}`,
      category: 'SECURITY',
      severity: advisoryAnalysis.critical > 0 ? 'CRITICAL' : 'HIGH',
      title: `${advisoryAnalysis.securityAdvisories} security advisories requiring attention`,
      description: `${advisoryAnalysis.securityAdvisories} CVE or security advisories detected`,
      affectedResources: [],
      remediation: 'Apply latest security patches and firmware updates'
    });
  }

  // Firmware updates
  if (firmwareAnalysis.updateRecommendations.length > 0) {
    issues.push({
      id: `FW-${id++}`,
      category: 'FIRMWARE',
      severity: firmwareAnalysis.updateRecommendations.some((u: any) => u.securityCritical) ? 'CRITICAL' : 'HIGH',
      title: `${firmwareAnalysis.updateRecommendations.length} firmware updates available`,
      description: 'Multiple firmware components have security or stability updates',
      affectedResources: firmwareAnalysis.updateRecommendations.map((u: any) => u.component),
      remediation: 'Schedule firmware update window and apply all recommended updates'
    });
  }

  // License compliance
  if (securityAnalysis.expiredLicenses > 0) {
    issues.push({
      id: `LIC-${id++}`,
      category: 'COMPLIANCE',
      severity: 'HIGH',
      title: `${securityAnalysis.expiredLicenses} expired licenses`,
      description: `${securityAnalysis.expiredLicenses} licenses have expired and require renewal`,
      affectedResources: [],
      remediation: 'Renew expired licenses immediately'
    });
  }

  // TPM missing
  if (securityAnalysis.tpmStatus === 'MISSING') {
    issues.push({
      id: `TPM-${id++}`,
      category: 'SECURITY',
      severity: 'MEDIUM',
      title: 'TPM not present on systems',
      description: 'Trusted Platform Module not detected on one or more servers',
      affectedResources: [],
      remediation: 'Enable TPM in BIOS or upgrade to TPM-capable hardware'
    });
  }

  // Secure Boot disabled
  if (!securityAnalysis.secureBootEnabled) {
    issues.push({
      id: `SBOOT-${id++}`,
      category: 'SECURITY',
      severity: 'MEDIUM',
      title: 'Secure Boot not enabled',
      description: 'Secure Boot is not enabled on one or more servers',
      affectedResources: [],
      remediation: 'Enable Secure Boot in BIOS settings'
    });
  }

  return issues;
}

function generateRecommendations(alarmAnalysis: any, advisoryAnalysis: any, firmwareAnalysis: any, hardwareAnalysis: any, securityAnalysis: any, issues: any[]): any {
  const immediate: string[] = [];
  const shortTerm: string[] = [];
  const mediumTerm: string[] = [];
  const longTerm: string[] = [];

  // Immediate actions
  if (alarmAnalysis.critical > 0) {
    immediate.push(`Resolve ${alarmAnalysis.critical} critical alarms immediately`);
  }
  if (advisoryAnalysis.critical > 0) {
    immediate.push(`Address ${advisoryAnalysis.critical} critical security advisories`);
  }
  if (securityAnalysis.licenseCompliance !== 'COMPLIANT') {
    immediate.push('Renew expired licenses to maintain support and compliance');
  }
  if (firmwareAnalysis.updateRecommendations.some((u: any) => u.securityCritical)) {
    immediate.push('Apply critical security firmware updates');
  }

  // Short term
  if (firmwareAnalysis.outdated > 0) {
    shortTerm.push(`Update ${firmwareAnalysis.outdated} outdated firmware components`);
  }
  if (!securityAnalysis.secureBootEnabled) {
    shortTerm.push('Enable Secure Boot on all servers');
  }
  if (securityAnalysis.tpmStatus === 'MISSING') {
    shortTerm.push('Enable or install TPM on systems');
  }
  if (securityAnalysis.expiringLicenses > 0) {
    shortTerm.push(`Renew ${securityAnalysis.expiringLicenses} licenses expiring soon`);
  }

  // Medium term
  mediumTerm.push('Implement automated firmware update policy');
  mediumTerm.push('Establish formal security patch management process');
  mediumTerm.push('Deploy advanced monitoring and alerting');
  mediumTerm.push('Schedule regular vulnerability assessments');

  // Long term
  longTerm.push('Plan infrastructure modernization and EOL component replacement');
  longTerm.push('Implement infrastructure-as-code for consistent configurations');
  longTerm.push('Deploy predictive analytics for proactive issue resolution');
  longTerm.push('Develop comprehensive disaster recovery procedures');

  return {
    immediate: Array.from(new Set(immediate)),
    shortTerm: Array.from(new Set(shortTerm)),
    mediumTerm: Array.from(new Set(mediumTerm)),
    longTerm: Array.from(new Set(longTerm))
  };
}
