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

import fs from 'fs';
import { IntersightConfig } from '../services/intersightApi.js';

export interface MCPServerConfig {
  serverConfig: {
    name: string;
    toolSelectionMode: 'whitelist' | 'blacklist' | 'all';
    enableAllTools: boolean;
    serverProfileFocus: boolean;
  };
  toolConfiguration: {
    enabledTools: string[];
    disabledTools: string[];
    serverProfileFocus?: {
      enabled: boolean;
      priorityTools: string[];
    };
  };
}

// Core 65 tools for basic Intersight operations
const CORE_65_TOOLS = [
  // Inventory & Discovery (8 tools)
  'list_compute_servers',
  'get_server_details', 
  'list_chassis',
  'list_fabric_interconnects',
  'list_compute_blades',
  'list_compute_rack_units',
  'list_compute_boards',
  'search_resources',

  // Alarms & Monitoring (3 tools)
  'list_alarms',
  'get_tam_advisory_count',
  'list_tam_advisories',

  // Policy Management (12 tools)
  'list_policies',
  'get_policy',
  'list_server_profiles',
  'get_server_profile',
  'list_bios_units',
  'list_boot_device_boot_modes',
  'list_adapter_config_policies',
  'get_adapter_config_policy',
  'list_lan_connectivity_policies',
  'get_lan_connectivity_policy',
  'list_vnics',
  'get_vnic',

  // Pool Management (6 tools)
  'list_pools',
  'list_ippool_blocks',
  'list_macpool_blocks',
  'list_fcpool_blocks',
  'get_ippool_block',
  'get_macpool_block',

  // Telemetry & Monitoring (15 tools)
  'get_server_telemetry',
  'get_chassis_telemetry',
  'get_adapter_telemetry',
  'get_top_resources',
  'list_processor_units',
  'list_memory_units',
  'list_storage_controllers',
  'list_physical_drives',
  'get_power_statistics',
  'get_thermal_statistics',
  'list_fan_modules',
  'list_psu_units',
  'list_storage_virtual_drives',
  'list_pci_devices',
  'list_graphics_cards',

  // Hardware & Firmware (7 tools)
  'list_firmware_running',
  'list_licenses',
  'list_hcl_operating_systems',
  'list_hcl_hyperflex_compatibility',
  'list_equipment_io_cards',
  'list_equipment_sys_io_ctrls',
  'list_management_controllers',

  // Fabric & Network (6 tools)
  'list_fabric_vlans',
  'get_fabric_vlan',
  'list_fabric_vsans',
  'get_fabric_vsan',
  'list_fabric_port_channels',
  'get_fabric_port_channel',

  // Workflow & System (4 tools)
  'list_workflows',
  'get_workflow',
  'list_top_systems',
  'get_top_system',

  // Code Examples (4 tools)
  'get_powershell_examples',
  'get_python_examples',
  'get_terraform_examples',
  'get_ansible_examples',

  // Security & Health Check Agent (1 tool)
  'generate_security_health_report'
];

export function loadMCPServerConfig(): MCPServerConfig {
  const configPath = process.env.INTERSIGHT_CONFIG_FILE || 
    './intersight-mcp-server-config.json';
  
  let config: MCPServerConfig;
  
  try {
    if (fs.existsSync(configPath)) {
      config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    } else {
      // Default configuration
      config = {
        serverConfig: {
          name: 'intersight',
          toolSelectionMode: 'whitelist',
          enableAllTools: false,
          serverProfileFocus: false
        },
        toolConfiguration: {
          enabledTools: CORE_65_TOOLS,
          disabledTools: []
        }
      };
    }
  } catch (error) {
    console.error('Error loading MCP config, using defaults:', error);
    config = {
      serverConfig: {
        name: 'intersight',
        toolSelectionMode: 'whitelist',
        enableAllTools: false,
        serverProfileFocus: false
      },
      toolConfiguration: {
        enabledTools: CORE_65_TOOLS,
        disabledTools: []
      }
    };
  }
  
  // Override with environment variables
  if (process.env.INTERSIGHT_TOOL_MODE === 'all') {
    config.serverConfig.enableAllTools = true;
    config.serverConfig.toolSelectionMode = 'all';
  } else if (process.env.INTERSIGHT_TOOL_MODE === 'core') {
    config.serverConfig.enableAllTools = false;
    config.serverConfig.toolSelectionMode = 'whitelist';
    config.toolConfiguration.enabledTools = CORE_65_TOOLS;
  }
  
  if (process.env.INTERSIGHT_ENABLE_ALL_TOOLS === 'true') {
    config.serverConfig.enableAllTools = true;
    config.serverConfig.toolSelectionMode = 'all';
  }
  
  if (process.env.INTERSIGHT_PROFILE_FOCUS === 'true') {
    config.serverConfig.serverProfileFocus = true;
  }
  
  return config;
}

export function isToolEnabled(toolName: string, config: MCPServerConfig, allTools: string[]): boolean {
  if (config.serverConfig.toolSelectionMode === 'all' || config.serverConfig.enableAllTools) {
    return true;
  }
  
  if (config.serverConfig.toolSelectionMode === 'whitelist') {
    return config.toolConfiguration.enabledTools.includes(toolName);
  }
  
  if (config.serverConfig.toolSelectionMode === 'blacklist') {
    return !config.toolConfiguration.disabledTools.some(pattern => {
      if (pattern.includes('*')) {
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        return regex.test(toolName);
      }
      return pattern === toolName;
    });
  }
  
  return false;
}

export function getEnabledTools(allTools: any[], config: MCPServerConfig): any[] {
  return allTools.filter(tool => isToolEnabled(tool.name, config, allTools.map(t => t.name)));
}

export function loadConfig(): IntersightConfig {
  const apiKeyId = process.env.INTERSIGHT_API_KEY_ID;
  const apiSecretKeyPath = process.env.INTERSIGHT_API_SECRET_KEY_PATH;
  const apiSecretKey = process.env.INTERSIGHT_API_SECRET_KEY;
  const baseUrl = process.env.INTERSIGHT_BASE_URL || 'https://intersight.com/api/v1';

  if (!apiKeyId) {
    throw new Error('INTERSIGHT_API_KEY_ID environment variable is required');
  }

  let secretKey: string;
  
  if (apiSecretKeyPath) {
    // Load from file path
    try {
      secretKey = fs.readFileSync(apiSecretKeyPath, 'utf8');
    } catch (error) {
      throw new Error(`Failed to read API secret key from ${apiSecretKeyPath}: ${error}`);
    }
  } else if (apiSecretKey) {
    // Use directly from environment variable
    secretKey = apiSecretKey;
  } else {
    throw new Error('Either INTERSIGHT_API_SECRET_KEY_PATH or INTERSIGHT_API_SECRET_KEY must be set');
  }

  return {
    apiKeyId,
    apiSecretKey: secretKey,
    baseUrl
  };
}
