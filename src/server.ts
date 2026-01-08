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

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { IntersightApiService } from './services/intersightApi.js';
import { loadConfig, loadMCPServerConfig, isToolEnabled, getEnabledTools, MCPServerConfig } from './utils/config.js';
import { createSecurityHealthCheckReport } from './services/securityHealthCheckAgent.js';

export class IntersightMCPServer {
  private server: Server;
  private apiService: IntersightApiService;
  private mcpConfig: MCPServerConfig;

  constructor() {
    // Load MCP server configuration
    this.mcpConfig = loadMCPServerConfig();
    
    this.server = new Server(
      {
        name: this.mcpConfig.serverConfig.name,
        version: '1.0.15',
      },
      {
        capabilities: {
          tools: {
            listChanged: false,
          },
        },
      }
    );

    // Load configuration and initialize API service
    const config = loadConfig();
    this.apiService = new IntersightApiService(config);

    this.setupHandlers();
  }

  private setupHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const allTools = this.getAllTools();
      const enabledTools = getEnabledTools(allTools, this.mcpConfig);
      
      // Log tool configuration for debugging
      console.error(`Intersight MCP Server: Exposing ${enabledTools.length} of ${allTools.length} tools`);
      console.error(`Tool mode: ${this.mcpConfig.serverConfig.toolSelectionMode}`);
      console.error(`Enable all tools: ${this.mcpConfig.serverConfig.enableAllTools}`);
      
      return {
        tools: enabledTools,
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      // Security check: verify tool is enabled
      const allToolNames = this.getAllTools().map(t => t.name);
      if (!isToolEnabled(name, this.mcpConfig, allToolNames)) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: Tool '${name}' is not enabled in current configuration. Use INTERSIGHT_TOOL_MODE=all to enable all tools.`,
            },
          ],
          isError: true,
        };
      }

      try {
        const result = await this.handleToolCall(name, args || {});
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (error: any) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error.message}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  private getAllTools(): Tool[] {
    return [
      // Inventory & Discovery Tools
      {
        name: 'list_compute_servers',
        description: 'List all compute servers (blades and rack units) with optional filtering',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression (e.g., "OperPowerState eq \'on\'")',
            },
          },
        },
      },
      {
        name: 'get_server_details',
        description: 'Get detailed information about a specific server by MOID',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'Managed Object ID of the server',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_chassis',
        description: 'List all equipment chassis',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'list_fabric_interconnects',
        description: 'List all fabric interconnects and network elements',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },

      // Alarms & Monitoring Tools
      {
        name: 'list_alarms',
        description: 'List active alarms with optional filtering by severity',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression (e.g., "Severity eq \'Critical\'")',
            },
          },
        },
      },
      {
        name: 'acknowledge_alarm',
        description: 'Acknowledge a specific alarm',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the alarm to acknowledge',
            },
          },
          required: ['moid'],
        },
      },

      // Policy Management Tools
      {
        name: 'list_policies',
        description: 'List policies of a specific type',
        inputSchema: {
          type: 'object',
          properties: {
            policyType: {
              type: 'string',
              description: 'Policy type (e.g., "boot/PrecisionPolicies", "bios/Policies", "vnic/LanConnectivityPolicies")',
            },
          },
          required: ['policyType'],
        },
      },
      {
        name: 'get_policy',
        description: 'Get details of a specific policy',
        inputSchema: {
          type: 'object',
          properties: {
            policyType: {
              type: 'string',
              description: 'Policy type path',
            },
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['policyType', 'moid'],
        },
      },
      {
        name: 'create_boot_policy',
        description: 'Create a new boot policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the boot policy',
            },
            description: {
              type: 'string',
              description: 'Description of the policy',
            },
            bootMode: {
              type: 'string',
              description: 'Boot mode: Uefi or Legacy',
              enum: ['Uefi', 'Legacy'],
            },
            secureBoot: {
              type: 'boolean',
              description: 'Enable UEFI secure boot',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'create_bios_policy',
        description: 'Create a new BIOS policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the BIOS policy',
            },
            description: {
              type: 'string',
              description: 'Description of the policy',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'create_network_policy',
        description: 'Create a new LAN connectivity policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the network policy',
            },
            description: {
              type: 'string',
              description: 'Description of the policy',
            },
            targetPlatform: {
              type: 'string',
              description: 'Target platform: FIAttached or Standalone',
              enum: ['FIAttached', 'Standalone'],
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'create_vnic',
        description: 'Create a vNIC (Ethernet interface) on a LAN connectivity policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the vNIC (e.g., "eth0")',
            },
            lanConnectivityPolicyMoid: {
              type: 'string',
              description: 'MOID of the LAN connectivity policy',
            },
            fabricId: {
              type: 'string',
              description: 'Fabric ID: A or B',
              enum: ['A', 'B'],
            },
            ethAdapterPolicyMoid: {
              type: 'string',
              description: 'MOID of the Ethernet Adapter policy (e.g., VMware, Linux)',
            },
            ethQosPolicyMoid: {
              type: 'string',
              description: 'MOID of the Ethernet QoS policy',
            },
            ethNetworkGroupPolicyMoid: {
              type: 'string',
              description: 'MOID of the Ethernet Network Group Policy (VLAN group)',
            },
            macPoolMoid: {
              type: 'string',
              description: 'MOID of the MAC address pool (optional)',
            },
            order: {
              type: 'number',
              description: 'vNIC order/placement (default: 0)',
            },
            vlans: {
              type: 'array',
              description: 'Array of VLAN IDs to assign',
              items: {
                type: 'number',
              },
            },
          },
          required: ['name', 'lanConnectivityPolicyMoid', 'fabricId', 'ethAdapterPolicyMoid', 'ethQosPolicyMoid', 'ethNetworkGroupPolicyMoid'],
        },
      },
      {
        name: 'list_vnics',
        description: 'List all vNICs (Ethernet interfaces) or filter by LAN connectivity policy',
        inputSchema: {
          type: 'object',
          properties: {
            lanConnectivityPolicyMoid: {
              type: 'string',
              description: 'MOID of LAN connectivity policy to filter vNICs (optional)',
            },
          },
        },
      },
      {
        name: 'get_vnic',
        description: 'Get details of a specific vNIC',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the vNIC',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'update_vnic',
        description: 'Update an existing vNIC',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the vNIC to update',
            },
            updates: {
              type: 'object',
              description: 'vNIC updates as JSON object',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_vnic',
        description: 'Delete a vNIC',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the vNIC to delete',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_vlan_group',
        description: 'Create an Ethernet Network Group Policy (VLAN group) for vNICs',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the VLAN group policy',
            },
            description: {
              type: 'string',
              description: 'Description of the VLAN group',
            },
            vlanIds: {
              type: 'array',
              description: 'Array of VLAN IDs to include in this group',
              items: {
                type: 'number',
              },
            },
            nativeVlan: {
              type: 'number',
              description: 'Native VLAN ID (optional)',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'vlanIds', 'organizationMoid'],
        },
      },
      {
        name: 'list_lan_connectivity_policies',
        description: 'List all LAN connectivity policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression (optional)',
            },
          },
        },
      },
      {
        name: 'get_lan_connectivity_policy',
        description: 'Get details of a specific LAN connectivity policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the LAN connectivity policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_eth_adapter_policies',
        description: 'List all Ethernet adapter policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression (optional)',
            },
          },
        },
      },
      {
        name: 'list_eth_qos_policies',
        description: 'List all Ethernet QoS policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression (optional)',
            },
          },
        },
      },
      {
        name: 'list_eth_network_group_policies',
        description: 'List all Ethernet Network Group policies (VLAN groups)',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression (optional)',
            },
          },
        },
      },
      {
        name: 'create_eth_network_policy',
        description: 'Create a vNIC Ethernet Network Policy that references a VLAN group',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the Ethernet Network Policy',
            },
            vlanGroupMoid: {
              type: 'string',
              description: 'MOID of the fabric.EthNetworkGroupPolicy (VLAN group)',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'vlanGroupMoid', 'organizationMoid'],
        },
      },
      {
        name: 'update_policy',
        description: 'Update an existing policy',
        inputSchema: {
          type: 'object',
          properties: {
            policyType: {
              type: 'string',
              description: 'Policy type path',
            },
            moid: {
              type: 'string',
              description: 'MOID of the policy to update',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON object',
            },
          },
          required: ['policyType', 'moid', 'updates'],
        },
      },
      {
        name: 'delete_policy',
        description: 'Delete a policy',
        inputSchema: {
          type: 'object',
          properties: {
            policyType: {
              type: 'string',
              description: 'Policy type path',
            },
            moid: {
              type: 'string',
              description: 'MOID of the policy to delete',
            },
          },
          required: ['policyType', 'moid'],
        },
      },

      // Pool Management Tools
      {
        name: 'list_pools',
        description: 'List pools of a specific type',
        inputSchema: {
          type: 'object',
          properties: {
            poolType: {
              type: 'string',
              description: 'Pool type (e.g., "ippool/Pools", "macpool/Pools", "uuidpool/Pools", "fcpool/Pools")',
            },
          },
          required: ['poolType'],
        },
      },
      {
        name: 'create_ip_pool',
        description: 'Create a new IP pool',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the IP pool',
            },
            description: {
              type: 'string',
              description: 'Description of the pool',
            },
            ipBlockFrom: {
              type: 'string',
              description: 'Starting IP address',
            },
            ipBlockTo: {
              type: 'string',
              description: 'Ending IP address',
            },
            gateway: {
              type: 'string',
              description: 'Default gateway',
            },
            netmask: {
              type: 'string',
              description: 'Subnet mask',
            },
            primaryDns: {
              type: 'string',
              description: 'Primary DNS server',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'ipBlockFrom', 'ipBlockTo', 'gateway', 'netmask', 'organizationMoid'],
        },
      },
      {
        name: 'create_mac_pool',
        description: 'Create a new MAC pool',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the MAC pool',
            },
            description: {
              type: 'string',
              description: 'Description of the pool',
            },
            macBlockFrom: {
              type: 'string',
              description: 'Starting MAC address (e.g., "00:25:B5:00:00:00")',
            },
            macBlockTo: {
              type: 'string',
              description: 'Ending MAC address',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'macBlockFrom', 'macBlockTo', 'organizationMoid'],
        },
      },
      {
        name: 'create_uuid_pool',
        description: 'Create a new UUID pool',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the UUID pool',
            },
            description: {
              type: 'string',
              description: 'Description of the pool',
            },
            prefix: {
              type: 'string',
              description: 'UUID prefix',
            },
            uuidBlockFrom: {
              type: 'string',
              description: 'Starting UUID suffix',
            },
            uuidBlockTo: {
              type: 'string',
              description: 'Ending UUID suffix',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'prefix', 'uuidBlockFrom', 'uuidBlockTo', 'organizationMoid'],
        },
      },
      {
        name: 'create_wwnn_pool',
        description: 'Create a new WWNN pool for Fibre Channel',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the WWNN pool',
            },
            description: {
              type: 'string',
              description: 'Description of the pool',
            },
            wwnnBlockFrom: {
              type: 'string',
              description: 'Starting WWNN address',
            },
            wwnnBlockTo: {
              type: 'string',
              description: 'Ending WWNN address',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'wwnnBlockFrom', 'wwnnBlockTo', 'organizationMoid'],
        },
      },
      {
        name: 'create_wwpn_pool',
        description: 'Create a new WWPN pool for Fibre Channel',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the WWPN pool',
            },
            description: {
              type: 'string',
              description: 'Description of the pool',
            },
            wwpnBlockFrom: {
              type: 'string',
              description: 'Starting WWPN address',
            },
            wwpnBlockTo: {
              type: 'string',
              description: 'Ending WWPN address',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'wwpnBlockFrom', 'wwpnBlockTo', 'organizationMoid'],
        },
      },
      {
        name: 'update_pool',
        description: 'Update an existing pool',
        inputSchema: {
          type: 'object',
          properties: {
            poolType: {
              type: 'string',
              description: 'Pool type path',
            },
            moid: {
              type: 'string',
              description: 'MOID of the pool to update',
            },
            updates: {
              type: 'object',
              description: 'Pool updates as JSON object',
            },
          },
          required: ['poolType', 'moid', 'updates'],
        },
      },
      {
        name: 'delete_pool',
        description: 'Delete a pool by type and MOID',
        inputSchema: {
          type: 'object',
          properties: {
            poolType: {
              type: 'string',
              description: 'Pool type path (e.g., "ippool/Pools", "macpool/Pools", "uuidpool/Pools")',
            },
            moid: {
              type: 'string',
              description: 'MOID of the pool to delete',
            },
          },
          required: ['poolType', 'moid'],
        },
      },

      // Configuration Management Tools - Adapter Configuration
      {
        name: 'list_adapter_config_policies',
        description: 'List all Ethernet adapter configuration policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_adapter_config_policy',
        description: 'Get details of a specific adapter configuration policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the adapter configuration policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_adapter_config_policy',
        description: 'Create a new Ethernet adapter configuration policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the adapter configuration policy',
            },
            description: {
              type: 'string',
              description: 'Description of the policy',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
            rssSettings: {
              type: 'boolean',
              description: 'Enable RSS (Receive Side Scaling)',
            },
            interruptSettings: {
              type: 'object',
              description: 'Interrupt settings configuration',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'update_adapter_config_policy',
        description: 'Update an existing adapter configuration policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy to update',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON object',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_adapter_config_policy',
        description: 'Delete an adapter configuration policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy to delete',
            },
          },
          required: ['moid'],
        },
      },

      // Configuration Management - Fabric Port Channels
      {
        name: 'list_fabric_port_channels',
        description: 'List all fabric port channels',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_fabric_port_channel',
        description: 'Get details of a specific fabric port channel',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the port channel',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_fabric_port_channel',
        description: 'Create a new fabric port channel',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the port channel',
            },
            portChannelId: {
              type: 'number',
              description: 'Port channel ID (1-256)',
            },
            fabricInterconnectMoid: {
              type: 'string',
              description: 'MOID of the fabric interconnect',
            },
            adminSpeed: {
              type: 'string',
              description: 'Admin speed: Auto, 1Gbps, 10Gbps, 25Gbps, 40Gbps, 100Gbps',
            },
          },
          required: ['name', 'portChannelId', 'fabricInterconnectMoid'],
        },
      },
      {
        name: 'update_fabric_port_channel',
        description: 'Update a fabric port channel',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the port channel to update',
            },
            updates: {
              type: 'object',
              description: 'Port channel updates as JSON object',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_fabric_port_channel',
        description: 'Delete a fabric port channel',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the port channel to delete',
            },
          },
          required: ['moid'],
        },
      },

      // Configuration Management - VLANs
      {
        name: 'list_fabric_vlans',
        description: 'List all fabric VLANs',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_fabric_vlan',
        description: 'Get details of a specific VLAN',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the VLAN',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_fabric_vlan',
        description: 'Create a new fabric VLAN',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the VLAN',
            },
            vlanId: {
              type: 'number',
              description: 'VLAN ID (1-4094)',
            },
            fabricEthNetworkGroupPolicyMoid: {
              type: 'string',
              description: 'MOID of the Ethernet Network Group Policy',
            },
            isNative: {
              type: 'boolean',
              description: 'Set as native VLAN',
            },
            multicastPolicyMoid: {
              type: 'string',
              description: 'MOID of multicast policy (optional)',
            },
          },
          required: ['name', 'vlanId'],
        },
      },
      {
        name: 'update_fabric_vlan',
        description: 'Update a fabric VLAN',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the VLAN to update',
            },
            updates: {
              type: 'object',
              description: 'VLAN updates as JSON object',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_fabric_vlan',
        description: 'Delete a fabric VLAN',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the VLAN to delete',
            },
          },
          required: ['moid'],
        },
      },

      // Configuration Management - VSANs (Fibre Channel)
      {
        name: 'list_fabric_vsans',
        description: 'List all fabric VSANs (Fibre Channel)',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_fabric_vsan',
        description: 'Get details of a specific VSAN',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the VSAN',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_fabric_vsan',
        description: 'Create a new fabric VSAN for Fibre Channel',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the VSAN',
            },
            vsanId: {
              type: 'number',
              description: 'VSAN ID (1-4094)',
            },
            fcZoneSharingMode: {
              type: 'string',
              description: 'FC zone sharing mode',
            },
            defaultZoning: {
              type: 'string',
              description: 'Default zoning: Enabled or Disabled',
            },
          },
          required: ['name', 'vsanId'],
        },
      },
      {
        name: 'update_fabric_vsan',
        description: 'Update a fabric VSAN',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the VSAN to update',
            },
            updates: {
              type: 'object',
              description: 'VSAN updates as JSON object',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_fabric_vsan',
        description: 'Delete a fabric VSAN',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the VSAN to delete',
            },
          },
          required: ['moid'],
        },
      },

      // Configuration Management - IP Pool Blocks
      {
        name: 'list_ippool_blocks',
        description: 'List all IP pool blocks',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_ippool_block',
        description: 'Get details of a specific IP pool block',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the IP pool block',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_ippool_block',
        description: 'Create a new IP pool block',
        inputSchema: {
          type: 'object',
          properties: {
            poolMoid: {
              type: 'string',
              description: 'MOID of the IP pool',
            },
            from: {
              type: 'string',
              description: 'Starting IP address',
            },
            to: {
              type: 'string',
              description: 'Ending IP address',
            },
            size: {
              type: 'number',
              description: 'Block size',
            },
          },
          required: ['poolMoid', 'from', 'size'],
        },
      },
      {
        name: 'update_ippool_block',
        description: 'Update an IP pool block',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the block to update',
            },
            updates: {
              type: 'object',
              description: 'Block updates as JSON object',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_ippool_block',
        description: 'Delete an IP pool block',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the block to delete',
            },
          },
          required: ['moid'],
        },
      },

      // Configuration Management - MAC Pool Blocks
      {
        name: 'list_macpool_blocks',
        description: 'List all MAC pool blocks',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_macpool_block',
        description: 'Get details of a specific MAC pool block',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the MAC pool block',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_macpool_block',
        description: 'Create a new MAC pool block',
        inputSchema: {
          type: 'object',
          properties: {
            poolMoid: {
              type: 'string',
              description: 'MOID of the MAC pool',
            },
            from: {
              type: 'string',
              description: 'Starting MAC address',
            },
            to: {
              type: 'string',
              description: 'Ending MAC address',
            },
            size: {
              type: 'number',
              description: 'Block size',
            },
          },
          required: ['poolMoid', 'from', 'size'],
        },
      },
      {
        name: 'update_macpool_block',
        description: 'Update a MAC pool block',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the block to update',
            },
            updates: {
              type: 'object',
              description: 'Block updates as JSON object',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_macpool_block',
        description: 'Delete a MAC pool block',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the block to delete',
            },
          },
          required: ['moid'],
        },
      },

      // Configuration Management - FC Pool Blocks (WWNN/WWPN)
      {
        name: 'list_fcpool_blocks',
        description: 'List all Fibre Channel pool blocks (WWNN/WWPN)',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_fcpool_block',
        description: 'Get details of a specific FC pool block',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the FC pool block',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_fcpool_block',
        description: 'Create a new FC pool block (WWNN or WWPN)',
        inputSchema: {
          type: 'object',
          properties: {
            poolMoid: {
              type: 'string',
              description: 'MOID of the FC pool',
            },
            from: {
              type: 'string',
              description: 'Starting WWN address',
            },
            to: {
              type: 'string',
              description: 'Ending WWN address',
            },
            size: {
              type: 'number',
              description: 'Block size',
            },
          },
          required: ['poolMoid', 'from', 'size'],
        },
      },
      {
        name: 'update_fcpool_block',
        description: 'Update an FC pool block',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the block to update',
            },
            updates: {
              type: 'object',
              description: 'Block updates as JSON object',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_fcpool_block',
        description: 'Delete an FC pool block',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the block to delete',
            },
          },
          required: ['moid'],
        },
      },

      // Advanced Networking - Fabric Uplink/Server Ports
      {
        name: 'list_fabric_uplink_ports',
        description: 'List all fabric uplink ports',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_fabric_server_ports',
        description: 'List all fabric server ports',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_fabric_port_operations',
        description: 'List all fabric port operations',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },

      // Network Control Policies
      {
        name: 'list_fabric_flow_control_policies',
        description: 'List all flow control policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_fabric_flow_control_policy',
        description: 'Get details of a specific flow control policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_fabric_flow_control_policy',
        description: 'Create a flow control policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the policy',
            },
            priorityFlowControlMode: {
              type: 'string',
              description: 'Priority flow control mode: auto, on',
              enum: ['auto', 'on'],
            },
            receiveDirection: {
              type: 'string',
              description: 'Receive direction: Disabled, Enabled',
              enum: ['Disabled', 'Enabled'],
            },
            sendDirection: {
              type: 'string',
              description: 'Send direction: Disabled, Enabled',
              enum: ['Disabled', 'Enabled'],
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'update_fabric_flow_control_policy',
        description: 'Update a flow control policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_fabric_flow_control_policy',
        description: 'Delete a flow control policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_fabric_link_control_policies',
        description: 'List all link control policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_fabric_link_control_policy',
        description: 'Get details of a specific link control policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_fabric_link_control_policy',
        description: 'Create a link control policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the policy',
            },
            udldSettings: {
              type: 'object',
              description: 'UDLD settings',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'update_fabric_link_control_policy',
        description: 'Update a link control policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_fabric_link_control_policy',
        description: 'Delete a link control policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_fabric_lacp_policies',
        description: 'List all link aggregation (LACP) policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_fabric_lacp_policy',
        description: 'Get details of a specific link aggregation policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_fabric_lacp_policy',
        description: 'Create a link aggregation (LACP) policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the policy',
            },
            lacpRate: {
              type: 'string',
              description: 'LACP rate: normal, fast',
              enum: ['normal', 'fast'],
            },
            suspendIndividual: {
              type: 'boolean',
              description: 'Suspend individual port',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'update_fabric_lacp_policy',
        description: 'Update a link aggregation policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_fabric_lacp_policy',
        description: 'Delete a link aggregation policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_fabric_system_qos_policies',
        description: 'List all system QoS policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_fabric_system_qos_policy',
        description: 'Get details of a specific system QoS policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_fabric_multicast_policies',
        description: 'List all multicast policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_fabric_multicast_policy',
        description: 'Get details of a specific multicast policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_fabric_multicast_policy',
        description: 'Create a multicast policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the policy',
            },
            querierIpAddress: {
              type: 'string',
              description: 'Querier IP address',
            },
            querierState: {
              type: 'string',
              description: 'Querier state: Disabled, Enabled',
              enum: ['Disabled', 'Enabled'],
            },
            snoopingState: {
              type: 'string',
              description: 'Snooping state: Disabled, Enabled',
              enum: ['Disabled', 'Enabled'],
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'update_fabric_multicast_policy',
        description: 'Update a multicast policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_fabric_multicast_policy',
        description: 'Delete a multicast policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },

      // Hardware Security & Management
      {
        name: 'list_equipment_tpms',
        description: 'List all Trusted Platform Module (TPM) devices',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_equipment_tpm',
        description: 'Get details of a specific TPM device',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the TPM device',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_boot_device_boot_modes',
        description: 'List all boot device boot modes',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_boot_device_boot_securities',
        description: 'List all boot device security settings',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_storage_local_disk_policies',
        description: 'List all local disk configuration policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_storage_local_disk_policy',
        description: 'Get details of a specific local disk policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_storage_local_disk_policy',
        description: 'Create a local disk configuration policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the policy',
            },
            mode: {
              type: 'string',
              description: 'Disk mode: Any Configuration, No Local Storage, RAID',
              enum: ['Any Configuration', 'No Local Storage', 'RAID'],
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'mode', 'organizationMoid'],
        },
      },
      {
        name: 'update_storage_local_disk_policy',
        description: 'Update a local disk policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_storage_local_disk_policy',
        description: 'Delete a local disk policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_sdcard_policies',
        description: 'List all SD card policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_sdcard_policy',
        description: 'Get details of a specific SD card policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_sdcard_policy',
        description: 'Create an SD card policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the policy',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'update_sdcard_policy',
        description: 'Update an SD card policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_sdcard_policy',
        description: 'Delete an SD card policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_kvm_policies',
        description: 'List all KVM policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_kvm_policy',
        description: 'Get details of a specific KVM policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_kvm_policy',
        description: 'Create a KVM policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the policy',
            },
            enableLocalServerVideo: {
              type: 'boolean',
              description: 'Enable local server video',
            },
            enableVideoEncryption: {
              type: 'boolean',
              description: 'Enable video encryption',
            },
            maximumSessions: {
              type: 'number',
              description: 'Maximum concurrent sessions (1-4)',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'update_kvm_policy',
        description: 'Update a KVM policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_kvm_policy',
        description: 'Delete a KVM policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_virtual_media_policies',
        description: 'List all virtual media policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_virtual_media_policy',
        description: 'Get details of a specific virtual media policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_virtual_media_policy',
        description: 'Create a virtual media policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the policy',
            },
            encryption: {
              type: 'boolean',
              description: 'Enable encryption',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'update_virtual_media_policy',
        description: 'Update a virtual media policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_virtual_media_policy',
        description: 'Delete a virtual media policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },

      // System Policies
      {
        name: 'list_snmp_policies',
        description: 'List all SNMP policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_snmp_policy',
        description: 'Get details of a specific SNMP policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_snmp_policy',
        description: 'Create an SNMP policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the policy',
            },
            enabled: {
              type: 'boolean',
              description: 'Enable SNMP',
            },
            snmpPort: {
              type: 'number',
              description: 'SNMP port (default: 161)',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'update_snmp_policy',
        description: 'Update an SNMP policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_snmp_policy',
        description: 'Delete an SNMP policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_syslog_policies',
        description: 'List all Syslog policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_syslog_policy',
        description: 'Get details of a specific Syslog policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_syslog_policy',
        description: 'Create a Syslog policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the policy',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'update_syslog_policy',
        description: 'Update a Syslog policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_syslog_policy',
        description: 'Delete a Syslog policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_ntp_policies',
        description: 'List all NTP policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_ntp_policy',
        description: 'Get details of a specific NTP policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_ntp_policy',
        description: 'Create an NTP policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the policy',
            },
            enabled: {
              type: 'boolean',
              description: 'Enable NTP',
            },
            ntpServers: {
              type: 'array',
              description: 'NTP server addresses',
              items: {
                type: 'string',
              },
            },
            timezone: {
              type: 'string',
              description: 'Timezone',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'update_ntp_policy',
        description: 'Update an NTP policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_ntp_policy',
        description: 'Delete an NTP policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_smtp_policies',
        description: 'List all SMTP policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_smtp_policy',
        description: 'Get details of a specific SMTP policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_smtp_policy',
        description: 'Create an SMTP policy',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the policy',
            },
            smtpServer: {
              type: 'string',
              description: 'SMTP server address',
            },
            smtpPort: {
              type: 'number',
              description: 'SMTP port (default: 25)',
            },
            senderEmail: {
              type: 'string',
              description: 'Sender email address',
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'smtpServer', 'organizationMoid'],
        },
      },
      {
        name: 'update_smtp_policy',
        description: 'Update an SMTP policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
            updates: {
              type: 'object',
              description: 'Policy updates as JSON',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_smtp_policy',
        description: 'Delete an SMTP policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_deviceconnector_policies',
        description: 'List all device connector policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_deviceconnector_policy',
        description: 'Get details of a specific device connector policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_certificatemanagement_policies',
        description: 'List all certificate management policies',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_certificatemanagement_policy',
        description: 'Get details of a specific certificate policy',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the policy',
            },
          },
          required: ['moid'],
        },
      },

      // Profile Management Tools
      {
        name: 'list_server_profiles',
        description: 'List all server profiles',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_server_profile',
        description: 'Get details of a specific server profile',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the server profile',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'create_server_profile',
        description: 'Create a new server profile',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the server profile',
            },
            description: {
              type: 'string',
              description: 'Description of the profile',
            },
            targetPlatform: {
              type: 'string',
              description: 'Target platform: FIAttached or Standalone',
              enum: ['FIAttached', 'Standalone'],
            },
            organizationMoid: {
              type: 'string',
              description: 'Organization MOID',
            },
          },
          required: ['name', 'organizationMoid'],
        },
      },
      {
        name: 'attach_policy_to_profile',
        description: 'Attach a policy to a server profile',
        inputSchema: {
          type: 'object',
          properties: {
            profileMoid: {
              type: 'string',
              description: 'MOID of the server profile',
            },
            policyMoid: {
              type: 'string',
              description: 'MOID of the policy to attach',
            },
            policyType: {
              type: 'string',
              description: 'Policy type (e.g., "boot.PrecisionPolicy", "bios.Policy")',
            },
            policyField: {
              type: 'string',
              description: 'Profile field name (e.g., "BootPolicySettings", "BiosPolicy")',
            },
          },
          required: ['profileMoid', 'policyMoid', 'policyType', 'policyField'],
        },
      },
      {
        name: 'attach_pool_to_profile',
        description: 'Attach a pool to a server profile',
        inputSchema: {
          type: 'object',
          properties: {
            profileMoid: {
              type: 'string',
              description: 'MOID of the server profile',
            },
            poolMoid: {
              type: 'string',
              description: 'MOID of the pool to attach',
            },
            poolType: {
              type: 'string',
              description: 'Pool type (e.g., "uuidpool.Pool")',
            },
            poolField: {
              type: 'string',
              description: 'Profile field name (e.g., "UuidPool")',
            },
          },
          required: ['profileMoid', 'poolMoid', 'poolType', 'poolField'],
        },
      },
      {
        name: 'assign_server_to_profile',
        description: 'Assign a physical server to a profile',
        inputSchema: {
          type: 'object',
          properties: {
            profileMoid: {
              type: 'string',
              description: 'MOID of the server profile',
            },
            serverMoid: {
              type: 'string',
              description: 'MOID of the physical server',
            },
          },
          required: ['profileMoid', 'serverMoid'],
        },
      },
      {
        name: 'deploy_server_profile',
        description: 'Deploy or undeploy a server profile',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the server profile',
            },
            action: {
              type: 'string',
              description: 'Deploy action: Deploy or Undeploy',
              enum: ['Deploy', 'Undeploy'],
            },
          },
          required: ['moid', 'action'],
        },
      },
      {
        name: 'update_server_profile',
        description: 'Update an existing server profile',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the profile to update',
            },
            updates: {
              type: 'object',
              description: 'Profile updates as JSON object',
            },
          },
          required: ['moid', 'updates'],
        },
      },
      {
        name: 'delete_server_profile',
        description: 'Delete a server profile',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the profile to delete',
            },
          },
          required: ['moid'],
        },
      },

      // Search & Query Tools
      {
        name: 'search_resources',
        description: 'Search for resources by type with optional OData filters',
        inputSchema: {
          type: 'object',
          properties: {
            resourceType: {
              type: 'string',
              description: 'Resource type path (e.g., "compute/PhysicalSummaries", "server/Profiles")',
            },
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
          required: ['resourceType'],
        },
      },

      // Telemetry & Metrics Tools
      {
        name: 'get_server_telemetry',
        description: 'Get telemetry data for a specific server (CPU, memory, temperature, power)',
        inputSchema: {
          type: 'object',
          properties: {
            serverMoid: {
              type: 'string',
              description: 'MOID of the server',
            },
            metricType: {
              type: 'string',
              description: 'Type of metric: CPU, Memory, Temperature, Power, or All',
              enum: ['CPU', 'Memory', 'Temperature', 'Power', 'All'],
            },
          },
          required: ['serverMoid'],
        },
      },
      {
        name: 'get_chassis_telemetry',
        description: 'Get telemetry data for a chassis (temperature, power, fans)',
        inputSchema: {
          type: 'object',
          properties: {
            chassisMoid: {
              type: 'string',
              description: 'MOID of the chassis',
            },
          },
          required: ['chassisMoid'],
        },
      },
      {
        name: 'get_adapter_telemetry',
        description: 'Get network adapter telemetry (throughput, errors, link status)',
        inputSchema: {
          type: 'object',
          properties: {
            adapterMoid: {
              type: 'string',
              description: 'MOID of the network adapter',
            },
          },
          required: ['adapterMoid'],
        },
      },
      {
        name: 'list_processor_units',
        description: 'List all processor units with current utilization',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_memory_units',
        description: 'List all memory units with health and capacity information',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_storage_controllers',
        description: 'List storage controllers with health and RAID information',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_physical_drives',
        description: 'List physical drives with health, capacity, and wear information',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_power_statistics',
        description: 'Get power consumption statistics for servers or chassis',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the server or chassis',
            },
            resourceType: {
              type: 'string',
              description: 'Resource type: server or chassis',
              enum: ['server', 'chassis'],
            },
          },
          required: ['moid', 'resourceType'],
        },
      },
      {
        name: 'get_thermal_statistics',
        description: 'Get thermal/temperature statistics for servers or chassis',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the server or chassis',
            },
            resourceType: {
              type: 'string',
              description: 'Resource type: server or chassis',
              enum: ['server', 'chassis'],
            },
          },
          required: ['moid', 'resourceType'],
        },
      },
      {
        name: 'list_fan_modules',
        description: 'List fan modules with operational status and speed',
        inputSchema: {
          type: 'object',
          properties: {
            chassisMoid: {
              type: 'string',
              description: 'MOID of the chassis (optional filter)',
            },
          },
        },
      },
      {
        name: 'list_psu_units',
        description: 'List power supply units with status and output',
        inputSchema: {
          type: 'object',
          properties: {
            chassisMoid: {
              type: 'string',
              description: 'MOID of the chassis (optional filter)',
            },
          },
        },
      },
      {
        name: 'get_top_resources',
        description: 'Get top N resources by metric (CPU, memory, power, temperature). Useful for finding highest utilization, hottest servers, power consumption leaders, etc.',
        inputSchema: {
          type: 'object',
          properties: {
            metricName: {
              type: 'string',
              description: 'Metric to rank by: CpuUtilization, MemoryUtilization, PowerConsumption, Temperature',
              enum: ['CpuUtilization', 'MemoryUtilization', 'PowerConsumption', 'Temperature'],
            },
            topN: {
              type: 'number',
              description: 'Number of top resources to return (default: 10)',
            },
            resourceType: {
              type: 'string',
              description: 'Type of resource: Server, Chassis, or All (default: Server)',
              enum: ['Server', 'Chassis', 'All'],
            },
          },
          required: ['metricName'],
        },
      },

      // Hardware Compatibility List (HCL) Tools
      {
        name: 'list_hcl_operating_systems',
        description: 'List supported operating systems from Hardware Compatibility List',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression (e.g., "Version contains \'Red Hat\'")',
            },
          },
        },
      },
      {
        name: 'list_hcl_operating_system_vendors',
        description: 'List operating system vendors from Hardware Compatibility List',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_hcl_hyperflex_compatibility',
        description: 'List HyperFlex software compatibility information',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },

      // Technical Advisory Management (TAM) Tools
      {
        name: 'list_tam_advisories',
        description: 'List all technical advisories and field notices affecting your infrastructure',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression (e.g., "Type eq \'fieldNotice\'")',
            },
          },
        },
      },
      {
        name: 'get_tam_advisory',
        description: 'Get detailed information about a specific advisory',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the advisory definition',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_tam_advisory_instances',
        description: 'List advisory instances showing which devices are affected by advisories',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression (e.g., filter by advisory MOID or affected object type)',
            },
          },
        },
      },
      {
        name: 'list_tam_security_advisories',
        description: 'List security advisories affecting your infrastructure',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_tam_advisory_count',
        description: 'Get count of advisories affecting infrastructure by severity',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },

      // Terminal & Systems Tools
      {
        name: 'list_terminal_audit_logs',
        description: 'List terminal session audit logs for compliance and security monitoring',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression (e.g., filter by user, device, or time range)',
            },
          },
        },
      },
      {
        name: 'list_top_systems',
        description: 'List all top-level systems with their associated compute resources (blades and rack units)',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'get_top_system',
        description: 'Get details of a specific top-level system including compute resources and network elements',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the top-level system',
            },
          },
          required: ['moid'],
        },
      },

      // Compute Inventory Tools
      {
        name: 'list_compute_blades',
        description: 'List all blade servers in chassis',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_compute_rack_units',
        description: 'List all rack-mounted servers',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_compute_boards',
        description: 'List all server motherboards',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },

      // Storage Tools
      {
        name: 'list_storage_virtual_drives',
        description: 'List all virtual drives (RAID volumes)',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_storage_flex_flash_controllers',
        description: 'List all FlexFlash controllers',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_storage_flex_flash_drives',
        description: 'List all FlexFlash physical drives',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },

      // Equipment Tools
      {
        name: 'list_equipment_io_cards',
        description: 'List all IO cards in chassis',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_equipment_sys_io_ctrls',
        description: 'List all system IO controllers',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },

      // Firmware Tools
      {
        name: 'list_firmware_running',
        description: 'List all running firmware versions across infrastructure',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression (e.g., filter by component type)',
            },
          },
        },
      },
      {
        name: 'list_firmware_upgrades',
        description: 'List all firmware upgrade operations',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },

      // License Tools
      {
        name: 'list_licenses',
        description: 'List all license information for registered devices',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },

      // Workflow Tools
      {
        name: 'list_workflows',
        description: 'List all workflow executions',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression (e.g., filter by status or time)',
            },
          },
        },
      },
      {
        name: 'get_workflow',
        description: 'Get details of a specific workflow execution',
        inputSchema: {
          type: 'object',
          properties: {
            moid: {
              type: 'string',
              description: 'MOID of the workflow',
            },
          },
          required: ['moid'],
        },
      },
      {
        name: 'list_workflow_tasks',
        description: 'List all workflow task executions',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },

      // PCI Tools
      {
        name: 'list_pci_devices',
        description: 'List all PCI devices (NICs, HBAs, GPU, etc.)',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },

      // Graphics Tools
      {
        name: 'list_graphics_cards',
        description: 'List all graphics cards (GPUs)',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },

      // BIOS Tools
      {
        name: 'list_bios_units',
        description: 'List all BIOS/UEFI firmware units',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },

      // Management Tools
      {
        name: 'list_management_controllers',
        description: 'List all management controllers (CIMC, IMC, BMC)',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },
      {
        name: 'list_management_interfaces',
        description: 'List all management network interfaces',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'OData filter expression',
            },
          },
        },
      },

      // PowerShell Examples Tool
      {
        name: 'get_powershell_examples',
        description: 'Get Cisco Intersight PowerShell module programming examples from GitHub. Returns code examples for various Intersight operations using the PowerShell SDK.',
        inputSchema: {
          type: 'object',
          properties: {
            topic: {
              type: 'string',
              description: 'Optional topic to search for (e.g., "server", "policy", "firmware", "workflow"). If not provided, returns list of available examples.',
            },
          },
        },
      },

      // Python Examples Tool
      {
        name: 'get_python_examples',
        description: 'Get Cisco Intersight Python SDK programming examples from GitHub. Accesses both the intersight-python examples and intersight-python-utils repositories for comprehensive Python code samples.',
        inputSchema: {
          type: 'object',
          properties: {
            topic: {
              type: 'string',
              description: 'Optional topic to search for (e.g., "servers", "policies", "firmware", "workflows"). If not provided, returns list of available examples.',
            },
            source: {
              type: 'string',
              description: 'Optional source: "examples" (SDK examples), "utils" (utility scripts), or "all" (default: all sources)',
              enum: ['examples', 'utils', 'all'],
            },
          },
        },
      },

      // Terraform Examples Tool
      {
        name: 'get_terraform_examples',
        description: 'Get Cisco Intersight Terraform resources and documentation. Access provider documentation from Terraform Registry and module examples from GitHub.',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'Optional resource or module name to search for (e.g., "server_profile", "policy", "pool", "network"). If not provided, returns list of available options.',
            },
            source: {
              type: 'string',
              description: 'Source: "registry" (Terraform Registry docs), "modules" (GitHub modules), or "all" (default: all)',
              enum: ['registry', 'modules', 'all'],
            },
          },
        },
      },

      // Ansible Examples Tool
      {
        name: 'get_ansible_examples',
        description: 'Get Cisco Intersight Ansible modules, playbooks, and CVD solutions. Access automation code from Ansible collection and validated design documentation.',
        inputSchema: {
          type: 'object',
          properties: {
            resource: {
              type: 'string',
              description: 'Optional resource name to search for (e.g., "server", "profile", "policy", "network"). If not provided, returns list of available options.',
            },
            source: {
              type: 'string',
              description: 'Source: "modules" (Ansible modules), "playbooks" (example playbooks), "cvd" (CVD solutions), or "all" (default: all)',
              enum: ['modules', 'playbooks', 'cvd', 'all'],
            },
          },
        },
      },

      // Security & Health Check Agent
      {
        name: 'generate_security_health_report',
        description: 'Generate a comprehensive security and health check report for the entire Intersight infrastructure. Analyzes alarms, advisories, CVEs, firmware, hardware health, security posture, compliance, and performance. Returns actionable recommendations prioritized by urgency.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  private async handleToolCall(name: string, args: Record<string, any>): Promise<any> {
    switch (name) {
      // Inventory & Discovery
      case 'list_compute_servers':
        return this.apiService.listComputeServers(args.filter);
      
      case 'get_server_details':
        return this.apiService.getServerDetails(args.moid);
      
      case 'list_chassis':
        return this.apiService.listChassis();
      
      case 'list_fabric_interconnects':
        return this.apiService.listFabricInterconnects();

      // Alarms & Monitoring
      case 'list_alarms':
        return this.apiService.listAlarms(args.filter);
      
      case 'acknowledge_alarm':
        return this.apiService.acknowledgeAlarm(args.moid);

      // Policy Management
      case 'list_policies':
        return this.apiService.listPolicies(args.policyType);
      
      case 'get_policy':
        return this.apiService.getPolicy(args.policyType, args.moid);
      
      case 'create_boot_policy':
        return this.apiService.createPolicy('boot/PrecisionPolicies', {
          ObjectType: 'boot.PrecisionPolicy',
          Name: args.name,
          Description: args.description,
          ConfiguredBootMode: args.bootMode,
          EnforceUefiSecureBoot: args.secureBoot,
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'create_bios_policy':
        return this.apiService.createPolicy('bios/Policies', {
          ObjectType: 'bios.Policy',
          Name: args.name,
          Description: args.description,
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'create_network_policy':
        return this.apiService.createPolicy('vnic/LanConnectivityPolicies', {
          ObjectType: 'vnic.LanConnectivityPolicy',
          Name: args.name,
          Description: args.description,
          TargetPlatform: args.targetPlatform,
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      // vNIC Management
      case 'list_vnics':
        const vnicFilter = args.lanConnectivityPolicyMoid
          ? `LanConnectivityPolicy/Moid eq '${args.lanConnectivityPolicyMoid}'`
          : '';
        return this.apiService.get(`/vnic/EthIfs${vnicFilter ? '?$filter=' + vnicFilter : ''}`);
      
      case 'get_vnic':
        return this.apiService.get(`/vnic/EthIfs/${args.moid}`);
      
      case 'update_vnic':
        return this.apiService.patch(`/vnic/EthIfs/${args.moid}`, args.updates);
      
      case 'delete_vnic':
        return this.apiService.delete(`/vnic/EthIfs/${args.moid}`);
      
      case 'create_vnic':
        const vnicData: any = {
          ObjectType: 'vnic.EthIf',
          Name: args.name,
          Order: args.order || 0,
          Placement: {
            SwitchId: args.fabricId,
            Id: 'MLOM',
          },
          MacAddressType: args.macPoolMoid ? 'POOL' : 'POOL',
          LanConnectivityPolicy: {
            ClassId: 'mo.MoRef',
            ObjectType: 'vnic.LanConnectivityPolicy',
            Moid: args.lanConnectivityPolicyMoid,
          },
          EthAdapterPolicy: {
            ClassId: 'mo.MoRef',
            ObjectType: 'vnic.EthAdapterPolicy',
            Moid: args.ethAdapterPolicyMoid,
          },
          EthQosPolicy: {
            ClassId: 'mo.MoRef',
            ObjectType: 'vnic.EthQosPolicy',
            Moid: args.ethQosPolicyMoid,
          },
          FabricEthNetworkGroupPolicy: [{
            ClassId: 'mo.MoRef',
            ObjectType: 'fabric.EthNetworkGroupPolicy',
            Moid: args.ethNetworkGroupPolicyMoid,
          }],
        };
        
        if (args.macPoolMoid) {
          vnicData.MacPool = {
            ClassId: 'mo.MoRef',
            ObjectType: 'macpool.Pool',
            Moid: args.macPoolMoid,
          };
        }
        
        return this.apiService.createPolicy('vnic/EthIfs', vnicData);
      
      // vNIC Policy Management
      case 'list_lan_connectivity_policies':
        return this.apiService.get(args.filter ? `/vnic/LanConnectivityPolicies?$filter=${args.filter}` : '/vnic/LanConnectivityPolicies');
      
      case 'get_lan_connectivity_policy':
        return this.apiService.get(`/vnic/LanConnectivityPolicies/${args.moid}`);
      
      case 'list_eth_adapter_policies':
        return this.apiService.get(args.filter ? `/vnic/EthAdapterPolicies?$filter=${args.filter}` : '/vnic/EthAdapterPolicies');
      
      case 'list_eth_qos_policies':
        return this.apiService.get(args.filter ? `/vnic/EthQosPolicies?$filter=${args.filter}` : '/vnic/EthQosPolicies');
      
      case 'list_eth_network_group_policies':
        return this.apiService.get(args.filter ? `/fabric/EthNetworkGroupPolicies?$filter=${args.filter}` : '/fabric/EthNetworkGroupPolicies');
      
      case 'create_vlan_group':
        const vlanSettings = args.vlanIds.map((vlanId: number) => ({
          VlanId: vlanId,
          Name: `VLAN${vlanId}`,
          DefaultVlan: args.nativeVlan === vlanId,
          AutoAllowOnUplinks: true,
        }));
        
        return this.apiService.createPolicy('fabric/EthNetworkGroupPolicies', {
          ObjectType: 'fabric.EthNetworkGroupPolicy',
          Name: args.name,
          Description: args.description || `VLAN group for VLANs: ${args.vlanIds.join(', ')}`,
          VlanSettings: {
            ClassId: 'fabric.VlanSettings',
            ObjectType: 'fabric.VlanSettings',
            AllowedVlans: args.vlanIds.join(','),
            NativeVlan: args.nativeVlan || args.vlanIds[0],
          },
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'create_eth_network_policy':
        return this.apiService.createPolicy('vnic/EthNetworkPolicies', {
          ObjectType: 'vnic.EthNetworkPolicy',
          Name: args.name,
          VlanSettings: args.vlanGroupMoid,
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_policy':
        return this.apiService.updatePolicy(args.policyType, args.moid, args.updates);
      
      case 'delete_policy':
        return this.apiService.deletePolicy(args.policyType, args.moid);

      // Pool Management
      case 'list_pools':
        return this.apiService.listPools(args.poolType);
      
      case 'create_ip_pool':
        return this.apiService.createPool('ippool/Pools', {
          ObjectType: 'ippool.Pool',
          Name: args.name,
          Description: args.description,
          IpV4Blocks: [{
            From: args.ipBlockFrom,
            To: args.ipBlockTo,
          }],
          IpV4Config: {
            Gateway: args.gateway,
            Netmask: args.netmask,
            PrimaryDns: args.primaryDns,
          },
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'create_mac_pool':
        return this.apiService.createPool('macpool/Pools', {
          ObjectType: 'macpool.Pool',
          Name: args.name,
          Description: args.description,
          MacBlocks: [{
            From: args.macBlockFrom,
            To: args.macBlockTo,
          }],
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'create_uuid_pool':
        return this.apiService.createPool('uuidpool/Pools', {
          ObjectType: 'uuidpool.Pool',
          Name: args.name,
          Description: args.description,
          Prefix: args.prefix,
          UuidSuffixBlocks: [{
            From: args.uuidBlockFrom,
            To: args.uuidBlockTo,
          }],
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'create_wwnn_pool':
        return this.apiService.createPool('fcpool/Pools', {
          ObjectType: 'fcpool.Pool',
          Name: args.name,
          Description: args.description,
          PoolPurpose: 'WWNN',
          IdBlocks: [{
            From: args.wwnnBlockFrom,
            To: args.wwnnBlockTo,
          }],
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'create_wwpn_pool':
        return this.apiService.createPool('fcpool/Pools', {
          ObjectType: 'fcpool.Pool',
          Name: args.name,
          Description: args.description,
          PoolPurpose: 'WWPN',
          IdBlocks: [{
            From: args.wwpnBlockFrom,
            To: args.wwpnBlockTo,
          }],
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_pool':
        return this.apiService.updatePool(args.poolType, args.moid, args.updates);
      
      case 'delete_pool':
        return this.apiService.deletePool(args.poolType, args.moid);

      // Configuration Management - Adapter Configuration
      case 'list_adapter_config_policies':
        return this.apiService.get(args.filter ? `/vnic/EthAdapterPolicies?$filter=${args.filter}` : '/vnic/EthAdapterPolicies');
      
      case 'get_adapter_config_policy':
        return this.apiService.get(`/vnic/EthAdapterPolicies/${args.moid}`);
      
      case 'create_adapter_config_policy':
        return this.apiService.post('/vnic/EthAdapterPolicies', {
          ObjectType: 'vnic.EthAdapterPolicy',
          Name: args.name,
          Description: args.description,
          RssSettings: args.rssSettings,
          InterruptSettings: args.interruptSettings,
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_adapter_config_policy':
        return this.apiService.patch(`/vnic/EthAdapterPolicies/${args.moid}`, args.updates);
      
      case 'delete_adapter_config_policy':
        return this.apiService.delete(`/vnic/EthAdapterPolicies/${args.moid}`);

      // Configuration Management - Fabric Port Channels
      case 'list_fabric_port_channels':
        return this.apiService.get(args.filter ? `/fabric/PortChannels?$filter=${args.filter}` : '/fabric/PortChannels');
      
      case 'get_fabric_port_channel':
        return this.apiService.get(`/fabric/PortChannels/${args.moid}`);
      
      case 'create_fabric_port_channel':
        return this.apiService.post('/fabric/PortChannels', {
          ObjectType: 'fabric.PortChannel',
          Name: args.name,
          PortChannelId: args.portChannelId,
          AdminSpeed: args.adminSpeed,
          NetworkElement: {
            ClassId: 'mo.MoRef',
            ObjectType: 'network.Element',
            Moid: args.fabricInterconnectMoid,
          },
        });
      
      case 'update_fabric_port_channel':
        return this.apiService.patch(`/fabric/PortChannels/${args.moid}`, args.updates);
      
      case 'delete_fabric_port_channel':
        return this.apiService.delete(`/fabric/PortChannels/${args.moid}`);

      // Configuration Management - VLANs
      case 'list_fabric_vlans':
        return this.apiService.get(args.filter ? `/fabric/Vlans?$filter=${args.filter}` : '/fabric/Vlans');
      
      case 'get_fabric_vlan':
        return this.apiService.get(`/fabric/Vlans/${args.moid}`);
      
      case 'create_fabric_vlan':
        const vlanData: Record<string, any> = {
          ObjectType: 'fabric.Vlan',
          Name: args.name,
          VlanId: args.vlanId,
          IsNative: args.isNative || false,
        };
        if (args.fabricEthNetworkGroupPolicyMoid) {
          vlanData.EthNetworkPolicy = {
            ClassId: 'mo.MoRef',
            ObjectType: 'fabric.EthNetworkGroupPolicy',
            Moid: args.fabricEthNetworkGroupPolicyMoid,
          };
        }
        if (args.multicastPolicyMoid) {
          vlanData.MulticastPolicy = {
            ClassId: 'mo.MoRef',
            ObjectType: 'fabric.MulticastPolicy',
            Moid: args.multicastPolicyMoid,
          };
        }
        return this.apiService.post('/fabric/Vlans', vlanData);
      
      case 'update_fabric_vlan':
        return this.apiService.patch(`/fabric/Vlans/${args.moid}`, args.updates);
      
      case 'delete_fabric_vlan':
        return this.apiService.delete(`/fabric/Vlans/${args.moid}`);

      // Configuration Management - VSANs
      case 'list_fabric_vsans':
        return this.apiService.get(args.filter ? `/fabric/Vsans?$filter=${args.filter}` : '/fabric/Vsans');
      
      case 'get_fabric_vsan':
        return this.apiService.get(`/fabric/Vsans/${args.moid}`);
      
      case 'create_fabric_vsan':
        return this.apiService.post('/fabric/Vsans', {
          ObjectType: 'fabric.Vsan',
          Name: args.name,
          VsanId: args.vsanId,
          FcZoneSharingMode: args.fcZoneSharingMode,
          DefaultZoning: args.defaultZoning,
        });
      
      case 'update_fabric_vsan':
        return this.apiService.patch(`/fabric/Vsans/${args.moid}`, args.updates);
      
      case 'delete_fabric_vsan':
        return this.apiService.delete(`/fabric/Vsans/${args.moid}`);

      // Configuration Management - IP Pool Blocks
      case 'list_ippool_blocks':
        return this.apiService.get(args.filter ? `/ippool/Blocks?$filter=${args.filter}` : '/ippool/Blocks');
      
      case 'get_ippool_block':
        return this.apiService.get(`/ippool/Blocks/${args.moid}`);
      
      case 'create_ippool_block':
        return this.apiService.post('/ippool/Blocks', {
          ObjectType: 'ippool.Block',
          From: args.from,
          To: args.to,
          Size: args.size,
          Pool: {
            ClassId: 'mo.MoRef',
            ObjectType: 'ippool.Pool',
            Moid: args.poolMoid,
          },
        });
      
      case 'update_ippool_block':
        return this.apiService.patch(`/ippool/Blocks/${args.moid}`, args.updates);
      
      case 'delete_ippool_block':
        return this.apiService.delete(`/ippool/Blocks/${args.moid}`);

      // Configuration Management - MAC Pool Blocks
      case 'list_macpool_blocks':
        return this.apiService.get(args.filter ? `/macpool/Blocks?$filter=${args.filter}` : '/macpool/Blocks');
      
      case 'get_macpool_block':
        return this.apiService.get(`/macpool/Blocks/${args.moid}`);
      
      case 'create_macpool_block':
        return this.apiService.post('/macpool/Blocks', {
          ObjectType: 'macpool.Block',
          From: args.from,
          To: args.to,
          Size: args.size,
          Pool: {
            ClassId: 'mo.MoRef',
            ObjectType: 'macpool.Pool',
            Moid: args.poolMoid,
          },
        });
      
      case 'update_macpool_block':
        return this.apiService.patch(`/macpool/Blocks/${args.moid}`, args.updates);
      
      case 'delete_macpool_block':
        return this.apiService.delete(`/macpool/Blocks/${args.moid}`);

      // Configuration Management - FC Pool Blocks
      case 'list_fcpool_blocks':
        return this.apiService.get(args.filter ? `/fcpool/Blocks?$filter=${args.filter}` : '/fcpool/Blocks');
      
      case 'get_fcpool_block':
        return this.apiService.get(`/fcpool/Blocks/${args.moid}`);
      
      case 'create_fcpool_block':
        return this.apiService.post('/fcpool/Blocks', {
          ObjectType: 'fcpool.Block',
          From: args.from,
          To: args.to,
          Size: args.size,
          Pool: {
            ClassId: 'mo.MoRef',
            ObjectType: 'fcpool.Pool',
            Moid: args.poolMoid,
          },
        });
      
      case 'update_fcpool_block':
        return this.apiService.patch(`/fcpool/Blocks/${args.moid}`, args.updates);
      
      case 'delete_fcpool_block':
        return this.apiService.delete(`/fcpool/Blocks/${args.moid}`);

      // Advanced Networking - Fabric Uplink/Server Ports
      case 'list_fabric_uplink_ports':
        return this.apiService.get(args.filter ? `/fabric/UplinkPcRoles?$filter=${args.filter}` : '/fabric/UplinkPcRoles');
      
      case 'list_fabric_server_ports':
        return this.apiService.get(args.filter ? `/fabric/ServerRoles?$filter=${args.filter}` : '/fabric/ServerRoles');
      
      case 'list_fabric_port_operations':
        return this.apiService.get(args.filter ? `/fabric/PortOperations?$filter=${args.filter}` : '/fabric/PortOperations');

      // Network Control Policies
      case 'list_fabric_flow_control_policies':
        return this.apiService.get(args.filter ? `/fabric/FlowControlPolicies?$filter=${args.filter}` : '/fabric/FlowControlPolicies');
      
      case 'get_fabric_flow_control_policy':
        return this.apiService.get(`/fabric/FlowControlPolicies/${args.moid}`);
      
      case 'create_fabric_flow_control_policy':
        return this.apiService.post('/fabric/FlowControlPolicies', {
          ObjectType: 'fabric.FlowControlPolicy',
          Name: args.name,
          PriorityFlowControlMode: args.priorityFlowControlMode || 'auto',
          ReceiveDirection: args.receiveDirection || 'Disabled',
          SendDirection: args.sendDirection || 'Disabled',
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_fabric_flow_control_policy':
        return this.apiService.patch(`/fabric/FlowControlPolicies/${args.moid}`, args.updates);
      
      case 'delete_fabric_flow_control_policy':
        return this.apiService.delete(`/fabric/FlowControlPolicies/${args.moid}`);
      
      case 'list_fabric_link_control_policies':
        return this.apiService.get(args.filter ? `/fabric/LinkControlPolicies?$filter=${args.filter}` : '/fabric/LinkControlPolicies');
      
      case 'get_fabric_link_control_policy':
        return this.apiService.get(`/fabric/LinkControlPolicies/${args.moid}`);
      
      case 'create_fabric_link_control_policy':
        return this.apiService.post('/fabric/LinkControlPolicies', {
          ObjectType: 'fabric.LinkControlPolicy',
          Name: args.name,
          UdldSettings: args.udldSettings || {},
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_fabric_link_control_policy':
        return this.apiService.patch(`/fabric/LinkControlPolicies/${args.moid}`, args.updates);
      
      case 'delete_fabric_link_control_policy':
        return this.apiService.delete(`/fabric/LinkControlPolicies/${args.moid}`);
      
      case 'list_fabric_lacp_policies':
        return this.apiService.get(args.filter ? `/fabric/LinkAggregationPolicies?$filter=${args.filter}` : '/fabric/LinkAggregationPolicies');
      
      case 'get_fabric_lacp_policy':
        return this.apiService.get(`/fabric/LinkAggregationPolicies/${args.moid}`);
      
      case 'create_fabric_lacp_policy':
        return this.apiService.post('/fabric/LinkAggregationPolicies', {
          ObjectType: 'fabric.LinkAggregationPolicy',
          Name: args.name,
          LacpRate: args.lacpRate || 'normal',
          SuspendIndividual: args.suspendIndividual || false,
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_fabric_lacp_policy':
        return this.apiService.patch(`/fabric/LinkAggregationPolicies/${args.moid}`, args.updates);
      
      case 'delete_fabric_lacp_policy':
        return this.apiService.delete(`/fabric/LinkAggregationPolicies/${args.moid}`);
      
      case 'list_fabric_system_qos_policies':
        return this.apiService.get(args.filter ? `/fabric/SystemQosPolicies?$filter=${args.filter}` : '/fabric/SystemQosPolicies');
      
      case 'get_fabric_system_qos_policy':
        return this.apiService.get(`/fabric/SystemQosPolicies/${args.moid}`);
      
      case 'list_fabric_multicast_policies':
        return this.apiService.get(args.filter ? `/fabric/MulticastPolicies?$filter=${args.filter}` : '/fabric/MulticastPolicies');
      
      case 'get_fabric_multicast_policy':
        return this.apiService.get(`/fabric/MulticastPolicies/${args.moid}`);
      
      case 'create_fabric_multicast_policy':
        return this.apiService.post('/fabric/MulticastPolicies', {
          ObjectType: 'fabric.MulticastPolicy',
          Name: args.name,
          QuerierIpAddress: args.querierIpAddress || '',
          QuerierState: args.querierState || 'Disabled',
          SnoopingState: args.snoopingState || 'Enabled',
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_fabric_multicast_policy':
        return this.apiService.patch(`/fabric/MulticastPolicies/${args.moid}`, args.updates);
      
      case 'delete_fabric_multicast_policy':
        return this.apiService.delete(`/fabric/MulticastPolicies/${args.moid}`);

      // Hardware Security & Management
      case 'list_equipment_tpms':
        return this.apiService.get(args.filter ? `/equipment/Tpms?$filter=${args.filter}` : '/equipment/Tpms');
      
      case 'get_equipment_tpm':
        return this.apiService.get(`/equipment/Tpms/${args.moid}`);
      
      case 'list_boot_device_boot_modes':
        return this.apiService.get(args.filter ? `/boot/DeviceBootModes?$filter=${args.filter}` : '/boot/DeviceBootModes');
      
      case 'list_boot_device_boot_securities':
        return this.apiService.get(args.filter ? `/boot/DeviceBootSecurities?$filter=${args.filter}` : '/boot/DeviceBootSecurities');
      
      case 'list_storage_local_disk_policies':
        return this.apiService.get(args.filter ? `/storage/StoragePolicies?$filter=${args.filter}` : '/storage/StoragePolicies');
      
      case 'get_storage_local_disk_policy':
        return this.apiService.get(`/storage/StoragePolicies/${args.moid}`);
      
      case 'create_storage_local_disk_policy':
        return this.apiService.post('/storage/StoragePolicies', {
          ObjectType: 'storage.StoragePolicy',
          Name: args.name,
          UnusedDisksState: args.mode,
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_storage_local_disk_policy':
        return this.apiService.patch(`/storage/StoragePolicies/${args.moid}`, args.updates);
      
      case 'delete_storage_local_disk_policy':
        return this.apiService.delete(`/storage/StoragePolicies/${args.moid}`);
      
      case 'list_sdcard_policies':
        return this.apiService.get(args.filter ? `/sdcard/Policies?$filter=${args.filter}` : '/sdcard/Policies');
      
      case 'get_sdcard_policy':
        return this.apiService.get(`/sdcard/Policies/${args.moid}`);
      
      case 'create_sdcard_policy':
        return this.apiService.post('/sdcard/Policies', {
          ObjectType: 'sdcard.Policy',
          Name: args.name,
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_sdcard_policy':
        return this.apiService.patch(`/sdcard/Policies/${args.moid}`, args.updates);
      
      case 'delete_sdcard_policy':
        return this.apiService.delete(`/sdcard/Policies/${args.moid}`);
      
      case 'list_kvm_policies':
        return this.apiService.get(args.filter ? `/kvm/Policies?$filter=${args.filter}` : '/kvm/Policies');
      
      case 'get_kvm_policy':
        return this.apiService.get(`/kvm/Policies/${args.moid}`);
      
      case 'create_kvm_policy':
        return this.apiService.post('/kvm/Policies', {
          ObjectType: 'kvm.Policy',
          Name: args.name,
          EnableLocalServerVideo: args.enableLocalServerVideo !== undefined ? args.enableLocalServerVideo : true,
          EnableVideoEncryption: args.enableVideoEncryption !== undefined ? args.enableVideoEncryption : true,
          MaximumSessions: args.maximumSessions || 4,
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_kvm_policy':
        return this.apiService.patch(`/kvm/Policies/${args.moid}`, args.updates);
      
      case 'delete_kvm_policy':
        return this.apiService.delete(`/kvm/Policies/${args.moid}`);
      
      case 'list_virtual_media_policies':
        return this.apiService.get(args.filter ? `/vmedia/Policies?$filter=${args.filter}` : '/vmedia/Policies');
      
      case 'get_virtual_media_policy':
        return this.apiService.get(`/vmedia/Policies/${args.moid}`);
      
      case 'create_virtual_media_policy':
        return this.apiService.post('/vmedia/Policies', {
          ObjectType: 'vmedia.Policy',
          Name: args.name,
          Encryption: args.encryption !== undefined ? args.encryption : true,
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_virtual_media_policy':
        return this.apiService.patch(`/vmedia/Policies/${args.moid}`, args.updates);
      
      case 'delete_virtual_media_policy':
        return this.apiService.delete(`/vmedia/Policies/${args.moid}`);

      // System Policies
      case 'list_snmp_policies':
        return this.apiService.get(args.filter ? `/snmp/Policies?$filter=${args.filter}` : '/snmp/Policies');
      
      case 'get_snmp_policy':
        return this.apiService.get(`/snmp/Policies/${args.moid}`);
      
      case 'create_snmp_policy':
        return this.apiService.post('/snmp/Policies', {
          ObjectType: 'snmp.Policy',
          Name: args.name,
          Enabled: args.enabled !== undefined ? args.enabled : true,
          SnmpPort: args.snmpPort || 161,
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_snmp_policy':
        return this.apiService.patch(`/snmp/Policies/${args.moid}`, args.updates);
      
      case 'delete_snmp_policy':
        return this.apiService.delete(`/snmp/Policies/${args.moid}`);
      
      case 'list_syslog_policies':
        return this.apiService.get(args.filter ? `/syslog/Policies?$filter=${args.filter}` : '/syslog/Policies');
      
      case 'get_syslog_policy':
        return this.apiService.get(`/syslog/Policies/${args.moid}`);
      
      case 'create_syslog_policy':
        return this.apiService.post('/syslog/Policies', {
          ObjectType: 'syslog.Policy',
          Name: args.name,
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_syslog_policy':
        return this.apiService.patch(`/syslog/Policies/${args.moid}`, args.updates);
      
      case 'delete_syslog_policy':
        return this.apiService.delete(`/syslog/Policies/${args.moid}`);
      
      case 'list_ntp_policies':
        return this.apiService.get(args.filter ? `/ntp/Policies?$filter=${args.filter}` : '/ntp/Policies');
      
      case 'get_ntp_policy':
        return this.apiService.get(`/ntp/Policies/${args.moid}`);
      
      case 'create_ntp_policy':
        return this.apiService.post('/ntp/Policies', {
          ObjectType: 'ntp.Policy',
          Name: args.name,
          Enabled: args.enabled !== undefined ? args.enabled : true,
          NtpServers: args.ntpServers || [],
          Timezone: args.timezone || 'America/Los_Angeles',
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_ntp_policy':
        return this.apiService.patch(`/ntp/Policies/${args.moid}`, args.updates);
      
      case 'delete_ntp_policy':
        return this.apiService.delete(`/ntp/Policies/${args.moid}`);
      
      case 'list_smtp_policies':
        return this.apiService.get(args.filter ? `/smtp/Policies?$filter=${args.filter}` : '/smtp/Policies');
      
      case 'get_smtp_policy':
        return this.apiService.get(`/smtp/Policies/${args.moid}`);
      
      case 'create_smtp_policy':
        return this.apiService.post('/smtp/Policies', {
          ObjectType: 'smtp.Policy',
          Name: args.name,
          SmtpServer: args.smtpServer,
          SmtpPort: args.smtpPort || 25,
          SenderEmail: args.senderEmail || '',
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'update_smtp_policy':
        return this.apiService.patch(`/smtp/Policies/${args.moid}`, args.updates);
      
      case 'delete_smtp_policy':
        return this.apiService.delete(`/smtp/Policies/${args.moid}`);
      
      case 'list_deviceconnector_policies':
        return this.apiService.get(args.filter ? `/deviceconnector/Policies?$filter=${args.filter}` : '/deviceconnector/Policies');
      
      case 'get_deviceconnector_policy':
        return this.apiService.get(`/deviceconnector/Policies/${args.moid}`);
      
      case 'list_certificatemanagement_policies':
        return this.apiService.get(args.filter ? `/certificatemanagement/Policies?$filter=${args.filter}` : '/certificatemanagement/Policies');
      
      case 'get_certificatemanagement_policy':
        return this.apiService.get(`/certificatemanagement/Policies/${args.moid}`);

      // Profile Management
      case 'list_server_profiles':
        return this.apiService.listServerProfiles();
      
      case 'get_server_profile':
        return this.apiService.getServerProfile(args.moid);
      
      case 'create_server_profile':
        return this.apiService.createServerProfile({
          ObjectType: 'server.Profile',
          Name: args.name,
          Description: args.description,
          TargetPlatform: args.targetPlatform || 'FIAttached',
          Organization: {
            ClassId: 'mo.MoRef',
            ObjectType: 'organization.Organization',
            Moid: args.organizationMoid,
          },
        });
      
      case 'attach_policy_to_profile': {
        const updateData: Record<string, any> = {};
        updateData[args.policyField] = {
          ClassId: 'mo.MoRef',
          ObjectType: args.policyType,
          Moid: args.policyMoid,
        };
        return this.apiService.updateServerProfile(args.profileMoid, updateData);
      }
      
      case 'attach_pool_to_profile': {
        const updateData: Record<string, any> = {};
        updateData[args.poolField] = {
          ClassId: 'mo.MoRef',
          ObjectType: args.poolType,
          Moid: args.poolMoid,
        };
        return this.apiService.updateServerProfile(args.profileMoid, updateData);
      }
      
      case 'assign_server_to_profile':
        return this.apiService.updateServerProfile(args.profileMoid, {
          AssignedServer: {
            ClassId: 'mo.MoRef',
            ObjectType: 'compute.RackUnit',
            Moid: args.serverMoid,
          },
        });
      
      case 'deploy_server_profile':
        return this.apiService.deployServerProfile(args.moid, args.action);
      
      case 'update_server_profile':
        return this.apiService.updateServerProfile(args.moid, args.updates);
      
      case 'delete_server_profile':
        return this.apiService.deleteServerProfile(args.moid);

      // Search & Query
      case 'search_resources':
        return this.apiService.searchResources(args.resourceType, args.filter);

      // Telemetry & Metrics
      case 'get_server_telemetry':
        return this.apiService.getServerTelemetry(args.serverMoid, args.metricType);
      
      case 'get_chassis_telemetry':
        return this.apiService.getChassisTelemetry(args.chassisMoid);
      
      case 'get_adapter_telemetry':
        return this.apiService.getAdapterTelemetry(args.adapterMoid);
      
      case 'list_processor_units':
        return this.apiService.listProcessorUnits(args.filter);
      
      case 'list_memory_units':
        return this.apiService.listMemoryUnits(args.filter);
      
      case 'list_storage_controllers':
        return this.apiService.listStorageControllers(args.filter);
      
      case 'list_physical_drives':
        return this.apiService.listPhysicalDrives(args.filter);
      
      case 'get_power_statistics':
        return this.apiService.getPowerStatistics(args.moid, args.resourceType);
      
      case 'get_thermal_statistics':
        return this.apiService.getThermalStatistics(args.moid, args.resourceType);
      
      case 'list_fan_modules':
        return this.apiService.listFanModules(args.chassisMoid);
      
      case 'list_psu_units':
        return this.apiService.listPsuUnits(args.chassisMoid);
      
      case 'get_top_resources':
        return this.apiService.getTopResources(args.metricName, args.topN, args.resourceType);

      // Hardware Compatibility List (HCL)
      case 'list_hcl_operating_systems':
        return this.apiService.get(args.filter ? `/hcl/OperatingSystems?$filter=${args.filter}` : '/hcl/OperatingSystems');
      
      case 'list_hcl_operating_system_vendors':
        return this.apiService.get(args.filter ? `/hcl/OperatingSystemVendors?$filter=${args.filter}` : '/hcl/OperatingSystemVendors');
      
      case 'list_hcl_hyperflex_compatibility':
        return this.apiService.get(args.filter ? `/hcl/HyperflexSoftwareCompatibilityInfos?$filter=${args.filter}` : '/hcl/HyperflexSoftwareCompatibilityInfos');

      // Technical Advisory Management (TAM)
      case 'list_tam_advisories':
        return this.apiService.get(args.filter ? `/tam/AdvisoryDefinitions?$filter=${args.filter}` : '/tam/AdvisoryDefinitions');
      
      case 'get_tam_advisory':
        return this.apiService.get(`/tam/AdvisoryDefinitions/${args.moid}`);
      
      case 'list_tam_advisory_instances':
        return this.apiService.get(args.filter ? `/tam/AdvisoryInstances?$filter=${args.filter}` : '/tam/AdvisoryInstances');
      
      case 'list_tam_security_advisories':
        return this.apiService.get(args.filter ? `/tam/SecurityAdvisories?$filter=${args.filter}` : '/tam/SecurityAdvisories');
      
      case 'get_tam_advisory_count':
        return this.apiService.get('/tam/AdvisoryCounts');

      // Terminal & Systems
      case 'list_terminal_audit_logs':
        return this.apiService.get(args.filter ? `/terminal/AuditLogs?$filter=${args.filter}` : '/terminal/AuditLogs');
      
      case 'list_top_systems':
        return this.apiService.get(args.filter ? `/top/Systems?$filter=${args.filter}` : '/top/Systems');
      
      case 'get_top_system':
        return this.apiService.get(`/top/Systems/${args.moid}`);

      // Compute Inventory
      case 'list_compute_blades':
        return this.apiService.get(args.filter ? `/compute/Blades?$filter=${args.filter}` : '/compute/Blades');
      
      case 'list_compute_rack_units':
        return this.apiService.get(args.filter ? `/compute/RackUnits?$filter=${args.filter}` : '/compute/RackUnits');
      
      case 'list_compute_boards':
        return this.apiService.get(args.filter ? `/compute/Boards?$filter=${args.filter}` : '/compute/Boards');

      // Storage
      case 'list_storage_virtual_drives':
        return this.apiService.get(args.filter ? `/storage/VirtualDrives?$filter=${args.filter}` : '/storage/VirtualDrives');
      
      case 'list_storage_flex_flash_controllers':
        return this.apiService.get(args.filter ? `/storage/FlexFlashControllers?$filter=${args.filter}` : '/storage/FlexFlashControllers');
      
      case 'list_storage_flex_flash_drives':
        return this.apiService.get(args.filter ? `/storage/FlexFlashPhysicalDrives?$filter=${args.filter}` : '/storage/FlexFlashPhysicalDrives');

      // Equipment
      case 'list_equipment_io_cards':
        return this.apiService.get(args.filter ? `/equipment/IoCards?$filter=${args.filter}` : '/equipment/IoCards');
      
      case 'list_equipment_sys_io_ctrls':
        return this.apiService.get(args.filter ? `/equipment/SystemIoControllers?$filter=${args.filter}` : '/equipment/SystemIoControllers');

      // Firmware
      case 'list_firmware_running':
        return this.apiService.get(args.filter ? `/firmware/RunningFirmwares?$filter=${args.filter}` : '/firmware/RunningFirmwares');
      
      case 'list_firmware_upgrades':
        return this.apiService.get(args.filter ? `/firmware/Upgrades?$filter=${args.filter}` : '/firmware/Upgrades');

      // License
      case 'list_licenses':
        return this.apiService.get(args.filter ? `/license/LicenseInfos?$filter=${args.filter}` : '/license/LicenseInfos');

      // Workflow
      case 'list_workflows':
        return this.apiService.get(args.filter ? `/workflow/WorkflowInfos?$filter=${args.filter}` : '/workflow/WorkflowInfos');
      
      case 'get_workflow':
        return this.apiService.get(`/workflow/WorkflowInfos/${args.moid}`);
      
      case 'list_workflow_tasks':
        return this.apiService.get(args.filter ? `/workflow/TaskInfos?$filter=${args.filter}` : '/workflow/TaskInfos');

      // PCI Devices
      case 'list_pci_devices':
        return this.apiService.get(args.filter ? `/pci/Devices?$filter=${args.filter}` : '/pci/Devices');

      // Graphics
      case 'list_graphics_cards':
        return this.apiService.get(args.filter ? `/graphics/Cards?$filter=${args.filter}` : '/graphics/Cards');

      // BIOS
      case 'list_bios_units':
        return this.apiService.get(args.filter ? `/bios/Units?$filter=${args.filter}` : '/bios/Units');

      // Management
      case 'list_management_controllers':
        return this.apiService.get(args.filter ? `/management/Controllers?$filter=${args.filter}` : '/management/Controllers');
      
      case 'list_management_interfaces':
        return this.apiService.get(args.filter ? `/management/Interfaces?$filter=${args.filter}` : '/management/Interfaces');

      // PowerShell Examples
      case 'get_powershell_examples':
        return this.getPowerShellExamples(args.topic);

      // Python Examples
      case 'get_python_examples':
        return this.getPythonExamples(args.topic, args.source || 'all');

      // Terraform Examples
      case 'get_terraform_examples':
        return this.getTerraformExamples(args.resource, args.source || 'all');

      // Ansible Examples
      case 'get_ansible_examples':
        return this.getAnsibleExamples(args.resource, args.source || 'all');

      // Security & Health Check Report
      case 'generate_security_health_report':
        console.error('🔍 Generating Security & Health Check Report...');
        
        // Collect all necessary data from Intersight API
        const [
          alarms,
          advisoryCount,
          advisories,
          advisoryInstances,
          firmware,
          operatingSystems,
          licenses,
          tpms,
          bootSecurity,
          policies,
          hyperflexCompat,
          processors,
          memoryUnits,
          physicalDrives,
          psuUnits,
          fanModules,
        ] = await Promise.all([
          this.apiService.listAlarms('').catch(() => ({ Results: [] })),
          this.apiService.get('/tam/AdvisoryCounts').catch(() => ({ critical: 0, warning: 0, info: 0 })),
          this.apiService.get('/tam/AdvisoryDefinitions').catch(() => ({ Results: [] })),
          this.apiService.get('/tam/AdvisoryInstances').catch(() => ({ Results: [] })),
          this.apiService.get('/firmware/RunningFirmwares').catch(() => ({ Results: [] })),
          this.apiService.get('/hcl/OperatingSystems').catch(() => ({ Results: [] })),
          this.apiService.get('/license/LicenseInfos').catch(() => ({ Results: [] })),
          this.apiService.get('/equipment/Tpms').catch(() => ({ Results: [] })),
          this.apiService.get('/boot/DeviceBootSecurities').catch(() => ({ Results: [] })),
          this.apiService.listPolicies('all').catch(() => ({ Results: [] })),
          this.apiService.get('/hcl/HyperflexSoftwareCompatibilityInfos').catch(() => ({ Results: [] })),
          this.apiService.get('/processor/Units').catch(() => ({ Results: [] })),
          this.apiService.get('/memory/Units').catch(() => ({ Results: [] })),
          this.apiService.get('/storage/PhysicalDisks').catch(() => ({ Results: [] })),
          this.apiService.get('/equipment/Psus').catch(() => ({ Results: [] })),
          this.apiService.get('/equipment/FanModules').catch(() => ({ Results: [] })),
        ]);

        // Get thermal and power data from actual servers
        const thermalData = await this.apiService.get('/compute/PhysicalSummaries?$select=Moid,Name,Temperature').catch(() => ({ Results: [] }));
        const powerData = await this.apiService.get('/compute/PhysicalSummaries?$select=Moid,Name,AllocatedPower,PowerState').catch(() => ({ Results: [] }));
        
        // Get all servers for MOID-to-name resolution
        const allServers = await this.apiService.get('/compute/PhysicalSummaries?$select=Moid,Name,Model,Serial').catch(() => ({ Results: [] }));

        // Get top resources for performance analysis
        const topCpuServers = await this.apiService.get('/compute/PhysicalSummaries?$top=5&$orderby=CpuCapacity desc').catch(() => ({ Results: [] }));
        const topMemServers = await this.apiService.get('/compute/PhysicalSummaries?$top=5&$orderby=TotalMemory desc').catch(() => ({ Results: [] }));
        const topPowerServers = await this.apiService.get('/compute/PhysicalSummaries?$top=5&$orderby=AllocatedPower desc').catch(() => ({ Results: [] }));
        
        const topResources = [
          ...(topCpuServers?.Results || []).map((s: any) => ({ ...s, metric: 'cpu' })),
          ...(topMemServers?.Results || []).map((s: any) => ({ ...s, metric: 'memory' })),
          ...(topPowerServers?.Results || []).map((s: any) => ({ ...s, metric: 'power' }))
        ];

        // Build hardware health object from real data
        const hardwareData = {
          processors: processors?.Results || [],
          memory: memoryUnits?.Results || [],
          drives: physicalDrives?.Results || [],
          psus: psuUnits?.Results || [],
          fans: fanModules?.Results || [],
        };

        const thermalStats = {
          averageTemp: thermalData?.Results?.reduce((sum: number, s: any) => sum + (s.Temperature || 0), 0) / (thermalData?.Results?.length || 1),
          servers: thermalData?.Results || [],
        };

        const powerStats = {
          totalPower: powerData?.Results?.reduce((sum: number, s: any) => sum + (s.AllocatedPower || 0), 0),
          servers: powerData?.Results || [],
        };

        // Generate the comprehensive report with real Intersight data
        const report = createSecurityHealthCheckReport(
          alarms?.Results || [],
          advisories?.Results || [],
          advisoryInstances?.Results || [],
          advisoryCount,
          firmware?.Results || [],
          operatingSystems?.Results || [],
          hardwareData,
          thermalStats,
          powerStats,
          licenses?.Results || [],
          tpms?.Results || [],
          bootSecurity?.Results || [],
          policies?.Results || [],
          hyperflexCompat?.Results?.[0] || null,
          topResources,
          allServers?.Results || []
        );

        console.error('✅ Security & Health Check Report generated successfully');
        console.error('📊 Report includes:');
        console.error(`   - ${report.alarms.total} alarms analyzed (${report.alarms.critical} critical)`);
        console.error(`   - ${report.advisories.total} advisories reviewed (${report.advisories.fieldNotices} field notices, ${report.advisories.eolAdvisories} EOL)`);
        console.error(`   - ${report.firmware.components} firmware components checked`);
        console.error(`   - ${report.summary.infrastructureOverview.totalServers} servers assessed`);
        console.error(`   - All affected devices tracked and resolved by name`);
        return report;

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  }

  private async getPowerShellExamples(topic?: string): Promise<any> {
    const baseUrl = 'https://api.github.com/repos/CiscoDevNet/intersight-powershell/contents/examples';
    
    try {
      // Fetch the examples directory listing
      const response = await fetch(baseUrl, {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'Intersight-MCP-Server'
        }
      });

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.statusText}`);
      }

      const directories = await response.json();
      
      // Get all subdirectories
      const subdirs = directories.filter((item: any) => item.type === 'dir');
      
      if (!topic) {
        // Return list of available example categories
        return {
          message: 'Available PowerShell example categories for Cisco Intersight',
          count: subdirs.length,
          categories: subdirs.map((dir: any) => ({
            name: dir.name,
            url: dir.html_url,
            description: `Examples for ${dir.name} operations`
          })),
          usage: 'Specify a topic (category name) to see examples in that category'
        };
      }

      // Find matching subdirectory
      const matchingDir = subdirs.find((dir: any) => 
        dir.name.toLowerCase() === topic.toLowerCase() ||
        dir.name.toLowerCase().includes(topic.toLowerCase())
      );

      if (!matchingDir) {
        return {
          message: `No category found for topic: ${topic}`,
          suggestion: 'Use get_powershell_examples without a topic to see all available categories',
          availableCategories: subdirs.slice(0, 10).map((d: any) => d.name)
        };
      }

      // Fetch files in the matching directory
      const dirResponse = await fetch(matchingDir.url, {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'Intersight-MCP-Server'
        }
      });

      if (!dirResponse.ok) {
        throw new Error(`Failed to fetch directory: ${dirResponse.statusText}`);
      }

      const files = await dirResponse.json();
      const ps1Files = files.filter((file: any) => file.name.endsWith('.ps1'));

      if (ps1Files.length === 0) {
        return {
          message: `No PowerShell examples found in category: ${matchingDir.name}`,
          categoryUrl: matchingDir.html_url
        };
      }

      // Fetch content of all .ps1 files in this category
      const examples = await Promise.all(
        ps1Files.slice(0, 5).map(async (file: any) => {
          const contentResponse = await fetch(file.download_url);
          const content = await contentResponse.text();
          
          return {
            name: file.name,
            url: file.html_url,
            content: content,
            description: file.name.replace('.ps1', '').replace(/[_-]/g, ' ')
          };
        })
      );

      return {
        message: `Found ${ps1Files.length} PowerShell example(s) in category: ${matchingDir.name}`,
        category: matchingDir.name,
        categoryUrl: matchingDir.html_url,
        examplesShown: examples.length,
        totalExamples: ps1Files.length,
        examples: examples
      };
    } catch (error) {
      return {
        error: 'Failed to fetch PowerShell examples',
        details: error instanceof Error ? error.message : String(error)
      };
    }
  }

  private async getPythonExamples(topic?: string, source: string = 'all'): Promise<any> {
    const examplesUrl = 'https://api.github.com/repos/CiscoUcs/intersight-python/contents/examples';
    const utilsUrl = 'https://api.github.com/repos/CiscoDevNet/intersight-python-utils/contents';
    
    try {
      const results: any = {
        sources: [],
        examples: [],
        totalCount: 0
      };

      // Fetch from SDK examples repository
      if (source === 'examples' || source === 'all') {
        try {
          const response = await fetch(examplesUrl, {
            headers: {
              'Accept': 'application/vnd.github.v3+json',
              'User-Agent': 'Intersight-MCP-Server'
            }
          });

          if (response.ok) {
            const items = await response.json();
            const pyFiles = items.filter((item: any) => item.type === 'file' && item.name.endsWith('.py'));
            
            results.sources.push({
              name: 'SDK Examples',
              repository: 'CiscoUcs/intersight-python',
              url: 'https://github.com/CiscoUcs/intersight-python/tree/master/examples',
              count: pyFiles.length
            });

            if (!topic) {
              results.examples.push(...pyFiles.map((file: any) => ({
                source: 'SDK Examples',
                name: file.name,
                url: file.html_url,
                download_url: file.download_url,
                description: file.name.replace('.py', '').replace(/[_-]/g, ' ')
              })));
            } else {
              const matching = pyFiles.filter((file: any) => 
                file.name.toLowerCase().includes(topic.toLowerCase())
              );
              
              for (const file of matching.slice(0, 3)) {
                const contentResponse = await fetch(file.download_url);
                const content = await contentResponse.text();
                results.examples.push({
                  source: 'SDK Examples',
                  name: file.name,
                  url: file.html_url,
                  content: content,
                  description: file.name.replace('.py', '').replace(/[_-]/g, ' ')
                });
              }
            }
          }
        } catch (error) {
          console.error('Error fetching SDK examples:', error);
        }
      }

      // Fetch from Python utilities repository
      if (source === 'utils' || source === 'all') {
        try {
          const response = await fetch(utilsUrl, {
            headers: {
              'Accept': 'application/vnd.github.v3+json',
              'User-Agent': 'Intersight-MCP-Server'
            }
          });

          if (response.ok) {
            const items = await response.json();
            const pyFiles = items.filter((item: any) => item.type === 'file' && item.name.endsWith('.py'));
            
            results.sources.push({
              name: 'Python Utilities',
              repository: 'CiscoDevNet/intersight-python-utils',
              url: 'https://github.com/CiscoDevNet/intersight-python-utils',
              count: pyFiles.length
            });

            if (!topic) {
              results.examples.push(...pyFiles.map((file: any) => ({
                source: 'Python Utilities',
                name: file.name,
                url: file.html_url,
                download_url: file.download_url,
                description: file.name.replace('.py', '').replace(/[_-]/g, ' ')
              })));
            } else {
              const matching = pyFiles.filter((file: any) => 
                file.name.toLowerCase().includes(topic.toLowerCase())
              );
              
              for (const file of matching.slice(0, 3)) {
                const contentResponse = await fetch(file.download_url);
                const content = await contentResponse.text();
                results.examples.push({
                  source: 'Python Utilities',
                  name: file.name,
                  url: file.html_url,
                  content: content,
                  description: file.name.replace('.py', '').replace(/[_-]/g, ' ')
                });
              }
            }
          }
        } catch (error) {
          console.error('Error fetching Python utilities:', error);
        }
      }

      results.totalCount = results.examples.length;

      if (!topic) {
        return {
          message: 'Available Python examples and utilities for Cisco Intersight',
          sources: results.sources,
          totalExamples: results.totalCount,
          examples: results.examples,
          usage: 'Specify a topic keyword to search for specific examples, and optionally set source to "examples", "utils", or "all"'
        };
      }

      if (results.examples.length === 0) {
        return {
          message: `No Python examples found for topic: ${topic}`,
          searchedSources: results.sources,
          suggestion: 'Use get_python_examples without a topic to see all available examples',
          hint: 'Try keywords like: servers, policies, firmware, workflows, blade, rack, network, storage'
        };
      }

      return {
        message: `Found ${results.totalCount} Python example(s) for topic: ${topic}`,
        sources: results.sources,
        examplesShown: results.examples.length,
        examples: results.examples
      };
    } catch (error) {
      return {
        error: 'Failed to fetch Python examples',
        details: error instanceof Error ? error.message : String(error)
      };
    }
  }

  private async getTerraformExamples(resource?: string, source: string = 'all'): Promise<any> {
    try {
      const results: any = {
        sources: [],
        resources: [],
        modules: []
      };

      // Fetch from Terraform Registry documentation
      if (source === 'registry' || source === 'all') {
        const registryUrl = 'https://registry.terraform.io/v2/providers/5464';
        
        try {
          const response = await fetch(registryUrl, {
            headers: {
              'Accept': 'application/json',
              'User-Agent': 'Intersight-MCP-Server'
            }
          });

          if (response.ok) {
            const data = await response.json();
            
            results.sources.push({
              name: 'Terraform Registry',
              provider: 'CiscoDevNet/intersight',
              url: 'https://registry.terraform.io/providers/CiscoDevNet/intersight/latest/docs',
              version: data.data?.attributes?.version || 'latest'
            });

            // Registry data structure - add info about available resources
            results.registryInfo = {
              provider: 'intersight',
              namespace: 'CiscoDevNet',
              documentation: 'https://registry.terraform.io/providers/CiscoDevNet/intersight/latest/docs',
              resourcesUrl: 'https://registry.terraform.io/providers/CiscoDevNet/intersight/latest/docs/resources',
              dataSourcesUrl: 'https://registry.terraform.io/providers/CiscoDevNet/intersight/latest/docs/data-sources',
              guideUrl: 'https://registry.terraform.io/providers/CiscoDevNet/intersight/latest/docs/guides'
            };

            if (resource) {
              // Provide direct links to resource documentation
              const resourceName = resource.toLowerCase().replace(/^intersight_/, '');
              results.registryDocs = {
                resourceDoc: `https://registry.terraform.io/providers/CiscoDevNet/intersight/latest/docs/resources/${resourceName}`,
                dataSourceDoc: `https://registry.terraform.io/providers/CiscoDevNet/intersight/latest/docs/data-sources/${resourceName}`,
                message: `Visit the URLs above for detailed Terraform documentation on ${resource}`
              };
            }
          }
        } catch (error) {
          console.error('Error fetching Terraform Registry:', error);
        }
      }

      // Fetch from GitHub modules
      if (source === 'modules' || source === 'all') {
        const baseUrl = 'https://api.github.com/repos/CiscoDevNet/intersight-terraform-modules/contents';
        
        try {
          const response = await fetch(baseUrl, {
            headers: {
              'Accept': 'application/vnd.github.v3+json',
              'User-Agent': 'Intersight-MCP-Server'
            }
          });

          if (response.ok) {
            const items = await response.json();
            const modules = items.filter((item: any) => item.type === 'dir');
            
            results.sources.push({
              name: 'GitHub Terraform Modules',
              repository: 'CiscoDevNet/intersight-terraform-modules',
              url: 'https://github.com/CiscoDevNet/intersight-terraform-modules',
              moduleCount: modules.length
            });

            if (!resource) {
              results.modules = modules.map((mod: any) => ({
                name: mod.name,
                url: mod.html_url,
                description: `Terraform module for ${mod.name.replace(/-/g, ' ')}`
              }));
            } else {
              // Find matching module
              const matchingModule = modules.find((mod: any) => 
                mod.name.toLowerCase() === resource.toLowerCase() ||
                mod.name.toLowerCase().includes(resource.toLowerCase())
              );

              if (matchingModule) {
                const moduleResponse = await fetch(matchingModule.url, {
                  headers: {
                    'Accept': 'application/vnd.github.v3+json',
                    'User-Agent': 'Intersight-MCP-Server'
                  }
                });

                if (moduleResponse.ok) {
                  const moduleFiles = await moduleResponse.json();
                  const tfFiles = moduleFiles.filter((file: any) => 
                    file.type === 'file' && (file.name.endsWith('.tf') || file.name === 'README.md')
                  );

                  // Fetch content of main .tf files (limit to 3)
                  const mainFiles = await Promise.all(
                    tfFiles.slice(0, 3).map(async (file: any) => {
                      const contentResponse = await fetch(file.download_url);
                      const content = await contentResponse.text();
                      
                      return {
                        name: file.name,
                        url: file.html_url,
                        content: content,
                        type: file.name.endsWith('.md') ? 'documentation' : 'terraform'
                      };
                    })
                  );

                  results.moduleDetails = {
                    name: matchingModule.name,
                    url: matchingModule.html_url,
                    files: mainFiles
                  };
                }
              }
            }
          }
        } catch (error) {
          console.error('Error fetching GitHub modules:', error);
        }
      }

      // Build response
      if (!resource) {
        return {
          message: 'Cisco Intersight Terraform Resources and Modules',
          sources: results.sources,
          registryInfo: results.registryInfo,
          githubModules: results.modules,
          usage: 'Specify a resource name to get detailed documentation and examples. Use source parameter to filter: "registry", "modules", or "all"'
        };
      }

      return {
        message: `Terraform resources and modules for: ${resource}`,
        sources: results.sources,
        registryDocumentation: results.registryDocs,
        moduleDetails: results.moduleDetails,
        recommendation: 'Check both Registry documentation (for resource syntax) and GitHub modules (for complete examples)'
      };

    } catch (error) {
      return {
        error: 'Failed to fetch Terraform examples',
        details: error instanceof Error ? error.message : String(error)
      };
    }
  }

  private async getAnsibleExamples(resource?: string, source: string = 'all'): Promise<any> {
    try {
      const results: any = {
        sources: [],
        modules: [],
        playbooks: [],
        cvd: []
      };

      // Fetch Ansible modules
      if (source === 'modules' || source === 'all') {
        const modulesUrl = 'https://api.github.com/repos/CiscoDevNet/intersight-ansible/contents/plugins/modules';
        
        try {
          const response = await fetch(modulesUrl, {
            headers: {
              'Accept': 'application/vnd.github.v3+json',
              'User-Agent': 'Intersight-MCP-Server'
            }
          });

          if (response.ok) {
            const items = await response.json();
            const moduleFiles = items.filter((item: any) => 
              item.type === 'file' && item.name.endsWith('.py') && !item.name.startsWith('__')
            );
            
            results.sources.push({
              name: 'Ansible Modules',
              repository: 'CiscoDevNet/intersight-ansible',
              url: 'https://github.com/CiscoDevNet/intersight-ansible/tree/main/plugins/modules',
              count: moduleFiles.length
            });

            if (!resource) {
              results.modules = moduleFiles.map((file: any) => ({
                name: file.name.replace('.py', ''),
                url: file.html_url,
                description: `Ansible module for ${file.name.replace('.py', '').replace(/_/g, ' ')}`
              }));
            } else {
              const matching = moduleFiles.filter((file: any) => 
                file.name.toLowerCase().includes(resource.toLowerCase())
              );

              for (const file of matching.slice(0, 3)) {
                const contentResponse = await fetch(file.download_url);
                const content = await contentResponse.text();
                results.modules.push({
                  name: file.name.replace('.py', ''),
                  url: file.html_url,
                  content: content,
                  type: 'module'
                });
              }
            }
          }
        } catch (error) {
          console.error('Error fetching Ansible modules:', error);
        }
      }

      // Fetch Ansible playbooks
      if (source === 'playbooks' || source === 'all') {
        const playbooksUrl = 'https://api.github.com/repos/CiscoDevNet/intersight-ansible/contents/playbooks';
        
        try {
          const response = await fetch(playbooksUrl, {
            headers: {
              'Accept': 'application/vnd.github.v3+json',
              'User-Agent': 'Intersight-MCP-Server'
            }
          });

          if (response.ok) {
            const items = await response.json();
            const playbookFiles = items.filter((item: any) => 
              item.type === 'file' && (item.name.endsWith('.yml') || item.name.endsWith('.yaml'))
            );
            
            results.sources.push({
              name: 'Ansible Playbooks',
              repository: 'CiscoDevNet/intersight-ansible',
              url: 'https://github.com/CiscoDevNet/intersight-ansible/tree/main/playbooks',
              count: playbookFiles.length
            });

            if (!resource) {
              results.playbooks = playbookFiles.map((file: any) => ({
                name: file.name,
                url: file.html_url,
                description: `Example playbook: ${file.name.replace(/\.(yml|yaml)$/, '').replace(/[-_]/g, ' ')}`
              }));
            } else {
              const matching = playbookFiles.filter((file: any) => 
                file.name.toLowerCase().includes(resource.toLowerCase())
              );

              for (const file of matching.slice(0, 3)) {
                const contentResponse = await fetch(file.download_url);
                const content = await contentResponse.text();
                results.playbooks.push({
                  name: file.name,
                  url: file.html_url,
                  content: content,
                  type: 'playbook'
                });
              }
            }
          }
        } catch (error) {
          console.error('Error fetching Ansible playbooks:', error);
        }
      }

      // Fetch CVD FlashStack documentation
      if (source === 'cvd' || source === 'all') {
        const cvdUrl = 'https://api.github.com/repos/ucs-compute-solutions/CVD-FlashStack-IMM-VCF/contents';
        
        try {
          const response = await fetch(cvdUrl, {
            headers: {
              'Accept': 'application/vnd.github.v3+json',
              'User-Agent': 'Intersight-MCP-Server'
            }
          });

          if (response.ok) {
            const items = await response.json();
            
            results.sources.push({
              name: 'CVD FlashStack IMM Solutions',
              repository: 'ucs-compute-solutions/CVD-FlashStack-IMM-VCF',
              url: 'https://github.com/ucs-compute-solutions/CVD-FlashStack-IMM-VCF',
              description: 'Cisco Validated Design for FlashStack with Intersight Managed Mode'
            });

            // Get README and key files
            const readmeFile = items.find((item: any) => 
              item.type === 'file' && item.name.toLowerCase() === 'readme.md'
            );

            if (readmeFile && !resource) {
              const contentResponse = await fetch(readmeFile.download_url);
              const content = await contentResponse.text();
              results.cvd.push({
                name: 'README.md',
                url: readmeFile.html_url,
                content: content.substring(0, 1000) + '...',
                type: 'documentation'
              });
            }

            // List directories (likely contain different components)
            const dirs = items.filter((item: any) => item.type === 'dir');
            results.cvdStructure = dirs.map((dir: any) => ({
              name: dir.name,
              url: dir.html_url
            }));
          }
        } catch (error) {
          console.error('Error fetching CVD FlashStack:', error);
        }
      }

      // Build response
      if (!resource) {
        return {
          message: 'Cisco Intersight Ansible Automation Resources',
          sources: results.sources,
          ansibleModules: results.modules.length > 0 ? results.modules.slice(0, 20) : undefined,
          ansiblePlaybooks: results.playbooks.length > 0 ? results.playbooks.slice(0, 20) : undefined,
          cvdSolution: results.cvd.length > 0 ? results.cvd : undefined,
          cvdStructure: results.cvdStructure,
          usage: 'Specify a resource name to get detailed code examples. Use source parameter to filter: "modules", "playbooks", "cvd", or "all"'
        };
      }

      return {
        message: `Ansible automation resources for: ${resource}`,
        sources: results.sources,
        modules: results.modules.length > 0 ? results.modules : undefined,
        playbooks: results.playbooks.length > 0 ? results.playbooks : undefined,
        cvdInfo: results.cvd.length > 0 ? results.cvd : undefined,
        recommendation: 'Check modules for automation tasks, playbooks for complete workflows, and CVD for validated solution architectures'
      };

    } catch (error) {
      return {
        error: 'Failed to fetch Ansible examples',
        details: error instanceof Error ? error.message : String(error)
      };
    }
  }

  async run(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Intersight MCP Server running on stdio');
  }
}