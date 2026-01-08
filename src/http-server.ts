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

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { IntersightApiService } from './services/intersightApi.js';
import { loadConfig, loadMCPServerConfig, isToolEnabled, getEnabledTools, MCPServerConfig } from './utils/config.js';
import { IntersightMCPServer } from './server.js';

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Initialize API Service and MCP Configuration
let apiService: IntersightApiService;
let mcpConfig: MCPServerConfig;
let mcpServer: IntersightMCPServer;
let allTools: Tool[];
let enabledTools: Tool[];

try {
  const config = loadConfig();
  mcpConfig = loadMCPServerConfig();
  apiService = new IntersightApiService(config);
  mcpServer = new IntersightMCPServer();
  
  // Get tools from the MCP server instance
  allTools = (mcpServer as any).getAllTools();
  enabledTools = getEnabledTools(allTools, mcpConfig);
  
  console.log('✅ Intersight API Service initialized successfully');
  console.log(`🔧 Configuration: ${mcpConfig.serverConfig.toolSelectionMode} mode`);
  console.log(`🛠️  Tools: ${enabledTools.length} of ${allTools.length} enabled`);
} catch (error) {
  console.error('❌ Failed to initialize API Service:', error);
  process.exit(1);
}

// Tool execution function (uses the MCP server's handleToolCall)
async function executeTool(name: string, args: Record<string, any>): Promise<any> {
  // Security check: verify tool is enabled
  const allToolNames = allTools.map(t => t.name);
  if (!isToolEnabled(name, mcpConfig, allToolNames)) {
    throw new Error(`Tool '${name}' is not enabled in current configuration. Use INTERSIGHT_TOOL_MODE=all to enable all tools.`);
  }

  // Use the MCP server's tool execution logic
  return (mcpServer as any).handleToolCall(name, args);
}

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.16',
    configuration: {
      toolMode: mcpConfig.serverConfig.toolSelectionMode,
      enabledTools: enabledTools.length,
      totalTools: allTools.length,
      enableAllTools: mcpConfig.serverConfig.enableAllTools
    },
    description: 'Intersight MCP HTTP Server - v1.0.16 with Tool Configuration'
  });
});

// API info endpoint
app.get('/api/info', (req: Request, res: Response) => {
  res.json({
    name: 'Intersight MCP Server',
    version: '1.0.16',
    description: 'HTTP API for Cisco Intersight MCP tools with configurable tool modes',
    configuration: {
      toolMode: mcpConfig.serverConfig.toolSelectionMode,
      enabledTools: enabledTools.length,
      totalTools: allTools.length,
      toolModeEnv: process.env.INTERSIGHT_TOOL_MODE || 'core (default)'
    },
    endpoints: {
      health: '/health',
      tools: '/api/tools',
      execute: '/api/execute',
      search: '/api/tools/search',
      batch: '/api/batch',
      config: '/api/config'
    },
    documentation: 'https://github.com/jim-coyne/Intersight_MCP'
  });
});

// Configuration endpoint
app.get('/api/config', (req: Request, res: Response) => {
  res.json({
    success: true,
    configuration: {
      serverName: mcpConfig.serverConfig.name,
      toolSelectionMode: mcpConfig.serverConfig.toolSelectionMode,
      enableAllTools: mcpConfig.serverConfig.enableAllTools,
      serverProfileFocus: mcpConfig.serverConfig.serverProfileFocus,
      enabledToolsCount: enabledTools.length,
      totalToolsCount: allTools.length,
      environmentVariable: process.env.INTERSIGHT_TOOL_MODE || 'not set (using default: core)'
    },
    instructions: {
      coreMode: 'Set INTERSIGHT_TOOL_MODE=core for 65 safe, read-only tools',
      allMode: 'Set INTERSIGHT_TOOL_MODE=all for 199+ tools with full CRUD capabilities'
    }
  });
});

// List available tools
app.get('/api/tools', async (req: Request, res: Response) => {
  try {
    res.json({
      success: true,
      configuration: {
        toolMode: mcpConfig.serverConfig.toolSelectionMode,
        enabledTools: enabledTools.length,
        totalTools: allTools.length
      },
      tools: enabledTools.map((tool: Tool) => ({
        name: tool.name,
        description: tool.description,
        parameters: tool.inputSchema?.properties || {}
      }))
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve tools',
      message: error instanceof Error ? error.message : String(error)
    });
  }
});

// Execute a tool
app.post('/api/execute', async (req: Request, res: Response) => {
  try {
    const { tool, parameters = {} } = req.body;
    
    if (!tool) {
      return res.status(400).json({
        success: false,
        error: 'Tool name is required',
        usage: 'POST /api/execute with { "tool": "tool_name", "parameters": {...} }'
      });
    }

    // Check if tool exists in enabled tools
    const toolExists = enabledTools.some((t: Tool) => t.name === tool);
    if (!toolExists) {
      return res.status(400).json({
        success: false,
        error: `Tool not available: ${tool}`,
        message: `Tool '${tool}' is not enabled in current configuration (${mcpConfig.serverConfig.toolSelectionMode} mode)`,
        availableTools: enabledTools.map((t: Tool) => t.name),
        hint: 'Use INTERSIGHT_TOOL_MODE=all to enable all tools'
      });
    }

    // Execute the tool
    const result = await executeTool(tool, parameters);
    
    res.json({
      success: true,
      tool: tool,
      parameters: parameters,
      result: result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Tool execution failed',
      message: error instanceof Error ? error.message : String(error),
      timestamp: new Date().toISOString()
    });
  }
});

// Batch tool execution
app.post('/api/batch', async (req: Request, res: Response) => {
  try {
    const { operations } = req.body;
    
    if (!Array.isArray(operations)) {
      return res.status(400).json({
        success: false,
        error: 'Operations must be an array',
        usage: 'POST /api/batch with { "operations": [{"tool": "tool_name", "parameters": {...}}, ...] }'
      });
    }

    const results = [];
    
    for (const operation of operations) {
      try {
        const result = await executeTool(operation.tool, operation.parameters || {});
        results.push({
          success: true,
          tool: operation.tool,
          result: result
        });
      } catch (error) {
        results.push({
          success: false,
          tool: operation.tool,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }

    res.json({
      success: true,
      totalOperations: operations.length,
      results: results,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Batch execution failed',
      message: error instanceof Error ? error.message : String(error)
    });
  }
});

// Search tools by name or description
app.get('/api/tools/search', (req: Request, res: Response) => {
  try {
    const { query } = req.query;
    
    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'Search query is required',
        usage: 'GET /api/tools/search?query=search_term'
      });
    }

    const searchTerm = (query as string).toLowerCase();
    
    const matchingTools = enabledTools.filter((tool: Tool) => 
      tool.name.toLowerCase().includes(searchTerm) ||
      (tool.description && tool.description.toLowerCase().includes(searchTerm))
    );

    res.json({
      success: true,
      query: query,
      totalMatches: matchingTools.length,
      tools: matchingTools.map((tool: Tool) => ({
        name: tool.name,
        description: tool.description,
        parameters: tool.inputSchema?.properties || {}
      }))
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Search failed',
      message: error instanceof Error ? error.message : String(error)
    });
  }
});

// Get tool details
app.get('/api/tools/:toolName', (req: Request, res: Response) => {
  try {
    const { toolName } = req.params;
    const tool = enabledTools.find((t: Tool) => t.name === toolName);
    
    if (!tool) {
      return res.status(404).json({
        success: false,
        error: `Tool not found: ${toolName}`,
        availableTools: enabledTools.map((t: Tool) => t.name)
      });
    }

    res.json({
      success: true,
      tool: {
        name: tool.name,
        description: tool.description,
        parameters: tool.inputSchema?.properties || {},
        required: tool.inputSchema?.required || []
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve tool details',
      message: error instanceof Error ? error.message : String(error)
    });
  }
});

// Error handling middleware
app.use((error: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Express error:', error);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: error.message
  });
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    availableEndpoints: [
      'GET /health',
      'GET /api/info', 
      'GET /api/tools',
      'GET /api/tools/:toolName',
      'GET /api/tools/search?query=term',
      'POST /api/execute',
      'POST /api/batch'
    ]
  });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Intersight MCP HTTP Server v1.0.15 running on port ${port}`);
  console.log(`🔧 Configuration Mode: ${mcpConfig.serverConfig.toolSelectionMode.toUpperCase()}`);
  console.log(`⚡ Enabled Tools: ${enabledTools.length} tools available`);
  console.log('');
  console.log(`� Health check: http://localhost:${port}/health`);
  console.log(`🔧 API info: http://localhost:${port}/api/info`);
  console.log(`🛠️  Tools list: http://localhost:${port}/api/tools`);
  console.log(`🔍 Search tools: http://localhost:${port}/api/tools/search?query=server`);
  console.log(`⚙️  Execute tool: POST http://localhost:${port}/api/execute`);
  console.log('');
  console.log(`💡 To enable all tools, set: INTERSIGHT_TOOL_MODE=all`);
  console.log(`💡 To use core tools only, set: INTERSIGHT_TOOL_MODE=core`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('📝 SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('📝 SIGINT received, shutting down gracefully');
  process.exit(0);
});