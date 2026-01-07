# PowerShell Tool Implementation Plan

## Overview

This document outlines the implementation plan for creating a PowerShell tool for OpenCode, similar to the existing bash tool. The PowerShell tool will enable executing PowerShell commands with the same safety, parsing, and permission features as the bash tool.

## Architecture Analysis

### Existing Bash Tool Components

The current bash tool (`packages/opencode/src/tool/bash.ts`) consists of:

1. **Parameter Validation**: Zod schema for command, timeout, workdir, description
2. **Shell Detection**: `Shell.acceptable()` for shell selection
3. **AST Parsing**: Tree-sitter for bash command parsing and safety analysis
4. **Permission System**: Directory access and command pattern permissions
5. **Process Management**: Child process spawning with timeout and abort handling
6. **Output Streaming**: Real-time output capture with length limits
7. **Metadata Tracking**: Command execution metadata and status

### PowerShell-Specific Requirements

PowerShell differs from bash in several key areas:

- **Syntax**: PowerShell uses cmdlets, pipelines, and object-oriented commands
- **Security**: ExecutionPolicy, ConstrainedLanguage mode, script signing
- **Path Handling**: Native Windows paths with different normalization
- **Process Model**: Different process spawning and job management
- **Command Discovery**: Get-Command vs bash `which`

## Implementation Plan

### Phase 1: Core Infrastructure

#### 1.1 Create PowerShell Tool File
```typescript
// packages/opencode/src/tool/powershell.ts
import z from "zod"
import { spawn } from "child_process"
import { Tool } from "./tool"
import DESCRIPTION from "./powershell.txt"
import { Log } from "../util/log"
import { Instance } from "../project/instance"
import { lazy } from "@/util/lazy"

export const log = Log.create({ service: "powershell-tool" })
```

#### 1.2 PowerShell Detection and Validation
```typescript
const detectPowerShell = () => {
  // Check for pwsh (PowerShell 7+) first, then powershell.exe
  // Validate execution policy allows script execution
  // Return preferred PowerShell executable path
}
```

#### 1.3 Parameter Schema
```typescript
parameters: z.object({
  command: z.string().describe("The PowerShell command to execute"),
  timeout: z.number().describe("Optional timeout in milliseconds").optional(),
  workdir: z.string().describe("Working directory").optional(),
  executionPolicy: z.enum(["Restricted", "AllSigned", "RemoteSigned", "Unrestricted", "Bypass"])
    .describe("PowerShell execution policy").optional(),
  description: z.string().describe("Command description (5-10 words)")
})
```

### Phase 2: Command Parsing and Safety

#### 2.1 AST Parsing for PowerShell
```typescript
// Use PowerShell AST or create custom parser for:
// - Cmdlet detection
// - Pipeline analysis
// - Path resolution
// - Dangerous command identification
const parsePowerShellCommand = (command: string) => {
  // Parse PowerShell syntax
  // Identify file system operations
  // Detect potentially dangerous cmdlets
  // Extract path references
}
```

#### 2.2 Permission Analysis
```typescript
// Adapt bash permission logic for PowerShell:
// - Convert Unix paths to Windows paths
// - Handle PowerShell drive notation (C:, HKLM:, etc.)
// - Identify cmdlets that access external resources
// - Check for script execution permissions
```

#### 2.3 Path Resolution
```typescript
// PowerShell-specific path handling:
// - Resolve PSDrives (C:, Env:, etc.)
// - Handle UNC paths (\\server\share)
// - Convert between Unix and Windows path formats
// - Validate path containment within project directory
```

### Phase 3: Execution Engine

#### 3.1 Process Spawning
```typescript
const executePowerShellCommand = async (params) => {
  const pwshPath = await detectPowerShell()
  const executionPolicy = params.executionPolicy || "RemoteSigned"

  const proc = spawn(pwshPath, [
    "-Command", params.command,
    "-ExecutionPolicy", executionPolicy,
    "-NoProfile",  // Prevent profile loading for security
    "-NonInteractive"  // Ensure non-interactive execution
  ], {
    cwd: params.workdir || Instance.directory,
    env: {
      ...process.env,
      // Set PowerShell-specific environment variables
    },
    stdio: ["ignore", "pipe", "pipe"]
  })

  return proc
}
```

#### 3.2 Output Handling
```typescript
// Handle PowerShell-specific output:
// - Object serialization (ConvertTo-Json)
// - Structured output vs text output
// - Error stream handling
// - Progress indicators
// - Verbose/Debug output streams
```

#### 3.3 Timeout and Abort Handling
```typescript
// Adapt existing timeout logic for PowerShell:
// - Handle PowerShell job management
// - Clean up PowerShell runspaces
// - Terminate background jobs
// - Handle pipeline termination
```

### Phase 4: PowerShell-Specific Features

#### 4.1 Cmdlet Discovery and Validation
```typescript
// Implement cmdlet validation:
// - Check if cmdlets exist (Get-Command equivalent)
// - Validate parameter sets
// - Handle cmdlet aliases
// - Detect potentially dangerous cmdlets
const DANGEROUS_CMDLETS = [
  "Remove-Item", "Stop-Process", "Set-Service",
  "New-ADUser", "Remove-ADUser", "Restart-Computer"
]
```

#### 4.2 Module Loading
```typescript
// Handle PowerShell module requirements:
// - Detect required modules in commands
// - Check module availability
// - Handle module loading errors
// - Support for common modules (ActiveDirectory, etc.)
```

#### 4.3 Execution Policy Management
```typescript
// Manage execution policies per command:
// - Temporary policy changes for specific commands
// - Scope execution policy to current process
// - Validate policy compatibility
// - Handle signed script requirements
```

### Phase 5: Integration and Testing

#### 5.1 Tool Registration
```typescript
export const PowerShellTool = Tool.define("powershell", async () => {
  const pwshPath = await detectPowerShell()
  log.info("PowerShell tool initialized", { path: pwshPath })

  return {
    description: DESCRIPTION.replaceAll("${directory}", Instance.directory),
    parameters: powershellParameters,
    execute: executePowerShellCommand
  }
})
```

#### 5.2 Permission Integration
```typescript
// Integrate with existing permission system:
// - Map PowerShell paths to permission patterns
// - Handle PSDrive permissions
// - Cmdlet-specific permissions
// - Module loading permissions
```

#### 5.3 Error Handling
```typescript
// PowerShell-specific error handling:
// - Parse PowerShell error records
// - Handle terminating vs non-terminating errors
// - Extract error details and stack traces
// - Map PowerShell errors to tool errors
```

### Phase 6: Documentation and Examples

#### 6.1 Tool Description
```txt
# powershell.txt
Execute PowerShell commands with safety and permission controls.

Available in directory: ${directory}

Supports:
- Cmdlet execution
- Pipeline operations
- Script execution (with execution policy management)
- Module loading
- Object serialization

Security features:
- Command AST analysis
- Path containment validation
- Execution policy control
- Dangerous cmdlet detection
```

#### 6.2 Usage Examples
```typescript
// Basic command execution
powershell({
  command: 'Get-ChildItem -Path . -Name',
  description: 'Lists files in current directory'
})

// With custom execution policy
powershell({
  command: 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process; .\\script.ps1',
  executionPolicy: 'Bypass',
  description: 'Runs PowerShell script with custom policy'
})

// Pipeline operations
powershell({
  command: 'Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object Name, CPU',
  description: 'Finds high-CPU processes'
})
```

## Implementation Timeline

### Week 1: Core Infrastructure
- Create powershell.ts file
- Implement PowerShell detection
- Set up parameter validation
- Basic command execution

### Week 2: Safety and Parsing
- Implement AST parsing for PowerShell
- Add permission checking
- Path resolution and validation
- Dangerous cmdlet detection

### Week 3: Advanced Features
- Execution policy management
- Module loading support
- Error handling improvements
- Output formatting

### Week 4: Integration and Testing
- Permission system integration
- Comprehensive testing
- Documentation
- Performance optimization

## Risk Assessment

### High Risk
- **Path Handling**: PowerShell/Windows path complexity
- **Security Model**: ExecutionPolicy and script signing
- **Process Management**: PowerShell job and runspace cleanup

### Medium Risk
- **AST Parsing**: PowerShell syntax complexity
- **Module Loading**: Dependency management
- **Cross-Platform**: Windows-specific features

### Low Risk
- **Basic Execution**: Similar to bash tool
- **Output Handling**: Standard stream processing
- **Timeout Management**: Existing patterns

## Success Criteria

1. **Functionality**: Execute PowerShell commands safely
2. **Security**: Prevent unauthorized operations
3. **Performance**: Comparable to bash tool performance
4. **Compatibility**: Work on Windows with PowerShell 5.1+ and 7+
5. **Integration**: Seamless permission and metadata integration

## Testing Strategy

### Unit Tests
- PowerShell detection and validation
- Command parsing and AST analysis
- Path resolution and permission checking
- Execution policy handling

### Integration Tests
- End-to-end command execution
- Permission system integration
- Error handling and recovery
- Cross-version compatibility (PS 5.1, 7.x)

### Security Tests
- Dangerous cmdlet detection
- Path traversal prevention
- Execution policy enforcement
- Module loading validation

## Dependencies

- **tree-sitter**: For PowerShell AST parsing (if available)
- **PowerShell SDK**: For advanced PowerShell integration
- **Existing OpenCode infrastructure**: Tool framework, permissions, logging

## Alternative Approaches

### Option A: PowerShell Remoting
- Use PowerShell remoting for execution
- Better isolation but more complex setup

### Option B: .NET Integration
- Use System.Management.Automation namespace
- Tighter integration but Windows-only

### Option C: Hybrid Approach
- Use process spawning for simple commands
- PowerShell remoting for complex operations

## Conclusion

The PowerShell tool implementation will provide OpenCode users with safe, controlled access to PowerShell functionality while maintaining the same security and permission model as the existing bash tool. The phased approach ensures incremental development with proper testing and validation at each stage.</content>
<parameter name="filePath">C:\Users\mchan\projects\windows_terminal\POWERSHELL_TOOL_IMPLEMENTATION_PLAN.md