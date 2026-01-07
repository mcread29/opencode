import z from "zod"
import { spawn } from "child_process"
import { Tool } from "./tool"
import DESCRIPTION from "./powershell.txt"
import { Log } from "../util/log"
import { Instance } from "../project/instance"
import { lazy } from "@/util/lazy"
import { $ } from "bun"
import { Filesystem } from "@/util/filesystem"
import { Flag } from "@/flag/flag.ts"
import path from "path"

const MAX_OUTPUT_LENGTH = Flag.OPENCODE_EXPERIMENTAL_BASH_MAX_OUTPUT_LENGTH || 30_000
const DEFAULT_TIMEOUT = Flag.OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS || 2 * 60 * 1000
const SIGKILL_TIMEOUT_MS = 200

export const log = Log.create({ service: "powershell-tool" })

// PowerShell execution policies
const EXECUTION_POLICIES = ["Restricted", "AllSigned", "RemoteSigned", "Unrestricted", "Bypass"] as const

// Dangerous PowerShell cmdlets that require explicit permission
const DANGEROUS_CMDLETS = [
  "Remove-Item",
  "Stop-Process",
  "Set-Service",
  "New-ADUser",
  "Remove-ADUser",
  "Restart-Computer",
  "Stop-Computer",
  "Set-ExecutionPolicy",
  "Invoke-Expression",
  "Start-Process",
  "New-Item",
  "Remove-ItemProperty",
  "Clear-Content",
  "Clear-Item",
  "Clear-ItemProperty",
  "Copy-Item",
  "Move-Item",
  "Rename-Item",
  "Set-Content",
  "Set-Item",
  "Set-ItemProperty",
]

// PowerShell drive mappings for path resolution
const PSDRIVES = {
  "C:": "C:\\",
  "D:": "D:\\",
  "E:": "E:\\",
  "F:": "F:\\",
  "G:": "G:\\",
  "H:": "H:\\",
  "Env:": "Environment",
  "HKLM:": "HKEY_LOCAL_MACHINE",
  "HKCU:": "HKEY_CURRENT_USER",
  "HKCR:": "HKEY_CLASSES_ROOT",
  "HKU:": "HKEY_USERS",
  "HKCC:": "HKEY_CURRENT_CONFIG",
}

// Detect available PowerShell executable
const detectPowerShell = async (): Promise<string> => {
  // Prefer pwsh (PowerShell 7+) over powershell.exe
  const pwsh = Bun.which("pwsh")
  if (pwsh) {
    log.info("Detected PowerShell 7+", { path: pwsh })
    return pwsh
  }

  // Fall back to Windows PowerShell
  const powershell = Bun.which("powershell")
  if (powershell) {
    log.info("Detected Windows PowerShell", { path: powershell })
    return powershell
  }

  // Check common installation paths
  const commonPaths = [
    "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
  ]

  for (const testPath of commonPaths) {
    try {
      await Bun.file(testPath).exists()
      log.info("Found PowerShell at common path", { path: testPath })
      return testPath
    } catch {
      // Continue checking other paths
    }
  }

  throw new Error("PowerShell executable not found. Please ensure PowerShell is installed.")
}

// Validate execution policy
const validateExecutionPolicy = (policy?: string): string => {
  if (!policy) return "RemoteSigned"

  if (!EXECUTION_POLICIES.includes(policy as any)) {
    throw new Error(`Invalid execution policy: ${policy}. Valid policies: ${EXECUTION_POLICIES.join(", ")}`)
  }

  return policy
}

// Parse PowerShell command for safety analysis
const parsePowerShellCommand = (command: string) => {
  // Basic PowerShell command parsing
  // This is a simplified parser - a full AST parser would be more robust
  const cmdlets: string[] = []
  const paths: string[] = []

  // Extract cmdlets (basic pattern matching)
  const cmdletMatches = command.match(/\b[A-Z][a-zA-Z0-9-]*-[A-Z][a-zA-Z0-9-]*\b/g)
  if (cmdletMatches) {
    cmdlets.push(...cmdletMatches)
  }

  // Extract paths (basic pattern matching for file paths and PSDrives)
  const pathMatches = command.match(
    /['"]?([A-Za-z]:[^\s'"]*|\\\\[^\\]+\\[^\s'"]*|Env:[^\s'"]*|HKLM:[^\s'"]*|HKCU:[^\s'"]*)['"]?/g,
  )
  if (pathMatches) {
    paths.push(...pathMatches.map((p) => p.replace(/['"]/g, "")))
  }

  return { cmdlets, paths }
}

// Resolve PowerShell paths to absolute paths
const resolvePowerShellPath = (psPath: string): string => {
  // Handle PSDrives
  for (const [psDrive, systemPath] of Object.entries(PSDRIVES)) {
    if (psPath.startsWith(psDrive)) {
      if (psDrive.endsWith(":")) {
        // File system drive
        return psPath.replace(psDrive, systemPath)
      } else {
        // Registry or environment - return as-is for now
        return psPath
      }
    }
  }

  // Handle UNC paths
  if (psPath.startsWith("\\\\")) {
    return psPath
  }

  // Handle relative paths
  if (!path.isAbsolute(psPath)) {
    return path.resolve(Instance.directory, psPath)
  }

  return psPath
}

// Check if cmdlet is dangerous
const isDangerousCmdlet = (cmdlet: string): boolean => {
  return DANGEROUS_CMDLETS.some((dangerous) => cmdlet.toLowerCase() === dangerous.toLowerCase())
}

// Execute PowerShell command
const executePowerShellCommand = async (
  params: {
    command: string
    timeout?: number
    workdir?: string
    executionPolicy?: string
    description: string
  },
  ctx: any,
) => {
  const pwshPath = await detectPowerShell()
  const executionPolicy = validateExecutionPolicy(params.executionPolicy)
  const cwd = params.workdir || Instance.directory
  const timeout = params.timeout ?? DEFAULT_TIMEOUT

  if (params.timeout !== undefined && params.timeout < 0) {
    throw new Error(`Invalid timeout value: ${params.timeout}. Timeout must be a positive number.`)
  }

  // Parse command for safety analysis
  const { cmdlets, paths } = parsePowerShellCommand(params.command)

  // Check external directory access
  const checkExternalDirectory = async (dir: string) => {
    if (Filesystem.contains(Instance.directory, dir)) return

    await ctx.ask({
      permission: "external_directory",
      patterns: [dir, path.join(dir, "*")],
      always: [path.dirname(dir) + "*"],
      metadata: {
        command: params.command,
      },
    })
  }

  // Check working directory
  await checkExternalDirectory(cwd)

  // Check paths referenced in command
  for (const psPath of paths) {
    const resolvedPath = resolvePowerShellPath(psPath)
    if (resolvedPath !== psPath) {
      // Only check if it was actually resolved
      await checkExternalDirectory(resolvedPath)
    }
  }

  // Check cmdlet permissions - ask for dangerous cmdlets
  const askPatterns = new Set<string>()
  for (const cmdlet of cmdlets) {
    if (isDangerousCmdlet(cmdlet)) {
      askPatterns.add(cmdlet + "*")
    }
  }

  if (askPatterns.size > 0) {
    await ctx.ask({
      permission: "powershell",
      patterns: Array.from(askPatterns),
      always: Array.from(askPatterns),
      metadata: {
        command: params.command,
      },
    })
  }

  // Spawn PowerShell process
  const proc = spawn(
    pwshPath,
    [
      "-Command",
      params.command,
      "-ExecutionPolicy",
      executionPolicy,
      "-NoProfile", // Prevent profile loading for security
      "-NonInteractive", // Ensure non-interactive execution
    ],
    {
      cwd,
      env: {
        ...process.env,
        // Set PowerShell-specific environment variables if needed
      },
      stdio: ["ignore", "pipe", "pipe"],
      detached: process.platform !== "win32",
    },
  )

  let output = ""

  // Initialize metadata with empty output
  ctx.metadata({
    metadata: {
      output: "",
      description: params.description,
    },
  })

  const append = (chunk: Buffer) => {
    if (output.length <= MAX_OUTPUT_LENGTH) {
      output += chunk.toString()
      ctx.metadata({
        metadata: {
          output,
          description: params.description,
        },
      })
    }
  }

  proc.stdout?.on("data", append)
  proc.stderr?.on("data", append)

  let timedOut = false
  let aborted = false
  let exited = false

  const killTree = async () => {
    const pid = proc.pid
    if (!pid || exited) {
      return
    }

    if (process.platform === "win32") {
      await new Promise<void>((resolve) => {
        const killer = spawn("taskkill", ["/pid", String(pid), "/f", "/t"], { stdio: "ignore" })
        killer.once("exit", resolve)
        killer.once("error", resolve)
      })
      return
    }

    try {
      process.kill(-pid, "SIGTERM")
      await Bun.sleep(SIGKILL_TIMEOUT_MS)
      if (!exited) {
        process.kill(-pid, "SIGKILL")
      }
    } catch (_e) {
      proc.kill("SIGTERM")
      await Bun.sleep(SIGKILL_TIMEOUT_MS)
      if (!exited) {
        proc.kill("SIGKILL")
      }
    }
  }

  if (ctx.abort.aborted) {
    aborted = true
    await killTree()
  }

  const abortHandler = () => {
    aborted = true
    void killTree()
  }

  ctx.abort.addEventListener("abort", abortHandler, { once: true })

  const timeoutTimer = setTimeout(() => {
    timedOut = true
    void killTree()
  }, timeout + 100)

  await new Promise<void>((resolve, reject) => {
    const cleanup = () => {
      clearTimeout(timeoutTimer)
      ctx.abort.removeEventListener("abort", abortHandler)
    }

    proc.once("exit", () => {
      exited = true
      cleanup()
      resolve()
    })

    proc.once("error", (error) => {
      exited = true
      cleanup()
      reject(error)
    })
  })

  let resultMetadata: String[] = ["<powershell_metadata>"]

  if (output.length > MAX_OUTPUT_LENGTH) {
    output = output.slice(0, MAX_OUTPUT_LENGTH)
    resultMetadata.push(`powershell tool truncated output as it exceeded ${MAX_OUTPUT_LENGTH} char limit`)
  }

  if (timedOut) {
    resultMetadata.push(`powershell tool terminated command after exceeding timeout ${timeout} ms`)
  }

  if (aborted) {
    resultMetadata.push("User aborted the command")
  }

  if (resultMetadata.length > 1) {
    resultMetadata.push("</powershell_metadata>")
    output += "\n\n" + resultMetadata.join("\n")
  }

  return {
    title: params.description,
    metadata: {
      output,
      exit: proc.exitCode,
      description: params.description,
    },
    output,
  }
}

export const PowerShellTool = Tool.define("powershell", async () => {
  const pwshPath = await detectPowerShell()
  log.info("PowerShell tool initialized", { path: pwshPath })

  return {
    description: DESCRIPTION.replaceAll("${directory}", Instance.directory),
    parameters: z.object({
      command: z.string().describe("The PowerShell command to execute"),
      timeout: z.number().describe("Optional timeout in milliseconds").optional(),
      workdir: z
        .string()
        .describe(
          `The working directory to run the command in. Defaults to ${Instance.directory}. Use this instead of 'cd' commands.`,
        )
        .optional(),
      executionPolicy: z
        .enum(EXECUTION_POLICIES)
        .describe("PowerShell execution policy. Defaults to RemoteSigned.")
        .optional(),
      description: z
        .string()
        .describe(
          "Clear, concise description of what this command does in 5-10 words. Examples:\nInput: Get-ChildItem\nOutput: Lists files in current directory\n\nInput: Get-Process\nOutput: Shows running processes\n\nInput: Get-Service\nOutput: Lists Windows services\n\nInput: New-Item\nOutput: Creates new file or directory",
        ),
    }),
    execute: executePowerShellCommand,
  }
})
