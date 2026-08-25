// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/**
 * Shared, shell-free child-process launcher.
 *
 * Every `az` / `azd` / dev-server invocation in this codebase goes through this
 * module so process spawning is centralised on ONE hardened seam:
 *
 *  - We NEVER pass `shell: true` or compose a command string. `cross-spawn`
 *    handles Windows `.cmd`/`.bat` shims while escaping each discrete argv
 *    element; callers cannot opt into general shell-string interpretation.
 *  - Before applying a caller-selected working directory, we resolve the tool
 *    from absolute host PATH entries and pass its verified absolute path. This
 *    prevents Windows lookup from preferring a same-named project-local shim.
 *  - Centralising here also gives tests a single module to mock
 *    (`vi.mock("../proc-exec.js", …)`) instead of stubbing `node:child_process`.
 *
 * The error shape mirrors Node's `execFile` rejection (`.stdout` / `.stderr` /
 * `.code`, with stderr appended to `.message`) so existing error classifiers
 * keep working unchanged.
 */

import type { ChildProcess, SpawnOptions } from "node:child_process";
import { fileURLToPath } from "node:url";
import spawn from "cross-spawn";
import { resolveExecutablePath } from "./executable-resolver.js";

export interface RunCommandOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  /** Kill the child and reject once this many milliseconds have elapsed. */
  timeout?: number;
}

export interface RunCommandResult {
  stdout: string;
  stderr: string;
}

/**
 * Error thrown by {@link runCommand} when the child exits non-zero, cannot be
 * spawned, or times out. Shaped like Node's `execFile` rejection so callers that
 * read `.stdout` / `.stderr` / `.code` or match `.message` keep working.
 */
export interface RunCommandError extends Error {
  stdout: string;
  stderr: string;
  code?: number | string;
}

/**
 * Run a command to completion and buffer its output. Never enables shell mode;
 * each argument remains a discrete argv element.
 */
export function runCommand(
  command: string,
  args: readonly string[] = [],
  options: RunCommandOptions = {},
): Promise<RunCommandResult> {
  return new Promise<RunCommandResult>((resolvePromise, reject) => {
    let stdout = "";
    let stderr = "";

    // shell:false is the entire point: callers provide discrete argv elements,
    // never a shell command string.
    let child: ChildProcess;
    try {
      const executable = options.cwd !== undefined
        ? resolveExecutablePath(command, { cwd: options.cwd, env: options.env })
        : command;
      child = spawn(executable, [...args], {
        cwd: options.cwd,
        env: options.env,
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      // Argument/options validation can throw before a ChildProcess exists.
      // Normalize that path to the same shape as asynchronous spawn failures.
      const e =
        err instanceof Error
          ? (err as RunCommandError)
          : (new Error(String(err)) as RunCommandError);
      e.stdout = stdout;
      e.stderr = stderr;
      reject(e);
      return;
    }

    let settled = false;
    let timer: NodeJS.Timeout | undefined;

    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      fn();
    };

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    child.on("error", (err: NodeJS.ErrnoException) => {
      // Spawn failures land here — notably ENOENT for a missing command.
      // Preserve the original message text (callers match "ENOENT" / "not
      // recognized") and surface `.code` so `e.code === "ENOENT"` checks work.
      finish(() => {
        const e = err as RunCommandError;
        e.stdout = stdout;
        e.stderr = stderr;
        if (err.code !== undefined) e.code = err.code;
        reject(e);
      });
    });

    child.on("close", (exitCode) => {
      finish(() => {
        if (exitCode === 0) {
          resolvePromise({ stdout, stderr });
          return;
        }
        // Append stderr to the message (as Node's execFile does) so classifiers
        // that inspect `error.message` (AADSTS / "az login" / "not recognized")
        // still see the underlying CLI output.
        const suffix = stderr.trim().length > 0 ? `\n${stderr}` : "";
        const e = new Error(
          `Command failed: ${command} (exit code ${exitCode ?? "unknown"})${suffix}`,
        ) as RunCommandError;
        e.stdout = stdout;
        e.stderr = stderr;
        if (exitCode !== null) e.code = exitCode;
        reject(e);
      });
    });

    if (options.timeout && options.timeout > 0) {
      timer = setTimeout(() => {
        finish(() => {
          child.kill();
          const e = new Error(
            `Command timed out after ${options.timeout}ms: ${command}`,
          ) as RunCommandError;
          e.stdout = stdout;
          e.stderr = stderr;
          e.code = "ETIMEDOUT";
          reject(e);
        });
      }, options.timeout);
      if (typeof timer.unref === "function") timer.unref();
    }
  });
}

/**
 * Spawn a streaming child process without a shell. Thin `cross-spawn`
 * passthrough for callers that need the live `ChildProcess` (detached
 * dev-servers, custom stdio, event handling). `shell` is always forced off.
 */
export function spawnProcess(
  command: string,
  args: readonly string[] = [],
  options: SpawnOptions = {},
): ChildProcess {
  const cwd =
    typeof options.cwd === "string"
      ? options.cwd
      : options.cwd
        ? fileURLToPath(options.cwd)
        : undefined;
  const executable = cwd !== undefined
    ? resolveExecutablePath(command, { cwd, env: options.env })
    : command;
  return spawn(executable, [...args], { ...options, shell: false });
}
