// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/**
 * Resolve an external executable before a caller-controlled working directory is
 * applied. This avoids Windows command lookup selecting a same-named shim from
 * the working directory ahead of the host-configured PATH.
 */

import { accessSync, constants, realpathSync, statSync } from "node:fs";
import { posix, win32 } from "node:path";

export type ExecutableResolutionErrorCode =
  | "ENOENT"
  | "ERR_INVALID_EXECUTABLE"
  | "ERR_UNTRUSTED_EXECUTABLE";

export class ExecutableResolutionError extends Error {
  readonly code: ExecutableResolutionErrorCode;

  constructor(message: string, code: ExecutableResolutionErrorCode) {
    super(message);
    this.name = "ExecutableResolutionError";
    this.code = code;
  }
}

export interface ExecutableResolverDependencies {
  platform: NodeJS.Platform;
  isExecutableFile(candidate: string): boolean;
  realpath(candidate: string): string;
}

export interface ResolveExecutableOptions {
  cwd: string;
  env?: NodeJS.ProcessEnv;
}

function defaultDependencies(): ExecutableResolverDependencies {
  const platform = process.platform;
  return {
    platform,
    isExecutableFile: (candidate) => {
      try {
        if (!statSync(candidate).isFile()) return false;
        if (platform !== "win32") accessSync(candidate, constants.X_OK);
        return true;
      } catch {
        return false;
      }
    },
    realpath: (candidate) => realpathSync.native(candidate),
  };
}

function environmentValue(
  env: NodeJS.ProcessEnv,
  name: string,
  platform: NodeJS.Platform,
): string | undefined {
  if (env[name] !== undefined) return env[name];
  if (platform !== "win32") return undefined;
  const key = Object.keys(env).find((candidate) => candidate.toUpperCase() === name);
  return key ? env[key] : undefined;
}

function isWithinDirectory(
  candidate: string,
  directory: string,
  pathApi: typeof posix | typeof win32,
): boolean {
  const relative = pathApi.relative(directory, candidate);
  return (
    relative === "" ||
    (relative !== ".." &&
      !relative.startsWith(`..${pathApi.sep}`) &&
      !pathApi.isAbsolute(relative))
  );
}

/**
 * Resolve `command` only from absolute host PATH entries, canonicalize it, and
 * reject a result inside `cwd`. The returned path is always absolute.
 *
 * The dependency argument exists so platform-specific path lookup can be tested
 * deterministically without launching a process.
 */
export function resolveExecutablePath(
  command: string,
  options: ResolveExecutableOptions,
  dependencies: ExecutableResolverDependencies = defaultDependencies(),
): string {
  const { platform } = dependencies;
  const pathApi = platform === "win32" ? win32 : posix;
  const env = options.env ?? process.env;
  const projectDir = dependencies.realpath(options.cwd);

  if (!pathApi.isAbsolute(command) && /[\\/]/.test(command)) {
    throw new ExecutableResolutionError(
      `Executable "${command}" must be a bare name or absolute path when a working directory is set.`,
      "ERR_INVALID_EXECUTABLE",
    );
  }

  const pathEntries = pathApi.isAbsolute(command)
    ? [""]
    : (environmentValue(env, "PATH", platform) ?? "")
        .split(pathApi.delimiter)
        .map((entry) => entry.trim().replace(/^"(.*)"$/, "$1"))
        .filter((entry) => entry.length > 0 && pathApi.isAbsolute(entry));

  const extensions =
    platform === "win32" && pathApi.extname(command) === ""
      ? (environmentValue(env, "PATHEXT", platform) ?? ".COM;.EXE;.BAT;.CMD")
          .split(";")
          .map((extension) => extension.trim())
          .filter(Boolean)
      : [""];

  for (const directory of pathEntries) {
    for (const extension of extensions) {
      const candidate = pathApi.isAbsolute(command)
        ? `${command}${extension}`
        : pathApi.join(directory, `${command}${extension}`);
      if (!dependencies.isExecutableFile(candidate)) continue;

      const resolved = dependencies.realpath(candidate);
      if (!pathApi.isAbsolute(resolved)) {
        throw new ExecutableResolutionError(
          `Executable "${command}" did not resolve to an absolute path.`,
          "ERR_INVALID_EXECUTABLE",
        );
      }
      if (isWithinDirectory(resolved, projectDir, pathApi)) {
        throw new ExecutableResolutionError(
          `Refusing to execute "${command}" because it resolves inside the requested working directory.`,
          "ERR_UNTRUSTED_EXECUTABLE",
        );
      }
      return resolved;
    }
  }

  throw new ExecutableResolutionError(
    `Unable to resolve executable "${command}" from PATH before applying the requested working directory.`,
    "ENOENT",
  );
}
