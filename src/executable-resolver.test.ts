// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { describe, expect, it } from "vitest";
import {
  ExecutableResolutionError,
  resolveExecutablePath,
  type ExecutableResolverDependencies,
} from "./executable-resolver.js";

const PROJECT_DIR = String.raw`C:\work\generated-project`;
const TRUSTED_DIR = String.raw`C:\Program Files\Azure CLI\bin`;
const PROJECT_SHIM = String.raw`C:\work\generated-project\az.cmd`;
const TRUSTED_SHIM = String.raw`C:\Program Files\Azure CLI\bin\az.cmd`;

function windowsResolver(files: string[]): {
  dependencies: ExecutableResolverDependencies;
  probed: string[];
} {
  const knownFiles = new Map(files.map((file) => [file.toLowerCase(), file]));
  const probed: string[] = [];
  return {
    dependencies: {
      platform: "win32",
      isExecutableFile: (candidate) => {
        probed.push(candidate);
        return knownFiles.has(candidate.toLowerCase());
      },
      realpath: (candidate) => knownFiles.get(candidate.toLowerCase()) ?? candidate,
    },
    probed,
  };
}

describe("resolveExecutablePath", () => {
  it("resolves a Windows CLI shim from PATH without probing the project cwd", () => {
    const { dependencies, probed } = windowsResolver([PROJECT_SHIM, TRUSTED_SHIM]);

    const resolved = resolveExecutablePath(
      "az",
      {
        cwd: PROJECT_DIR,
        env: { Path: TRUSTED_DIR, PATHEXT: ".EXE;.CMD" },
      },
      dependencies,
    );

    expect(resolved).toBe(TRUSTED_SHIM);
    expect(probed).not.toContain(PROJECT_SHIM);
  });

  it("rejects a Windows PATH entry that resolves inside the project directory", () => {
    const { dependencies } = windowsResolver([PROJECT_SHIM, TRUSTED_SHIM]);

    expect(() =>
      resolveExecutablePath(
        "az",
        {
          cwd: PROJECT_DIR,
          env: { Path: `${PROJECT_DIR};${TRUSTED_DIR}`, PATHEXT: ".EXE;.CMD" },
        },
        dependencies,
      ),
    ).toThrowError(
      expect.objectContaining<Partial<ExecutableResolutionError>>({
        code: "ERR_UNTRUSTED_EXECUTABLE",
      }),
    );
  });

  it("rejects an external path whose canonical target is inside the project", () => {
    const linkDir = String.raw`C:\trusted-links`;
    const link = String.raw`C:\trusted-links\az.cmd`;

    expect(() =>
      resolveExecutablePath(
        "az",
        {
          cwd: PROJECT_DIR,
          env: { Path: linkDir, PATHEXT: ".CMD" },
        },
        {
          platform: "win32",
          isExecutableFile: (candidate) => candidate.toLowerCase() === link.toLowerCase(),
          realpath: (candidate) =>
            candidate.toLowerCase() === link.toLowerCase() ? PROJECT_SHIM : candidate,
        },
      ),
    ).toThrowError(
      expect.objectContaining<Partial<ExecutableResolutionError>>({
        code: "ERR_UNTRUSTED_EXECUTABLE",
      }),
    );
  });

  it("surfaces an explicit error when the executable is absent from PATH", () => {
    const { dependencies } = windowsResolver([]);

    expect(() =>
      resolveExecutablePath(
        "azd",
        {
          cwd: PROJECT_DIR,
          env: { Path: TRUSTED_DIR, PATHEXT: ".EXE;.CMD" },
        },
        dependencies,
      ),
    ).toThrowError(
      expect.objectContaining<Partial<ExecutableResolutionError>>({
        code: "ENOENT",
      }),
    );
  });

  it("verifies an absolute Windows command path with PATHEXT", () => {
    const command = String.raw`C:\Program Files\Azure CLI\bin\az`;
    const { dependencies } = windowsResolver([TRUSTED_SHIM]);

    expect(
      resolveExecutablePath(
        command,
        {
          cwd: PROJECT_DIR,
          env: { PATHEXT: ".EXE;.CMD" },
        },
        dependencies,
      ),
    ).toBe(TRUSTED_SHIM);
  });

  it("preserves POSIX executable discovery from absolute PATH entries", () => {
    const resolved = resolveExecutablePath(
      "azd",
      {
        cwd: "/work/generated-project",
        env: { PATH: "/usr/local/bin:/usr/bin" },
      },
      {
        platform: "linux",
        isExecutableFile: (candidate) => candidate === "/usr/local/bin/azd",
        realpath: (candidate) => candidate,
      },
    );

    expect(resolved).toBe("/usr/local/bin/azd");
  });
});
