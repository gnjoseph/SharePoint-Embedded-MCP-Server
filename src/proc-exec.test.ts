// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runCommand, spawnProcess } from "./proc-exec.js";

const { resolveExecutablePathMock, spawnMock } = vi.hoisted(() => ({
  resolveExecutablePathMock: vi.fn(),
  spawnMock: vi.fn(),
}));
vi.mock("cross-spawn", () => ({ default: spawnMock }));
vi.mock("./executable-resolver.js", () => ({
  resolveExecutablePath: resolveExecutablePathMock,
}));

/** Minimal ChildProcess stand-in: EventEmitter with stdout/stderr streams + kill. */
class FakeChild extends EventEmitter {
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  kill = vi.fn();
}

beforeEach(() => {
  resolveExecutablePathMock.mockImplementation(
    (command: string) => `C:\\Program Files\\Trusted\\${command}.cmd`,
  );
});

afterEach(() => {
  resolveExecutablePathMock.mockReset();
  spawnMock.mockReset();
  vi.useRealTimers();
});

describe("runCommand", () => {
  it("buffers stdout/stderr and resolves on a zero exit", async () => {
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);

    const promise = runCommand("az", ["version"]);
    child.stdout.emit("data", Buffer.from("hel"));
    child.stdout.emit("data", Buffer.from("lo"));
    child.stderr.emit("data", Buffer.from("warn"));
    child.emit("close", 0);

    await expect(promise).resolves.toEqual({ stdout: "hello", stderr: "warn" });
  });

  it("never spawns with a shell", async () => {
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);

    const promise = runCommand("az", ["account", "show"], { cwd: "/tmp" });
    child.emit("close", 0);
    await promise;

    expect(spawnMock).toHaveBeenCalledTimes(1);
    const [command, args, opts] = spawnMock.mock.calls[0];
    expect(command).toBe(String.raw`C:\Program Files\Trusted\az.cmd`);
    expect(args).toEqual(["account", "show"]);
    expect(resolveExecutablePathMock).toHaveBeenCalledWith("az", {
      cwd: "/tmp",
      env: undefined,
    });
    expect(opts.shell).toBe(false);
    expect(opts.windowsHide).toBe(true);
    expect(opts.cwd).toBe("/tmp");
  });

  it("rejects a working-directory executable resolution error before spawning", async () => {
    resolveExecutablePathMock.mockImplementation(() => {
      throw Object.assign(new Error("untrusted executable resolution"), {
        code: "ERR_UNTRUSTED_EXECUTABLE",
      });
    });

    await expect(
      runCommand("az", ["version"], { cwd: "/project" }),
    ).rejects.toMatchObject({
      code: "ERR_UNTRUSTED_EXECUTABLE",
      stdout: "",
      stderr: "",
    });
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("passes a punctuation-heavy argument through as one discrete argv element (never a shell string)", async () => {
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);

    // A single argument packed with shell-significant punctuation must reach the
    // child verbatim as ONE argv element — never split, expanded, or interpreted.
    const packed = "rg & | ; $() (sub)";
    const promise = runCommand("az", ["group", "show", "--name", packed]);
    child.emit("close", 0);
    await promise;

    const [command, args, opts] = spawnMock.mock.calls[0];
    expect(command).toBe("az");
    // Exactly one element per logical argument; the packed value is untouched.
    expect(args).toEqual(["group", "show", "--name", packed]);
    expect(args[3]).toBe(packed);
    expect(opts.shell).toBe(false);
  });

  it("rejects on a non-zero exit with stdout/stderr/code and stderr in the message", async () => {
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);

    const promise = runCommand("az", ["group", "list"]);
    child.stdout.emit("data", Buffer.from("partial"));
    child.stderr.emit("data", Buffer.from("AADSTS50076 boom"));
    child.emit("close", 2);

    await expect(promise).rejects.toMatchObject({
      stdout: "partial",
      stderr: "AADSTS50076 boom",
      code: 2,
    });
    await promise.catch((e: Error) => {
      expect(e.message).toContain("AADSTS50076 boom");
    });
  });

  it("preserves ENOENT (missing command) as message text and code", async () => {
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);

    const promise = runCommand("az", ["version"]);
    child.emit("error", Object.assign(new Error("spawn az ENOENT"), { code: "ENOENT" }));

    await expect(promise).rejects.toMatchObject({ code: "ENOENT" });
    await promise.catch((e: Error) => {
      expect(e.message).toContain("ENOENT");
    });
  });

  it("normalizes a synchronous spawn throw with message, stack, code, and empty streams", async () => {
    const spawnError = Object.assign(new Error("invalid spawn options"), {
      code: "ERR_INVALID_ARG_TYPE",
    });
    spawnError.stack = "preserved synchronous spawn stack";
    spawnMock.mockImplementation(() => {
      throw spawnError;
    });

    const error = await runCommand("az", ["version"]).catch(
      (reason: unknown) => reason as Error & {
        stdout: string;
        stderr: string;
        code?: number | string;
      },
    );

    expect(error).toBe(spawnError);
    expect(error.message).toBe("invalid spawn options");
    expect(error.stack).toBe("preserved synchronous spawn stack");
    expect(error.code).toBe("ERR_INVALID_ARG_TYPE");
    expect(error.stdout).toBe("");
    expect(error.stderr).toBe("");
  });

  it("leaves code unset when a synchronous spawn error has no code", async () => {
    spawnMock.mockImplementation(() => {
      throw new Error("spawn failed before launch");
    });

    await expect(runCommand("az", ["version"])).rejects.toMatchObject({
      message: "spawn failed before launch",
      stdout: "",
      stderr: "",
    });
    await expect(runCommand("az", ["version"])).rejects.not.toHaveProperty("code");
  });

  it("kills the child and rejects with ETIMEDOUT when the timeout elapses", async () => {
    vi.useFakeTimers();
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);

    const promise = runCommand("az", ["version"], { timeout: 1000 });
    vi.advanceTimersByTime(1000);

    await expect(promise).rejects.toMatchObject({ code: "ETIMEDOUT" });
    expect(child.kill).toHaveBeenCalledTimes(1);
  });
});

describe("spawnProcess", () => {
  it("returns the child and forces shell off even if a caller requests one", () => {
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);

    const result = spawnProcess("npm", ["run", "dev"], {
      cwd: "/proj",
      detached: true,
      shell: true,
    });

    expect(result).toBe(child);
    const [command, args, opts] = spawnMock.mock.calls[0];
    expect(command).toBe(String.raw`C:\Program Files\Trusted\npm.cmd`);
    expect(args).toEqual(["run", "dev"]);
    expect(opts.detached).toBe(true);
    expect(opts.shell).toBe(false);
  });

  it("passes a punctuation-heavy argument through as one discrete argv element", () => {
    const child = new FakeChild();
    spawnMock.mockReturnValue(child);

    const packed = "run & | ; $()";
    spawnProcess("npm", ["run", packed], { detached: true });

    const [command, args, opts] = spawnMock.mock.calls[0];
    expect(command).toBe("npm");
    expect(args).toEqual(["run", packed]);
    expect(args[1]).toBe(packed);
    expect(opts.shell).toBe(false);
  });
});
