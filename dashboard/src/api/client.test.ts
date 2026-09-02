import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchHealth, inspectUrl } from "./client";

describe("fetchHealth", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns parsed health data on a 200 response", async () => {
    const body = {
      status: "ok",
      service: "PIP Backend",
      version: "0.1.0",
      database: "ok",
      timestamp: "2026-08-13T00:00:00Z",
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: true, json: async () => body }),
    );

    await expect(fetchHealth()).resolves.toEqual(body);
  });

  it("throws an error when the backend responds non-OK", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 500 }));

    await expect(fetchHealth()).rejects.toThrow(
      "Health check failed with status 500",
    );
  });
});

describe("inspectUrl", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("POSTs the URL and returns the inspection result", async () => {
    const body = {
      id: 1,
      url: "https://example.com/login",
      status: "completed",
      score: 10,
      classification: "safe",
      features: { scheme: "https" },
      reasons: ["Hostname contains suspicious keyword(s): login"],
      created_at: "2026-08-13T00:00:00Z",
      updated_at: "2026-08-13T00:00:00Z",
    };
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: true, json: async () => body });
    vi.stubGlobal("fetch", fetchMock);

    await expect(inspectUrl("https://example.com/login")).resolves.toEqual(body);

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/inspect",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ url: "https://example.com/login" }),
      }),
    );
  });

  it("throws an error when the backend rejects the URL", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 422 }));

    await expect(inspectUrl("not-a-url")).rejects.toThrow(
      "Inspection failed with status 422",
    );
  });
});
