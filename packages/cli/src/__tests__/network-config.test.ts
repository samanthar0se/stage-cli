import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { NetworkAccess } from "../network.js";

let directory: string;
let configPath: string;

beforeEach(async () => {
	directory = await fs.mkdtemp(path.join(os.tmpdir(), "stage-network-config-"));
	configPath = path.join(directory, "network.json");
});

afterEach(async () => {
	await fs.rm(directory, { recursive: true, force: true });
});

describe("network configuration", () => {
	it("uses network binding when no config file exists", () => {
		expect(NetworkAccess.load(configPath).host).toBe("0.0.0.0");
	});

	it("limits advertised addresses when explicitly bound to loopback", async () => {
		await fs.writeFile(configPath, JSON.stringify({ host: "127.0.0.1" }));

		const network = NetworkAccess.load(configPath);

		expect(network.reviewHosts).toEqual(["127.0.0.1"]);
	});

	it("normalizes configured DNS names before matching browser requests", async () => {
		await fs.writeFile(
			configPath,
			JSON.stringify({ allowedHosts: ["  Review.Tail-Example.TS.NET  "] }),
		);

		const network = NetworkAccess.load(configPath);

		expect(network.allowsHostname("review.tail-example.ts.net")).toBe(true);
		expect(network.allowsHostname("other.tail-example.ts.net")).toBe(false);
	});

	it.each([
		"*.ts.net",
		"http://review.ts.net",
		"review.ts.net:5391",
	])("rejects the invalid allowed host %s", async (host) => {
		await fs.writeFile(configPath, JSON.stringify({ allowedHosts: [host] }));

		expect(() => NetworkAccess.load(configPath)).toThrow();
	});

	it("rejects misspelled configuration keys instead of ignoring them", async () => {
		await fs.writeFile(configPath, JSON.stringify({ allowedHost: ["review.ts.net"] }));

		expect(() => NetworkAccess.load(configPath)).toThrow();
	});
});
