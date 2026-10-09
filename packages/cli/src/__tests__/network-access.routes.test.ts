import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CommentRouteHarness } from "./comments-route-harness.js";

let harness: CommentRouteHarness;
let configDir: string;
let configPath: string;

beforeEach(async () => {
	harness = new CommentRouteHarness();
	await harness.setup();
	configDir = await fs.mkdtemp(path.join(os.tmpdir(), "stage-network-"));
	configPath = path.join(configDir, "network.json");
	vi.stubEnv("STAGEREVIEW_NETWORK_CONFIG", configPath);
});

afterEach(async () => {
	await harness.teardown();
	vi.unstubAllEnvs();
	await fs.rm(configDir, { recursive: true, force: true });
});

async function configure(allowedHosts: string[]): Promise<void> {
	await fs.writeFile(configPath, JSON.stringify({ allowedHosts }));
}

function sameOriginHeaders(host: string, port: number): Record<string, string> {
	return {
		Host: `${host}:${port}`,
		Origin: `http://${host}:${port}`,
		"Sec-Fetch-Site": "same-origin",
	};
}

describe("network review access", () => {
	it("reads and writes comments through an explicitly allowed Tailscale hostname", async () => {
		const host = "review.tail-example.ts.net";
		await configure([host]);
		const runId = harness.seedRun();
		const port = await harness.start();
		const headers = sameOriginHeaders(host, port);

		const created = await harness.request(
			port,
			"POST",
			`/api/runs/${runId}/comment-threads`,
			harness.makeThreadBody(),
			headers,
		);
		const listed = await harness.request(
			port,
			"GET",
			`/api/runs/${runId}/comment-threads`,
			undefined,
			headers,
		);

		expect(created.status).toBe(201);
		expect(listed.status).toBe(200);
		expect(listed.body).toHaveLength(1);
	});

	it("accepts an explicitly allowed Tailscale IP", async () => {
		const host = "100.80.205.82";
		await configure([host]);
		const runId = harness.seedRun();
		const port = await harness.start();

		const response = await harness.request(
			port,
			"GET",
			`/api/runs/${runId}/comment-threads`,
			undefined,
			sameOriginHeaders(host, port),
		);

		expect(response.status).toBe(200);
	});

	it.each([
		"cross-site",
		"same-site",
	])("rejects %s fetches even through an allowed hostname", async (fetchSite) => {
		const host = "review.tail-example.ts.net";
		await configure([host]);
		const port = await harness.start();

		const response = await harness.request(
			port,
			"GET",
			"/api/runs/any/comment-threads",
			undefined,
			{ ...sameOriginHeaders(host, port), "Sec-Fetch-Site": fetchSite },
		);

		expect(response.status).toBe(403);
	});

	it("keeps each running server’s configured hostnames independent", async () => {
		const firstHost = "first.tail-example.ts.net";
		const secondHost = "second.tail-example.ts.net";
		const runId = harness.seedRun();
		await configure([firstHost]);
		const firstPort = await harness.start();
		await configure([secondHost]);
		const secondPort = await harness.start();
		const requestPath = `/api/runs/${runId}/comment-threads`;

		const first = await harness.request(
			firstPort,
			"GET",
			requestPath,
			undefined,
			sameOriginHeaders(firstHost, firstPort),
		);
		const second = await harness.request(
			secondPort,
			"GET",
			requestPath,
			undefined,
			sameOriginHeaders(firstHost, secondPort),
		);

		expect(first.status).toBe(200);
		expect(second.status).toBe(403);
	});

	it("rejects a foreign Origin on an allowed hostname", async () => {
		const host = "review.tail-example.ts.net";
		await configure([host]);
		const port = await harness.start();

		const response = await harness.request(
			port,
			"GET",
			"/api/runs/any/comment-threads",
			undefined,
			{ ...sameOriginHeaders(host, port), Origin: "https://attacker.example" },
		);

		expect(response.status).toBe(403);
	});

	it("rejects a matching Origin on an unknown hostname", async () => {
		const port = await harness.start();

		const response = await harness.request(
			port,
			"GET",
			"/api/runs/any/comment-threads",
			undefined,
			sameOriginHeaders("attacker.example", port),
		);

		expect(response.status).toBe(403);
		expect(response.body).toEqual({ error: "Cross-origin request rejected" });
	});

	const lanAddress = Object.values(os.networkInterfaces())
		.flatMap((addresses) => addresses ?? [])
		.find((address) => address.family === "IPv4" && !address.internal)?.address;

	it.skipIf(lanAddress === undefined)(
		"serves comments through a real network interface",
		async () => {
			if (lanAddress === undefined) throw new Error("No network interface available");
			const runId = harness.seedRun();
			const port = await harness.start();

			const status = await new Promise<number>((resolve, reject) => {
				const request = http.request(
					{
						hostname: lanAddress,
						port,
						path: `/api/runs/${runId}/comment-threads`,
						headers: sameOriginHeaders(lanAddress, port),
						agent: false,
					},
					(response) => {
						response.resume();
						response.on("end", () => resolve(response.statusCode ?? 0));
					},
				);
				request.on("error", reject);
				request.end();
			});

			expect(status).toBe(200);
		},
	);
});
