import { existsSync, readFileSync } from "node:fs";
import type { IncomingMessage } from "node:http";
import { homedir, networkInterfaces } from "node:os";
import path from "node:path";
import { z } from "zod";

export const DEFAULT_BIND_HOST = "0.0.0.0";
export const LOOPBACK_HOST = "127.0.0.1";

const NetworkConfigSchema = z
	.object({
		host: z.ipv4().default(DEFAULT_BIND_HOST),
		allowedHosts: z
			.array(
				z
					.string()
					.trim()
					.toLowerCase()
					.regex(
						/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/,
						"Use a hostname or IPv4 address without a port",
					),
			)
			.default([]),
	})
	.strict();

type NetworkConfig = z.infer<typeof NetworkConfigSchema>;

export class NetworkAccess {
	private static readonly requests = new WeakMap<IncomingMessage, NetworkAccess>();
	private readonly allowedHosts: Set<string>;
	readonly host: string;
	readonly reviewHosts: readonly string[];

	private constructor(config: NetworkConfig) {
		this.host = config.host;
		const interfaceHosts = Object.values(networkInterfaces())
			.flatMap((addresses) => addresses ?? [])
			.filter((address) => address.family === "IPv4" && !address.internal)
			.map((address) => address.address);
		this.reviewHosts = [
			...new Set(
				config.host === DEFAULT_BIND_HOST
					? [...interfaceHosts, ...config.allowedHosts]
					: [config.host],
			),
		];
		this.allowedHosts = new Set([
			LOOPBACK_HOST,
			"localhost",
			...this.reviewHosts,
			...config.allowedHosts,
		]);
	}

	static load(
		configPath = process.env.STAGEREVIEW_NETWORK_CONFIG ??
			path.join(homedir(), ".stage", "network.json"),
	): NetworkAccess {
		const input: unknown = existsSync(configPath)
			? JSON.parse(readFileSync(configPath, "utf8"))
			: {};
		return new NetworkAccess(NetworkConfigSchema.parse(input));
	}

	attach(req: IncomingMessage): void {
		NetworkAccess.requests.set(req, this);
	}

	static forRequest(req: IncomingMessage): NetworkAccess {
		const network = NetworkAccess.requests.get(req);
		if (!network) throw new Error("Request network access was not initialized");
		return network;
	}

	allowsHostname(hostname: string): boolean {
		return this.allowedHosts.has(hostname);
	}
}
