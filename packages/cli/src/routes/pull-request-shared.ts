import path from "node:path";
import { eq } from "drizzle-orm";
import type { StageDb } from "../db/client.js";
import { chapterRun } from "../db/schema/index.js";
import { type GitHubRepo, parseGitHubRepo } from "../github/index.js";
import { NetworkAccess } from "../network.js";
import type { RouteHandler, RouteParams } from "../server.js";
import { writeJson } from "./json.js";

type Res = Parameters<RouteHandler>[1];
type Req = Parameters<RouteHandler>[0];

export interface RunRepo {
	repoRoot: string;
	originUrl: string | null;
	/** PR this run targets (`--pr`), or null for branch-detected and legacy runs. */
	prNumber: number | null;
	/**
	 * Branch checked out when the run was imported; pins PR discovery to the
	 * branch the user actually reviewed. Null on legacy rows, which fall back
	 * to the checked-out branch's PR.
	 */
	headRef: string | null;
}

/** Resolve a run's repo context, writing the matching error response on failure. */
export function resolveRun(db: StageDb, params: RouteParams, res: Res): RunRepo | null {
	const runId = params.runId;
	if (!runId) {
		writeJson(res, 400, { error: "Missing runId" });
		return null;
	}
	const [run] = db.select().from(chapterRun).where(eq(chapterRun.id, runId)).limit(1).all();
	if (!run) {
		writeJson(res, 404, { error: `Run ${runId} not found` });
		return null;
	}
	const repoRoot = run.repoRoot;
	if (!path.isAbsolute(repoRoot) || repoRoot.split(path.sep).includes("..")) {
		writeJson(res, 500, {
			error: "Run repoRoot is not an absolute path or contains traversal segments",
		});
		return null;
	}
	return { repoRoot, originUrl: run.originUrl, prNumber: run.prNumber, headRef: run.headRef };
}

export function requireRepo(run: RunRepo, res: Res): GitHubRepo | null {
	const repo = parseGitHubRepo(run.originUrl);
	if (!repo) {
		writeJson(res, 404, { error: "Run is not associated with a GitHub remote" });
		return null;
	}
	return repo;
}

export function query(req: Req, key: string): string | null {
	const url = req.url ?? "";
	const qIdx = url.indexOf("?");
	if (qIdx < 0) return null;
	return new URLSearchParams(url.slice(qIdx + 1)).get(key);
}

export function parseNumber(value: string | null): number | null {
	if (value === null) return null;
	const n = Number(value);
	return Number.isInteger(n) && n > 0 ? n : null;
}

/** Hostname from a `Host` header (`host[:port]`), or null if it can't be parsed. */
function hostHeaderHostname(host: string | undefined): string | null {
	if (!host) return null;
	try {
		return new URL(`http://${host}`).hostname;
	} catch {
		return null;
	}
}

/**
 * Require an explicitly allowed Host plus same-origin Origin and fetch metadata.
 * The Host allowlist also rejects DNS rebinding with a matching hostile Origin.
 */
export function enforceSameOrigin(req: Req, res: Res): boolean {
	const host = req.headers.host;
	const hostname = hostHeaderHostname(host);
	if (hostname === null || !NetworkAccess.forRequest(req).allowsHostname(hostname)) {
		writeJson(res, 403, { error: "Cross-origin request rejected" });
		return false;
	}
	// Cross-site subresource loads (e.g. an <img> on a malicious page pointed
	// at this review port) carry no Origin but do carry Sec-Fetch-Site in
	// every modern browser; same-origin SPA requests send "same-origin" and
	// non-browser clients omit the header entirely.
	const secFetchSite = req.headers["sec-fetch-site"];
	if (
		typeof secFetchSite === "string" &&
		secFetchSite !== "same-origin" &&
		secFetchSite !== "none"
	) {
		writeJson(res, 403, { error: "Cross-origin request rejected" });
		return false;
	}
	const origin = req.headers.origin;
	if (origin === undefined) return true;
	try {
		if (new URL(origin).host === host) return true;
	} catch {
		// malformed Origin — fall through to reject
	}
	writeJson(res, 403, { error: "Cross-origin request rejected" });
	return false;
}
