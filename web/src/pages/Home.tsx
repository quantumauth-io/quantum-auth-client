import { useEffect, useRef, useState } from "react";
import { PairExtensionCard } from "../components/PairExtensionCard";
import { CollapsibleSection } from "../components/CollapsibleSection";

import { apiFetch } from "../lib/api";
import type { ApiResult } from "../lib/api";
import type { SessionValidateResp } from "../types/qa";

type Status = {
    ok: boolean;
    version?: string;
    tpm?: { ok: boolean; detail?: string };
};

type ExchangeResp = {
    token: string;
    header?: string;
};

const SESSION_KEY = "qa_session_token";

// Pairing params are passed in the hash query (/#/pair?pair_id=...&code=...&server=...)
function getHashQueryParams(): URLSearchParams {
    const hash = window.location.hash || "";
    const idx = hash.indexOf("?");
    if (idx === -1) return new URLSearchParams();
    return new URLSearchParams(hash.slice(idx + 1));
}

function clearHashQuery() {
    const hash = window.location.hash || "";
    window.location.hash = hash.split("?")[0] || "#/";
}

/**
 * IMPORTANT:
 * - If you are serving UI + API from same origin, keep these relative.
 * - If UI is on a different port, you should set VITE_API_BASE at build time.
 */
const STATUS_PATH = "/status"; // adjust to "/api/status" ONLY if that’s what your Go server exposes

export default function Home() {
    const [status, setStatus] = useState<Status | null>(null);
    const [statusErr, setStatusErr] = useState<string | null>(null);

    const [sessionValid, setSessionValid] = useState<boolean | null>(null);
    const [sessionErr, setSessionErr] = useState<string | null>(null);

    const [sessionToken, setSessionToken] = useState<string>(() => {
        return localStorage.getItem(SESSION_KEY) || "";
    });

    async function validateSessionToken(token: string) {
        if (!token) {
            setSessionValid(false);
            setSessionErr(null);
            return;
        }

        // apiFetch returns ApiResult<T> and does not throw on HTTP errors.
        let res: ApiResult<SessionValidateResp>;
        try {
            res = await apiFetch<SessionValidateResp>("/agent/session/validate", {
                method: "GET",
                headers: {
                    "X-QA-Session": token,
                },
            });
        } catch (e: any) {
            setSessionValid(false);
            setSessionErr(e?.message ?? "Could not validate session");
            return;
        }

        if (res.status === 401) {
            localStorage.removeItem(SESSION_KEY);
            setSessionToken("");
            setSessionValid(false);
            setSessionErr("Session expired. Re-pair from the client link.");
            return;
        }

        if (!res.ok) {
            setSessionValid(false);
            setSessionErr(`Validate failed (HTTP ${res.status}) ${res.error}`.trim());
            return;
        }

        // If your handler returns { ok, valid }, respect it.
        // If your type doesn’t include `valid`, this will compile only if SessionValidateResp has it.
        // If not, remove this check.
        if (typeof (res.data as any)?.valid === "boolean" && !(res.data as any).valid) {
            setSessionValid(false);
            setSessionErr("Session invalid. Re-pair from the client link.");
            return;
        }

        setSessionValid(true);
        setSessionErr(null);
    }

    useEffect(() => {
        void validateSessionToken(sessionToken || "");
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [sessionToken]);

    // Status fetch on load
    useEffect(() => {
        let alive = true;

        (async () => {
            try {
                const res = await apiFetch<Status>(STATUS_PATH, { method: "GET" });
                if (!alive) return;

                if (!res.ok) {
                    setStatus(null);
                    setStatusErr(`Status failed (HTTP ${res.status}) ${res.error}`.trim());
                    return;
                }

                setStatus(res.data);
                setStatusErr(null);
            } catch (e: any) {
                if (!alive) return;
                setStatus(null);
                setStatusErr(e?.message ?? String(e));
            }
        })();

        return () => {
            alive = false;
        };
    }, []);

    // Pair exchange (if opened from CLI link)
    const ranPair = useRef(false);
    useEffect(() => {
        if (ranPair.current) return;
        ranPair.current = true;

        let alive = true;

        (async () => {
            const qs = getHashQueryParams();
            const pair_id = qs.get("pair_id") ?? "";
            const code = qs.get("code") ?? "";

            // No pairing params → do nothing
            if (!pair_id || !code) return;

            // If server param is present, use it; otherwise assume same origin.
            const exchangePath = "/pair/exchange";

            try {
                const res = await apiFetch<ExchangeResp>(exchangePath, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    // IMPORTANT: your old code used credentials: "omit".
                    // apiFetch currently forces credentials: "include". If you truly must omit,
                    // we can add a knob. For now, server is localhost and doesn't rely on cookies.
                    body: JSON.stringify({ pair_id, code }),
                });

                if (!alive) return;

                if (!res.ok) {
                    // Don’t silently fail; surface something helpful
                    setSessionValid(false);
                    setSessionErr(`Pair exchange failed (HTTP ${res.status}) ${res.error}`.trim());
                    return;
                }

                localStorage.setItem(SESSION_KEY, res.data.token);
                setSessionToken(res.data.token);

                clearHashQuery();
            } catch {
                // keep it quiet; you can log if you want
            }
        })();

        return () => {
            alive = false;
        };
    }, []);

    const clientRunning = !!status?.ok && !statusErr;

    return (
        <div style={{ maxWidth: 800, margin: "0 auto", padding: 24, fontFamily: "system-ui" }}>
            <h1 style={{ marginBottom: 8 }}>Quantum Agent</h1>
            <p style={{ marginTop: 0, opacity: 0.8 }}>Local guardian UI (localhost)</p>

            <CollapsibleSection
                title="Status"
                indicatorColor={clientRunning ? "limegreen" : "tomato"}
                indicatorTitle={clientRunning ? "Client running" : "Client not responding"}
                defaultOpen={true}
                storageKey="qa_ui_section_status"
            >
                <div className="pt-4">
                    {statusErr && (
                        <div className="flex items-center gap-3 text-red-400">
                            <span className="text-xl">✕</span>
                            <span>Could not reach the client: {statusErr}</span>
                        </div>
                    )}

                    {!statusErr && !status && <div className="text-white/60">Checking client status…</div>}

                    {!statusErr && status?.ok && (
                        <div className="flex items-center gap-3 text-green-400">
                            <span className="text-xl">✓</span>
                            <span>Client running</span>
                        </div>
                    )}
                </div>
            </CollapsibleSection>

            <CollapsibleSection
                title="Session"
                indicatorColor={sessionValid === true ? "limegreen" : "tomato"}
                indicatorTitle={
                    sessionValid === null ? "Checking session…" : sessionValid ? "Session active" : "Session invalid"
                }
                defaultOpen={true}
                storageKey="qa_ui_section_session"
            >
                <div className="pt-4 space-y-4">
                    {sessionValid === null && (
                        <div className="flex items-center gap-3 text-white/60">
                            <span className="text-xl">…</span>
                            <span>Validating session…</span>
                        </div>
                    )}

                    {sessionValid === true && (
                        <div className="flex items-center gap-3 text-green-400">
                            <span className="text-xl">✓</span>
                            <span>Session active</span>
                        </div>
                    )}

                    {sessionValid === false && (
                        <div className="flex items-center gap-3 text-red-400">
                            <span className="text-xl">✕</span>
                            <span>{sessionErr ?? "No active session"}</span>
                        </div>
                    )}

                    <div className="flex gap-3">
                        <button
                            className="px-4 py-2 rounded-lg bg-black/40 hover:bg-black/60 transition"
                            onClick={() => {
                                localStorage.removeItem(SESSION_KEY);
                                setSessionToken("");
                                setSessionValid(false);
                                setSessionErr(null);
                            }}
                        >
                            Clear session
                        </button>

                        <button
                            className="px-4 py-2 rounded-lg bg-black/40 hover:bg-black/60 transition"
                            onClick={() => window.location.reload()}
                        >
                            Refresh
                        </button>
                    </div>
                </div>
            </CollapsibleSection>

            {/* pass token down so PairExtensionCard never uses stale memo */}
            <PairExtensionCard sessionToken={sessionToken} />

            <div style={{ marginTop: 16, padding: 16, border: "1px solid #333", borderRadius: 12 }}>
                <h2 style={{ marginTop: 0 }}>Actions (coming next)</h2>
                <ul>
                    <li>Register guardian</li>
                    <li>Deposit</li>
                    <li>Withdraw (requires TPM approval)</li>
                </ul>
            </div>
        </div>
    );
}
