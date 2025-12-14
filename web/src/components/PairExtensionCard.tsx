import { useEffect, useState } from "react";
import { CollapsibleSection } from "./CollapsibleSection";

import { apiFetch } from "../lib/api";
import type { ApiResult } from "../lib/api";

type PairResp = {
    ok: boolean;
    pairingToken?: string;
    pairingTokenPath?: string;
    error?: string;
};

type ExtensionStatusResp = {
    paired: boolean;
};

function CopyIcon({ className = "" }: { className?: string }) {
    return (
        <svg
            className={className}
            viewBox="0 0 24 24"
            width="18"
            height="18"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
        >
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
        </svg>
    );
}

export function PairExtensionCard({ sessionToken }: { sessionToken: string }) {
    const [token, setToken] = useState("");
    const [loading, setLoading] = useState(false);
    const [copied, setCopied] = useState(false);

    const [error, setError] = useState(""); // for generate/copy actions
    const [paired, setPaired] = useState<boolean | null>(null); // null = checking/unknown
    const [statusErr, setStatusErr] = useState(""); // for status endpoint

    async function fetchExtensionStatus(currentToken: string) {
        setStatusErr("");

        if (!currentToken) {
            setPaired(false);
            return;
        }

        let res: ApiResult<ExtensionStatusResp>;
        try {
            res = await apiFetch<ExtensionStatusResp>("/agent/extension/status", {
                method: "GET",
                headers: {
                    "X-QA-Session": currentToken,
                },
            });
        } catch (e: any) {
            setPaired(false);
            setStatusErr(e?.message || "Could not read extension status");
            return;
        }

        if (res.status === 401) {
            setPaired(false);
            setStatusErr("Session expired (401). Re-pair the UI from the client link.");
            return;
        }

        if (!res.ok) {
            setPaired(false);
            setStatusErr(`Status failed (HTTP ${res.status}) ${res.error}`.trim());
            return;
        }

        setPaired(Boolean(res.data.paired));
    }

    // Re-check status whenever session token changes (pairing / client restart)
    useEffect(() => {
        setPaired(sessionToken ? null : false);
        void fetchExtensionStatus(sessionToken);

        // clear token generation UI state on session changes
        setError("");
        setCopied(false);
        // (optional) clear generated token when session changes:
        // setToken("");
    }, [sessionToken]);

    async function requestPairingToken() {
        setLoading(true);
        setError("");
        setCopied(false);

        if (!sessionToken) {
            setLoading(false);
            setError("Missing agent session token. Pair the UI first.");
            return;
        }

        let res: ApiResult<PairResp>;
        try {
            res = await apiFetch<PairResp>("/agent/extension/pair", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-QA-Session": sessionToken,
                },
            });
        } catch (e: any) {
            setToken("");
            setError(e?.message || "Unknown error");
            setLoading(false);
            return;
        } finally {
            // note: we handle setLoading below to ensure consistent state
        }

        if (res.status === 401) {
            setToken("");
            setError("Session expired (401). Re-pair the UI from the client link.");
            setLoading(false);
            return;
        }

        if (!res.ok) {
            setToken("");
            setError(`Pair request failed (HTTP ${res.status}) ${res.error}`.trim());
            setLoading(false);
            return;
        }

        if (!res.data.ok || !res.data.pairingToken) {
            setToken("");
            setError(res.data.error || "Pair request failed: missing token");
            setLoading(false);
            return;
        }

        setToken(res.data.pairingToken);

        // refresh authoritative status after generating token
        await fetchExtensionStatus(sessionToken);

        setLoading(false);
    }

    async function copyToken() {
        if (!token) return;

        try {
            await navigator.clipboard.writeText(token);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1200);
        } catch {
            const el = document.getElementById("qa_pair_token_input") as HTMLInputElement | null;
            if (el) {
                el.focus();
                el.select();
                document.execCommand("copy");
                setCopied(true);
                window.setTimeout(() => setCopied(false), 1200);
            }
        }
    }

    const indicatorColor = !sessionToken ? "tomato" : paired === true ? "limegreen" : "tomato";

    const indicatorTitle = !sessionToken
        ? "No session"
        : paired === null
            ? "Checking…"
            : paired
                ? "Extension paired"
                : "Extension not paired";

    return (
        <CollapsibleSection
            title="Pair Browser Extension"
            indicatorColor={indicatorColor}
            indicatorTitle={indicatorTitle}
            defaultOpen={false}
            storageKey="qa_ui_section_pair_extension"
        >
            <div className="pt-4 space-y-4">
                <div className="space-y-3">
                    <div className="text-sm text-white/70 text-center">
                        Generate a pairing token and paste it into the QuantumAuth browser extension.
                    </div>

                    <div className="flex justify-center gap-3">
                        <button
                            onClick={requestPairingToken}
                            disabled={!sessionToken || loading}
                            className={[
                                "rounded-xl px-4 py-2 font-semibold",
                                "border border-white/20",
                                !sessionToken || loading
                                    ? "bg-white/5 text-white/60 cursor-not-allowed"
                                    : "bg-white/10 hover:bg-white/15",
                                "transition-colors",
                            ].join(" ")}
                            title={!sessionToken ? "Pair the UI first" : "Generate a token for the extension"}
                        >
                            {loading ? "Generating…" : "Generate token"}
                        </button>

                        <button
                            onClick={() => void fetchExtensionStatus(sessionToken)}
                            disabled={!sessionToken || loading}
                            className={[
                                "rounded-xl px-4 py-2 font-semibold",
                                "border border-white/20",
                                !sessionToken || loading
                                    ? "bg-white/5 text-white/60 cursor-not-allowed"
                                    : "bg-white/5 hover:bg-white/10",
                                "transition-colors",
                            ].join(" ")}
                            title={!sessionToken ? "Pair the UI first" : "Refresh pairing status"}
                        >
                            Refresh
                        </button>
                    </div>

                    <div className="text-xs text-center min-h-[18px]">
                        {statusErr ? <span className="text-red-300">{statusErr}</span> : null}
                        {!statusErr && sessionToken && paired === true ? (
                            <span className="text-green-300">Extension paired</span>
                        ) : null}
                        {!statusErr && sessionToken && paired === false ? (
                            <span className="text-white/60">Extension not paired yet</span>
                        ) : null}
                        {!statusErr && !sessionToken ? (
                            <span className="text-white/60">No session: start the client and pair the UI first</span>
                        ) : null}
                    </div>
                </div>

                <div>
                    <div className="text-xs text-white/60 mb-2">Pairing token</div>

                    <div className="flex items-center gap-2 rounded-2xl border border-white/15 bg-white/5 p-3">
                        <input
                            id="qa_pair_token_input"
                            value={token}
                            readOnly
                            placeholder="Click “Generate token”"
                            className={[
                                "flex-1",
                                "bg-transparent",
                                "outline-none",
                                "text-sm",
                                "font-mono",
                                token ? "text-white" : "text-white/60",
                            ].join(" ")}
                        />

                        <button
                            onClick={copyToken}
                            disabled={!token}
                            title={token ? "Copy to clipboard" : "Generate a token first"}
                            className={[
                                "inline-flex items-center justify-center",
                                "w-10 h-9 rounded-xl",
                                "border border-white/20",
                                token ? "bg-white/10 hover:bg-white/15" : "bg-white/5 cursor-not-allowed opacity-60",
                                "transition-colors",
                            ].join(" ")}
                        >
                            <CopyIcon />
                        </button>
                    </div>

                    <div className="mt-2 min-h-[18px] text-xs">
                        {error ? <span className="text-red-300">{error}</span> : null}
                        {!error && copied ? <span className="text-green-300">Copied</span> : null}
                    </div>
                </div>
            </div>
        </CollapsibleSection>
    );
}
