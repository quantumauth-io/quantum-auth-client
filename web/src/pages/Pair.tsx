import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";

import { apiFetch } from "../lib/api";
import type { ApiResult } from "../lib/api";

type ExchangeResp = {
    token: string;
    header?: string;
};

const SESSION_KEY = "qa_session_token";

function safeServer(raw: string | null) {
    // lock to localhost to avoid someone passing a malicious server URL
    const allowed = new Set(["http://127.0.0.1:6137", "http://localhost:6137"]);
    if (!raw) return "http://127.0.0.1:6137";
    try {
        const u = new URL(raw);
        const norm = `${u.protocol}//${u.hostname}${u.port ? `:${u.port}` : ""}`;
        if (allowed.has(norm)) return norm;
    } catch {}
    return "http://127.0.0.1:6137";
}

function getHashQueryParams(): URLSearchParams {
    const hash = window.location.hash || ""; // "#/pair?x=1&y=2"
    const idx = hash.indexOf("?");
    if (idx === -1) return new URLSearchParams();
    return new URLSearchParams(hash.slice(idx + 1));
}

export default function PairPage() {
    const nav = useNavigate();
    const [status, setStatus] = useState<"working" | "ok" | "error">("working");
    const [msg, setMsg] = useState("Pairing with local QuantumAuth client…");

    const ran = useRef(false);

    useEffect(() => {
        if (ran.current) return;
        ran.current = true;

        let alive = true;

        (async () => {
            const qs = getHashQueryParams();
            const pair_id = qs.get("pair_id") ?? "";
            const code = qs.get("code") ?? "";
            const server = safeServer(qs.get("server"));

            if (!pair_id || !code) {
                if (!alive) return;
                setStatus("error");
                setMsg("Missing pair_id or code in URL.");
                return;
            }

            let res: ApiResult<ExchangeResp>;
            try {
                // Note: apiFetch uses VITE_API_BASE for relative paths.
                // Here we want an explicit host from the CLI link, so we pass an absolute URL.
                res = await apiFetch<ExchangeResp>(`${server}/pair/exchange`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ pair_id, code }),
                });
            } catch {
                if (!alive) return;
                setStatus("error");
                setMsg(`Could not reach local client at ${server}. Is it running?`);
                return;
            }

            if (!alive) return;

            if (!res.ok) {
                setStatus("error");
                setMsg(
                    res.status === 410
                        ? "Pairing code expired. Go back to the client and generate a new link."
                        : `Pairing failed (HTTP ${res.status}). ${res.error}`.trim()
                );
                return;
            }

            // store token
            localStorage.setItem(SESSION_KEY, res.data.token);

            // clear URL so code isn't left in history (keep same route)
            // If you use hash routing, use window.location.hash = "#/pair" instead.
            window.history.replaceState({}, document.title, "/pair");

            setStatus("ok");
            setMsg("Paired! Redirecting…");

            nav("/", { replace: true });
        })();

        return () => {
            alive = false;
        };
    }, [nav]);

    return (
        <div style={{ padding: 24 }}>
            <h1>QuantumAuth Pairing</h1>
            <p>{msg}</p>

            {status === "error" && (
                <div style={{ marginTop: 16 }}>
                    <button onClick={() => window.location.reload()}>Retry</button>
                </div>
            )}
        </div>
    );
}
