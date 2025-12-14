import type { ApiResult } from "./types";
import { apiUrl } from "./apiBase";

export async function apiFetch<T>(
    path: string,
    init?: RequestInit
): Promise<ApiResult<T>> {
    const res = await fetch(apiUrl(path), {
        ...init,
        headers: {
            Accept: "application/json",
            ...(init?.headers ?? {}),
        },
        credentials: "omit",
    });

    if (!res.ok) {
        return {
            ok: false,
            status: res.status,
            error: await res.text().catch(() => res.statusText),
            headers: res.headers,
        };
    }

    const ct = res.headers.get("content-type") ?? "";
    const data =
        res.status === 204 || !ct.includes("application/json")
            ? (undefined as T)
            : ((await res.json()) as T);

    return {
        ok: true,
        status: res.status,
        data,
        headers: res.headers,
    };
}
