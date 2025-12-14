export type StatusResp = {
    ok: boolean;
    version?: string;
    tpm?: { ok: boolean; detail?: string };
};

export type ExchangeResp = {
    token: string;
    header?: string;
};

// Example for your validate endpoint (edit fields to match server)
export type SessionValidateResp = {
    ok: boolean;
    subject?: string;
    expiresAt?: string;
};
