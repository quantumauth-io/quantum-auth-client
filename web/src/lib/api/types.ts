export type ApiOk<T> = {
    ok: true;
    status: number;
    data: T;
    headers: Headers;
};

export type ApiErr = {
    ok: false;
    status: number;
    error: string;
    headers: Headers;
};

export type ApiResult<T> = ApiOk<T> | ApiErr;

export function isApiOk<T>(r: ApiResult<T>): r is ApiOk<T> {
    return r.ok;
}

export function isApiErr<T>(r: ApiResult<T>): r is ApiErr {
    return !r.ok;
}
