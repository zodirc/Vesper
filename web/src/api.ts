export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export interface Client {
  request<T>(method: string, path: string, body?: unknown): Promise<T>;
}

export function createClient(token: string | null, onUnauthorized: () => void): Client {
  return {
    async request<T>(method: string, path: string, body?: unknown): Promise<T> {
      const headers: Record<string, string> = {};
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }
      if (body !== undefined) {
        headers["Content-Type"] = "application/json";
      }
      const response = await fetch(path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      if (response.status === 401) {
        onUnauthorized();
      }
      const text = await response.text();
      const payload = text === "" ? null : JSON.parse(text) as { error?: { code?: string; message?: string } };
      if (!response.ok) {
        throw new ApiError(response.status, payload?.error?.code ?? "request_failed", payload?.error?.message ?? response.statusText);
      }
      return payload as T;
    },
  };
}
