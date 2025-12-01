export type Role = "admin" | "user" | "guard";

export type Vehicle = {
  id: string;
  plate: string;
  make?: string;
  model?: string;
  owner_name: string;
  owner_unit?: string;
  owner_phone?: string;
  status: "active" | "inactive" | string;
  created_at?: string;
  expires_at?: string | null;
};

export type CheckResponse =
  | { approved: true; vehicle: Vehicle }
  | { approved: false; message?: string };

export type Paginated<T> = {
  items: T[];
  total: number;
  page: number;
  limit: number;
};

// Use environment variable if set, otherwise default to /api
const API_BASE = (import.meta as any).env?.VITE_API_BASE_URL || "";

export type User = {
  id: number;
  username: string;
  role: "admin" | "guard";
  active: boolean;
  first_name?: string | null;
  last_name?: string | null;
};

export type LoginResponse = {
  username: string;
  role: Role;
};

function getRoleHeader() {
  try {
    const raw = localStorage.getItem("s24_auth");
    if (!raw) return {};
    const auth = JSON.parse(raw) as { role?: Role };
    return auth?.role ? { "x-role": auth.role } : {};
  } catch {
    return {};
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  // Ensure the path starts with a slash and doesn't have duplicate slashes
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const url = API_BASE ? `${API_BASE}${normalizedPath}` : normalizedPath;
  
  const res = await fetch(url, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init.headers || {}),
      ...getRoleHeader(),
    },
    ...init,
  });
  const contentType = res.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) {
    const detail = (body as any)?.detail || (typeof body === "string" ? body : "Request failed");
    throw new Error(detail);
  }
  return body as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<LoginResponse>('/api/login', {
      method: "POST",
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    }),
  users: {
    list: () => request<{ items: User[] }>('/api/users'),
    create: (payload: { username: string; password: string; role: "admin" | "guard"; first_name?: string; last_name?: string }) =>
      request<User>('/api/users', {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    toggleActive: (id: number) =>
      request<{ id: number; active: boolean }>(`/api/users/${id}/toggle`, {
        method: "PATCH",
      }),
  },
  check: (code: string) => request<CheckResponse>(`/api/check/${encodeURIComponent(code)}`),
  qr: (vehicleId: string) => request<{ qr: string }>(`/api/qrcode/${encodeURIComponent(vehicleId)}`),
  vehicles: {
    listAll: () => request<Vehicle[]>('/api/vehicles'),
    list: (params: { page?: number; limit?: number; q?: string; status?: Vehicle["status"] } = {}) => {
      const usp = new URLSearchParams();
      if (params.page) usp.set("page", String(params.page));
      if (params.limit) usp.set("limit", String(params.limit));
      if (params.q) usp.set("q", params.q);
      if (params.status) usp.set("status", params.status);
      const qs = usp.toString();
      return request<Paginated<Vehicle>>(`/api/vehicles${qs ? `?${qs}` : ""}`);
    },
    create: (payload: Omit<Vehicle, 'id' | 'created_at'>) => request<{ message: string; id: string }>('/api/vehicles', {
      method: "POST",
      body: JSON.stringify(payload),
    }),
    update: (id: string, payload: Partial<Omit<Vehicle, 'id' | 'created_at'>>) => request<Vehicle>(`/api/vehicles/${encodeURIComponent(id)}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
    delete: (id: string) => request<{ message: string }>(`/api/vehicles/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
    toggleActive: (id: string) => request<{ id: string; status: Vehicle["status"]}>(`/api/vehicles/${encodeURIComponent(id)}/toggle`, {
      method: "PATCH",
    }),
  },
};
