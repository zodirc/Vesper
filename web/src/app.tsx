import { createContext, useContext, useMemo, useState, type FormEvent } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { ApiError, createClient, type Client } from "./api";
import { loadSession, saveSession, when, type Session } from "./model";
import { AssetsPage, FindingsPage, GrantsPage, IntelPage, LibraryPage, OverviewPage, ScansPage, ServicesPage } from "./pages";

interface SessionState {
  session: Session;
  client: Client;
  logout: () => Promise<void>;
}

const SessionContext = createContext<SessionState | null>(null);

export function useSession(): SessionState {
  const value = useContext(SessionContext);
  if (!value) {
    throw new Error("session is missing");
  }
  return value;
}

export function App() {
  const [session, setSession] = useState<Session | null>(() => loadSession());
  const client = useMemo(() => createClient(session?.token ?? null, () => {
    saveSession(null);
    setSession(null);
  }), [session?.token]);

  if (!session) {
    return <Login onLogin={(next) => { saveSession(next); setSession(next); }} />;
  }

  async function logout() {
    try {
      await client.request("DELETE", "/api/v1/sessions");
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 401) {
        saveSession(null);
        setSession(null);
        return;
      }
    }
    saveSession(null);
    setSession(null);
  }

  return (
    <SessionContext.Provider value={{ session, client, logout }}>
      <div className="shell">
        <nav className="nav">
          <strong>Vesper</strong>
          <NavLink to="/" end>概览</NavLink>
          <NavLink to="/grants">授权</NavLink>
          <NavLink to="/scans">扫描</NavLink>
          <NavLink to="/assets">资产</NavLink>
          <NavLink to="/services">服务</NavLink>
          <NavLink to="/findings">风险</NavLink>
          <NavLink to="/library">规则与模板</NavLink>
          <NavLink to="/intel">情报</NavLink>
          <button type="button" onClick={() => void logout()}>退出</button>
        </nav>
        <main className="main">
          <div className="top">
            <span className="muted">会话到期 {when(session.expiresAt)}</span>
          </div>
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/grants" element={<GrantsPage />} />
            <Route path="/scans" element={<ScansPage />} />
            <Route path="/scans/:id" element={<ScansPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/services" element={<ServicesPage />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/findings/:id" element={<FindingsPage />} />
            <Route path="/library" element={<LibraryPage />} />
            <Route path="/intel" element={<IntelPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </SessionContext.Provider>
  );
}

function Login({ onLogin }: { onLogin: (session: Session) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const client = useMemo(() => createClient(null, () => undefined), []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      const created = await client.request<{ token: string; expires_at: string }>("POST", "/api/v1/sessions", { username, password });
      onLogin({ token: created.token, expiresAt: created.expires_at });
    } catch (err) {
      setError(err);
    }
  }

  return (
    <div className="login">
      <form onSubmit={(event) => void submit(event)}>
        <h1>Vesper</h1>
        <p className="muted">本地管理入口。口令只发往本机控制服务。</p>
        <label>用户名<input autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} /></label>
        <label>口令<input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        <Notice error={error} />
        <button className="primary" type="submit">登录</button>
      </form>
    </div>
  );
}

export function Notice({ error, text }: { error?: unknown; text?: string }) {
  if (text) {
    return <p className="ok">{text}</p>;
  }
  if (!error) {
    return null;
  }
  const message = error instanceof ApiError ? `${error.code}: ${error.message}` : error instanceof Error ? error.message : "请求失败";
  return <p className="error" role="alert">{message}</p>;
}
