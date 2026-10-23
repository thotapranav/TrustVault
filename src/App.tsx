import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { createClient } from "@supabase/supabase-js";
import type { Session } from "@supabase/supabase-js";
import {
  Activity, ArrowDownToLine, ArrowRight, Bell, Check, Clock3, Eye,
  FileCheck2, FileClock, FileText, Files, FolderOpen, LayoutDashboard,
  LoaderCircle, LockKeyhole, LogOut, Plus, Search, ShieldCheck, Upload,
  UserRound, Users, X,
} from "lucide-react";

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;
type Role = "admin" | "owner" | "viewer";
type Page = "overview" | "documents" | "upload" | "activity" | "sharing" | "users";
type Document = {
  id: string; title: string; description: string | null; original_filename: string;
  category: string; owner_id: string; mime_type: string; size_bytes: number; created_at: string;
  permission: "read" | "edit"; owned: boolean;
};
type AuditEvent = {
  id: number; actor_id: string | null; action: string; outcome: string; created_at: string;
  document_id: string | null; details: Record<string, unknown>;
};
type UserProfile = { id: string; email: string; display_name: string | null; role?: Role };
type ShareRequest = {
  action: "grant" | "revoke";
  document_id: string;
  permission?: "read" | "edit";
  user_id?: string;
  all_users?: boolean;
};
type Preview = { document: Document; url: string };
type Notice = { text: string; kind: "success" | "error" | "info" };

const navigation: { id: Page; label: string; icon: typeof LayoutDashboard }[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "documents", label: "My documents", icon: Files },
  { id: "upload", label: "Upload a document", icon: Upload },
  { id: "activity", label: "Activity history", icon: Clock3 },
  { id: "sharing", label: "Sharing", icon: Users },
  { id: "users", label: "User management", icon: UserRound },
];

const actionLabels: Record<string, string> = {
  upload: "Document uploaded",
  download: "Document downloaded",
  grant: "Document shared",
  revoke: "Access revoked",
  preview: "Document previewed",
  role_change: "User role changed",
};

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function formatSize(bytes: number) {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function initials(email?: string) {
  return email?.split("@")[0]?.slice(0, 2).toUpperCase() || "TV";
}

export default function App() {
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY || SUPABASE_ANON_KEY.startsWith("<")) {
    return <SetupScreen />;
  }
  return <TrustVault url={SUPABASE_URL} anonKey={SUPABASE_ANON_KEY} />;
}

function SetupScreen() {
  return (
    <main className="setup-screen">
      <div className="setup-card">
        <span className="brand-mark"><ShieldCheck size={24} /></span>
        <p className="eyebrow">TRUSTVAULT SETUP</p>
        <h1>Connect your secure workspace</h1>
        <p className="muted">Add your local Supabase credentials to connect sign-in, document storage and activity history.</p>
        <div className="setup-step"><span>1</span><div><b>Start Supabase</b><code>supabase start</code></div></div>
        <div className="setup-step"><span>2</span><div><b>Create your database</b><code>supabase db reset</code></div></div>
        <div className="setup-step"><span>3</span><div><b>Configure the app</b><code>Copy .env.example to .env and add your Supabase anon key.</code></div></div>
        <p className="setup-foot"><LockKeyhole size={15} /> Never put your service-role key in this frontend.</p>
      </div>
    </main>
  );
}

function TrustVault({ url, anonKey }: { url: string; anonKey: string }) {
  const supabase = useMemo(() => createClient(url, anonKey), [url, anonKey]);
  const [session, setSession] = useState<Session | null | undefined>(undefined);
  const [page, setPage] = useState<Page>("overview");
  const [role, setRole] = useState<Role>("viewer");
  const [documents, setDocuments] = useState<Document[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [loadingData, setLoadingData] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [search, setSearch] = useState("");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  useEffect(() => () => {
    if (preview) URL.revokeObjectURL(preview.url);
  }, [preview]);

  useEffect(() => {
    let active = true;
    supabase.auth.getSession().then(({ data, error }) => {
      if (!active) return;
      if (error) setNotice({ text: "Could not restore your session. Please sign in again.", kind: "error" });
      setSession(data.session);
    });
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, newSession) => {
      if (active) setSession(newSession);
    });
    return () => { active = false; subscription.unsubscribe(); };
  }, [supabase]);

  const refresh = useCallback(async () => {
    if (!session) return;
    setLoadingData(true);
    const [profileResult, documentsResult, grantsResult, eventsResult] = await Promise.all([
      supabase.from("profiles").select("role").eq("id", session.user.id).maybeSingle(),
      supabase.from("documents")
        .select("id,title,description,original_filename,category,owner_id,mime_type,size_bytes,created_at")
        .order("created_at", { ascending: false }).range(0, 99),
      supabase.from("document_permissions").select("document_id,permission")
        .eq("user_id", session.user.id).is("revoked_at", null),
      supabase.from("audit_events")
        .select("id,actor_id,action,outcome,created_at,document_id,details")
        .order("created_at", { ascending: false }).range(0, 99),
    ]);
    if (profileResult.error) {
      setNotice({ text: "Could not load your account details.", kind: "error" });
    } else if (profileResult.data?.role === "admin" || profileResult.data?.role === "owner" || profileResult.data?.role === "viewer") {
      setRole(profileResult.data.role);
    }
    if (documentsResult.error) {
      setNotice({ text: "Could not load documents. Check your Supabase connection and permissions.", kind: "error" });
    } else {
      const permissions = new Map((grantsResult.data ?? []).map((grant) => [grant.document_id, grant.permission]));
      setDocuments((documentsResult.data ?? []).map((document) => ({
        ...document,
        permission: document.owner_id === session.user.id ? "edit" : permissions.get(document.id) ?? "read",
        owned: document.owner_id === session.user.id,
      })) as Document[]);
    }
    if (grantsResult.error) setNotice({ text: "Could not load document permissions.", kind: "error" });
    if (eventsResult.error) {
      setNotice({ text: "Could not load activity history.", kind: "error" });
    } else {
      setEvents((eventsResult.data ?? []) as AuditEvent[]);
    }
    setLoadingData(false);
  }, [session, supabase]);

  useEffect(() => {
    if (!session) {
      setRole("viewer");
      setDocuments([]);
      setEvents([]);
      setPreview(null);
      return;
    }
    void refresh();
  }, [session, refresh]);

  async function signIn(email: string, password: string) {
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw error;
  }

  async function signUp(email: string, password: string) {
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) throw error;
    if (!data.session) {
      setNotice({ text: "Account created. Check your email to confirm your address, then sign in.", kind: "success" });
    }
  }

  async function resetPassword(email: string) {
    const { error } = await supabase.auth.resetPasswordForEmail(email, { redirectTo: window.location.origin });
    if (error) throw error;
    setNotice({ text: "Password reset instructions have been sent if that email is registered.", kind: "success" });
  }

  async function downloadDocument(document: Document) {
    if (!session) return;
    setNotice(null);
    try {
      const response = await fetch(`${url}/functions/v1/document-download?id=${encodeURIComponent(document.id)}`, {
        headers: { Authorization: `Bearer ${session.access_token}` },
      });
      if (!response.ok) {
        setNotice({ text: response.status === 403 ? "You no longer have download access to this document." : "Download failed. Please try again.", kind: "error" });
        return;
      }
      const objectUrl = URL.createObjectURL(await response.blob());
      const link = window.document.createElement("a");
      link.href = objectUrl;
      link.download = document.original_filename;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      setNotice({ text: "Your secure download has started.", kind: "success" });
      void refresh();
    } catch {
      setNotice({ text: "Could not reach the document service. Check that Supabase functions are running.", kind: "error" });
    }
  }

  async function previewDocument(document: Document) {
    if (!session) return;
    setNotice(null);
    try {
      const response = await fetch(`${url}/functions/v1/document-preview?id=${encodeURIComponent(document.id)}`, {
        headers: { Authorization: `Bearer ${session.access_token}` },
      });
      if (!response.ok) {
        setNotice({ text: response.status === 403 ? "You no longer have access to this document." : "Preview failed. Please try again.", kind: "error" });
        return;
      }
      setPreview({ document, url: URL.createObjectURL(await response.blob()) });
      void refresh();
    } catch {
      setNotice({ text: "Could not reach the document preview service. Check that Supabase functions are running.", kind: "error" });
    }
  }

  async function uploadDocument(formData: FormData) {
    if (!session) return;
    setNotice(null);
    let response: Response;
    try {
      response = await fetch(`${url}/functions/v1/document-upload`, {
        method: "POST",
        headers: { Authorization: `Bearer ${session.access_token}` },
        body: formData,
      });
    } catch (reason) {
      if (reason instanceof TypeError) {
        throw new Error("Could not reach the upload service. Ensure Supabase Functions are running and allow this app's local origin.");
      }
      throw reason;
    }
    if (!response.ok) {
      const text = response.status === 404 ? "The document-upload function is not deployed to the configured Supabase project. Deploy the Edge Function, then try again." :
        response.status === 413 ? "That file is too large. The maximum size is 10 MB." :
        response.status === 415 ? "Only PDF, PNG and JPEG files are supported." :
        `Upload failed (HTTP ${response.status}). Check the Supabase function logs and try again.`;
      throw new Error(text);
    }
    setNotice({ text: "Document uploaded securely.", kind: "success" });
    setPage("documents");
    await refresh();
  }

  async function shareDocument(payload: ShareRequest) {
    if (!session) return;
    const response = await fetch(`${url}/functions/v1/document-grant`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.access_token}`, "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const message = response.status === 403 ? "Only the document owner can change its sharing permissions." :
        response.status === 422 ? "Choose another registered user. You cannot share a document with yourself." :
        "Could not update sharing. Check the selected document and try again.";
      throw new Error(message);
    }
    setNotice({ text: payload.action === "grant" ? "Document access granted." : "Document access revoked.", kind: "success" });
    await refresh();
  }

  async function searchUsers(query: string): Promise<UserProfile[]> {
    if (!session) return [];
    const response = await fetch(`${url}/functions/v1/users-search?q=${encodeURIComponent(query)}`, {
      headers: { Authorization: `Bearer ${session.access_token}` },
    });
    if (!response.ok) throw new Error(response.status === 400 ? "Enter at least two characters to search." : "Could not search users.");
    const result = await response.json() as { users: UserProfile[] };
    return result.users;
  }

  async function updateUserRole(userId: string, nextRole: Role) {
    if (!session) return;
    const response = await fetch(`${url}/functions/v1/user-role`, {
      method: "POST",
      headers: { Authorization: `Bearer ${session.access_token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: userId, role: nextRole }),
    });
    if (!response.ok) {
      throw new Error(response.status === 403 ? "Only an administrator can change user roles." : "Could not update this user's role.");
    }
    setNotice({ text: "User role updated and recorded in the audit history.", kind: "success" });
    await refresh();
  }

  async function signOut() {
    const { error } = await supabase.auth.signOut();
    if (error) setNotice({ text: "Could not sign out. Please try again.", kind: "error" });
  }

  if (session === undefined) {
    return <main className="loading-screen"><LoaderCircle className="spin" size={26} /><span>Opening your secure workspace…</span></main>;
  }
  if (!session) {
    return <AuthScreen onSignIn={signIn} onSignUp={signUp} onResetPassword={resetPassword} notice={notice} />;
  }

  const ownDocuments = documents.filter((document) => document.owner_id === session.user.id);
  const visibleDocuments = documents.filter((document) => {
    const text = `${document.title} ${document.original_filename} ${document.category}`.toLowerCase();
    return text.includes(search.trim().toLowerCase());
  });
  const pageTitles: Record<Page, string> = {
    overview: "Overview", documents: "My documents", upload: "Upload a document",
    activity: "Activity history", sharing: "Sharing", users: "User management",
  };

  function navigate(nextPage: Page) {
    setPage(nextPage);
    setNotice(null);
    setMobileNavOpen(false);
  }

  return (
    <div className="app-shell">
      {mobileNavOpen && <button className="mobile-backdrop" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
      <aside className={`sidebar${mobileNavOpen ? " sidebar-open" : ""}`}>
        <a className="brand" href="#" onClick={(event) => { event.preventDefault(); navigate("overview"); }}>
          <span className="brand-mark"><ShieldCheck size={22} /></span>
          <span>Trust<span className="brand-light">Vault</span><small>PRIVATE DOCUMENTS</small></span>
        </a>
        <span className="nav-caption">WORKSPACE</span>
        <nav className="side-nav" aria-label="Main navigation">
          {navigation.filter(({ id }) => id !== "users" || role === "admin").map(({ id, label, icon: Icon }) => {
            const disabled = id === "sharing" && ownDocuments.length === 0;
            return (
              <button key={id} className={`nav-link${page === id ? " nav-link-active" : ""}`}
                disabled={disabled} onClick={() => navigate(id)}>
                <Icon size={19} strokeWidth={1.8} /><span>{label}</span>
                {id === "documents" && <span className="nav-count">{documents.length}</span>}
              </button>
            );
          })}
        </nav>
        <div className="sidebar-spacer" />
        <div className="security-note"><LockKeyhole size={17} /><div><b>Your files stay private</b><span>Encrypted storage. Controlled access.</span></div></div>
        <button className="profile-card" onClick={() => void signOut()}>
          <span className="avatar">{initials(session.user.email)}</span>
          <span className="profile-info"><b>{session.user.email?.split("@")[0]}</b><small>{role}</small></span>
          <LogOut size={17} className="profile-logout" />
        </button>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <button className="mobile-menu" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)}><Files size={21} /></button>
          <div className="breadcrumb">Workspace <span>/</span> <b>{pageTitles[page]}</b></div>
          <div className="topbar-right">
            <span className="secure-status"><span /> Secure workspace</span>
            <span className="avatar avatar-small">{initials(session.user.email)}</span>
          </div>
        </header>

        <div className="page-content">
          {notice && <div role={notice.kind === "error" ? "alert" : "status"} className={`notice notice-${notice.kind}`}>
            {notice.kind === "success" ? <Check size={18} /> : notice.kind === "error" ? <X size={18} /> : <Bell size={18} />}
            <span>{notice.text}</span><button aria-label="Dismiss message" onClick={() => setNotice(null)}><X size={16} /></button>
          </div>}
          {page === "overview" && <OverviewPage
            email={session.user.email ?? ""} userId={session.user.id} role={role} documents={documents} events={events} loading={loadingData}
            onNavigate={navigate} onPreview={previewDocument} />}
          {page === "documents" && <DocumentsPage
            documents={visibleDocuments} search={search} onSearch={setSearch} canUpload onUpload={() => navigate("upload")}
            onPreview={previewDocument} onDownload={downloadDocument} />}
          {page === "upload" && <UploadPage disabled={false} onUpload={uploadDocument} />}
          {page === "activity" && <ActivityPage events={events} documents={documents} loading={loadingData} isAdmin={role === "admin"} />}
          {page === "sharing" && <SharingPage documents={ownDocuments} onShare={shareDocument} onSearchUsers={searchUsers} />}
          {page === "users" && role === "admin" && <UserManagementPage onSearchUsers={searchUsers} onUpdateRole={updateUserRole} />}
        </div>
        <footer className="app-footer"><span>TrustVault</span><span>Private by design <ShieldCheck size={14} /></span></footer>
      </main>
      {preview && <PreviewDialog preview={preview} onClose={() => setPreview(null)} />}
    </div>
  );
}

function AuthScreen({ onSignIn, onSignUp, onResetPassword, notice }: {
  onSignIn: (email: string, password: string) => Promise<void>;
  onSignUp: (email: string, password: string) => Promise<void>;
  onResetPassword: (email: string) => Promise<void>;
  notice: Notice | null;
}) {
  const [mode, setMode] = useState<"signin" | "signup" | "reset">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (mode === "signin") await onSignIn(email, password);
      else if (mode === "signup") await onSignUp(email, password);
      else await onResetPassword(email);
      if (mode === "reset") setMode("signin");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Authentication failed. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  const isReset = mode === "reset";
  return (
    <main className="auth-screen">
      <section className="auth-art">
        <a className="brand brand-on-dark" href="#"><span className="brand-mark"><ShieldCheck size={22} /></span>
          <span>Trust<span className="brand-light">Vault</span><small>PRIVATE DOCUMENTS</small></span></a>
        <div className="auth-art-content">
          <div className="art-orbit orbit-one" /><div className="art-orbit orbit-two" />
          <div className="art-icon"><FileCheck2 size={40} strokeWidth={1.5} /></div>
          <p className="eyebrow">YOUR DOCUMENTS. YOUR CONTROL.</p>
          <h1>A safer place<br />for what matters.</h1>
          <p>Securely store, organize and share sensitive documents with the people you trust.</p>
        </div>
        <div className="auth-art-footer"><span><LockKeyhole size={15} /> End-to-end access control</span><span>TRUSTED STORAGE</span></div>
      </section>
      <section className="auth-form-panel">
        <div className="auth-mobile-brand"><span className="brand-mark"><ShieldCheck size={21} /></span>TrustVault</div>
        <div className="auth-form-wrap">
          <p className="eyebrow">{isReset ? "ACCOUNT RECOVERY" : mode === "signup" ? "CREATE YOUR ACCOUNT" : "WELCOME BACK"}</p>
          <h2>{isReset ? "Reset your password" : mode === "signup" ? "Create your account" : "Sign in to TrustVault"}</h2>
          <p className="muted">{isReset ? "We’ll send a reset link to your email address." : mode === "signup" ? "Get started with your secure document workspace." : "Your secure workspace is just a sign-in away."}</p>
          {(notice || error) && <div role={error ? "alert" : "status"} className={`notice ${error ? "notice-error" : `notice-${notice?.kind ?? "info"}`}`}>
            {error || notice?.text}
          </div>}
          <form className="auth-form" onSubmit={submit}>
            <label htmlFor="auth-email">Email address</label>
            <div className="input-icon"><UserRound size={18} /><input id="auth-email" type="email" autoComplete="email"
              placeholder="you@example.com" value={email} onChange={(event) => setEmail(event.target.value)} required /></div>
            {!isReset && <>
              <div className="password-label"><label htmlFor="auth-password">Password</label>
                {mode === "signin" && <button type="button" onClick={() => { setError(""); setMode("reset"); }}>Forgot password?</button>}</div>
              <div className="input-icon"><LockKeyhole size={18} /><input id="auth-password" type="password"
                autoComplete={mode === "signup" ? "new-password" : "current-password"} placeholder="At least 8 characters"
                minLength={8} value={password} onChange={(event) => setPassword(event.target.value)} required /></div>
            </>}
            <button className="button-primary auth-submit" disabled={busy}>
              {busy ? <LoaderCircle size={18} className="spin" /> : null}
              {busy ? "Please wait…" : isReset ? "Send reset link" : mode === "signup" ? "Create account" : "Sign in"}
              {!busy && !isReset && <ArrowRight size={17} />}
            </button>
          </form>
          <p className="auth-switch">
            {isReset ? <button onClick={() => { setError(""); setMode("signin"); }}>Back to sign in</button> :
              mode === "signup" ? <>Already have an account? <button onClick={() => { setError(""); setMode("signin"); }}>Sign in</button></> :
              <>New to TrustVault? <button onClick={() => { setError(""); setMode("signup"); }}>Create an account</button></>}
          </p>
          <div className="auth-assurance"><ShieldCheck size={16} /> Your data is protected by secure, permission-based access.</div>
        </div>
      </section>
    </main>
  );
}

function OverviewPage({ email, userId, role, documents, events, loading, onNavigate, onPreview }: {
  email: string; userId: string; role: Role; documents: Document[]; events: AuditEvent[]; loading: boolean;
  onNavigate: (page: Page) => void; onPreview: (document: Document) => void;
}) {
  const recent = documents.slice(0, 4);
  const recentEvents = events.slice(0, 4);
  const ownedCount = documents.filter((document) => document.owner_id === userId).length;
  return (
    <>
      <section className="welcome-banner">
        <div><p className="eyebrow">YOUR PRIVATE WORKSPACE</p><h1>Good to see you, {email.split("@")[0]}.</h1>
          <p>Keep your important documents organized, secure and within reach.</p></div>
        <button className="button-primary" onClick={() => onNavigate("upload")}>
          <Plus size={18} /> Upload document
        </button>
        <div className="welcome-decoration"><ShieldCheck size={118} strokeWidth={0.8} /></div>
      </section>
      <section className="stat-grid" aria-label="Workspace statistics">
        <StatCard icon={<Files size={20} />} label="Available documents" value={documents.length} detail="Documents you can access" />
        <StatCard icon={<FolderOpen size={20} />} label="Your uploads" value={ownedCount} detail="Owned in your workspace" />
        <StatCard icon={<Activity size={20} />} label="Recent activity" value={events.length} detail="Recorded securely" />
        <StatCard icon={<ShieldCheck size={20} />} label="Workspace security" value="Active" detail="Access checks enabled" secure />
      </section>
      <div className="content-grid">
        <section className="panel">
          <div className="section-heading"><div><h2>Recent documents</h2><p>Your latest secure files</p></div>
            <button className="text-button" onClick={() => onNavigate("documents")}>View all <ArrowRight size={15} /></button></div>
          {loading && documents.length === 0 ? <LoadingInline /> : recent.length === 0 ? <EmptyState icon={<Files size={22} />}
            title="No documents yet" description="Upload a document or view documents shared with you."
            action={<button className="text-button" onClick={() => onNavigate("upload")}>Upload a document <ArrowRight size={15} /></button>} /> :
            <div className="document-list">{recent.map((document) => <DocumentRow key={document.id} document={document} onPreview={onPreview} />)}</div>}
        </section>
        <section className="panel activity-panel">
          <div className="section-heading"><div><h2>Recent activity</h2><p>Latest workspace events</p></div>
            <button className="icon-button" aria-label="View activity history" onClick={() => onNavigate("activity")}><ArrowRight size={18} /></button></div>
          {recentEvents.length === 0 ? <EmptyState icon={<FileClock size={22} />} title="No activity yet" description="Document actions will be recorded here." /> :
            <ActivityList events={recentEvents} documents={documents} />}
        </section>
      </div>
      <section className="privacy-banner"><div className="privacy-icon"><LockKeyhole size={20} /></div>
        <div><b>Privacy is built into every step</b><p>Your access is verified for every document request. Shared access can be revoked by the document owner.</p></div>
        <ShieldCheck size={30} className="privacy-shield" />
      </section>
    </>
  );
}

function StatCard({ icon, label, value, detail, secure = false }: { icon: ReactNode; label: string; value: string | number; detail: string; secure?: boolean }) {
  return <div className="stat-card"><span className={`stat-icon${secure ? " stat-icon-green" : ""}`}>{icon}</span>
    <span className="stat-label">{label}</span><strong className={secure ? "stat-secure" : ""}>{value}</strong>
    <span className="stat-detail">{detail}</span></div>;
}

function DocumentsPage({ documents, search, onSearch, canUpload, onUpload, onPreview, onDownload }: {
  documents: Document[]; search: string; onSearch: (value: string) => void;
  canUpload: boolean; onUpload: () => void; onPreview: (document: Document) => void; onDownload: (document: Document) => void;
}) {
  return <>
    <PageHeading eyebrow="YOUR SECURE LIBRARY" title="My documents" description="Preview documents you can access. Download is available only to owners and users with edit permission."
      action={canUpload ? <button className="button-primary" onClick={onUpload}><Plus size={18} /> Upload document</button> : undefined} />
    <section className="panel">
      <div className="library-toolbar"><div className="search-field"><Search size={18} /><input aria-label="Search documents" placeholder="Search by title, filename or category…"
        value={search} onChange={(event) => onSearch(event.target.value)} />{search && <button aria-label="Clear search" onClick={() => onSearch("")}><X size={16} /></button>}</div>
        <span className="result-count">{documents.length} {documents.length === 1 ? "document" : "documents"}</span></div>
      {documents.length === 0 ? <EmptyState icon={<Files size={23} />} title={search ? "No matching documents" : "Your library is empty"}
        description={search ? "Try another search term." : "Files you upload or that are shared with you will appear here."}
        action={search || !canUpload ? undefined : <button className="button-secondary" onClick={onUpload}><Upload size={16} /> Upload a document</button>} /> :
        <div className="table-scroll"><table className="document-table"><thead><tr><th>DOCUMENT</th><th>CATEGORY</th><th>SIZE</th><th>ADDED</th><th>ACCESS</th><th /></tr></thead>
          <tbody>{documents.map((document) => <tr key={document.id}><td><div className="file-cell"><span className="file-icon"><FileText size={18} /></span>
            <span><b>{document.title}</b><small>{document.original_filename}</small></span></div></td><td><span className="category-pill">{document.category || "general"}</span></td>
            <td>{formatSize(document.size_bytes)}</td><td>{formatDate(document.created_at)}</td>
            <td><span className="category-pill">{document.owned ? "Owner" : document.permission === "edit" ? "Edit" : "Read only"}</span></td>
            <td className="document-actions"><button className="download-button" onClick={() => onPreview(document)}><Eye size={16} /> Preview</button>
              {document.permission === "edit" && <button className="download-button" onClick={() => onDownload(document)}><ArrowDownToLine size={16} /> Download</button>}</td></tr>)}</tbody>
        </table></div>}
    </section>
  </>;
}

function UploadPage({ disabled, onUpload }: { disabled: boolean; onUpload: (data: FormData) => Promise<void> }) {
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  function selectFile(candidate?: File) {
    if (!candidate) return;
    if (candidate.size > 10 * 1024 * 1024) {
      setFile(null);
      setError("That file is too large. The maximum size is 10 MB.");
      return;
    }
    setError("");
    setFile(candidate);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    if (!file) { setError("Choose a PDF, PNG or JPEG file first."); return; }
    setError("");
    setBusy(true);
    try {
      const data = new FormData(form);
      data.set("file", file);
      await onUpload(data);
      form.reset();
      setFile(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Upload failed. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return <>
    <PageHeading eyebrow="SECURE FILE INTAKE" title="Upload a document" description="Files are checked by the server and stored privately. Only PDF, PNG and JPEG files up to 10 MB are accepted." />
    {disabled ? <section className="panel permission-panel"><LockKeyhole size={25} /><div><h2>Administrator access required</h2>
      <p>Your account can upload documents.</p></div></section> :
      <form className="panel upload-form" onSubmit={submit}>
        {error && <div role="alert" className="notice notice-error"><X size={17} />{error}</div>}
        <div className="form-two-col"><label>Document title <span>*</span><input name="title" maxLength={200} placeholder="e.g. Service agreement" required /></label>
          <label>Category<input name="category" maxLength={60} placeholder="e.g. Contracts" defaultValue="general" /></label></div>
        <label>Description <small>Optional</small><textarea name="description" maxLength={1000} rows={3} placeholder="Add a short note about this document…" /></label>
        <label className="drop-zone" htmlFor="document-file" onDragOver={(event) => event.preventDefault()}
          onDrop={(event) => { event.preventDefault(); selectFile(event.dataTransfer.files[0]); }}>
          <span className="drop-icon"><Upload size={22} /></span>
          <b>{file ? file.name : "Choose a file to upload"}</b>
          <span>{file ? `${formatSize(file.size)} · ${file.type || "File selected"}` : "Drag a file here or click to browse"}</span>
          <small>PDF, PNG or JPEG · Maximum 10 MB</small>
          <input id="document-file" name="file" type="file" accept=".pdf,.png,.jpg,.jpeg,application/pdf,image/png,image/jpeg"
            onChange={(event) => selectFile(event.target.files?.[0])} required />
        </label>
        <div className="upload-actions"><span><LockKeyhole size={15} /> Private upload · Share only with selected users or all signed-in users</span>
          <button className="button-primary" disabled={busy || !file}>{busy ? <LoaderCircle size={17} className="spin" /> : <Upload size={17} />}{busy ? "Uploading…" : "Upload securely"}</button></div>
      </form>}
  </>;
}

function ActivityPage({ events, documents, loading, isAdmin }: { events: AuditEvent[]; documents: Document[]; loading: boolean; isAdmin: boolean }) {
  return <>
    <PageHeading eyebrow="AUDIT TRAIL" title="Activity history" description={isAdmin
      ? "Workspace-wide audit history, including the user account that performed each action and role changes."
      : "A chronological record of document uploads, previews, downloads and sharing changes visible to your account."} />
    <section className="panel history-panel"><div className="section-heading"><div><h2>Recent events</h2><p>Security events recorded by the workspace</p></div><span className="history-count">{events.length} events</span></div>
      {loading && events.length === 0 ? <LoadingInline /> : events.length === 0 ? <EmptyState icon={<FileClock size={23} />} title="No activity to show"
        description="Activity becomes available as document actions are recorded. The workspace only shows events permitted by your account." /> :
        <ActivityList events={events} documents={documents} expanded />}
    </section>
    <p className="history-note"><ShieldCheck size={16} /> Activity visibility follows the same document permissions as your workspace.</p>
  </>;
}

function ActivityList({ events, documents, expanded = false }: { events: AuditEvent[]; documents: Document[]; expanded?: boolean }) {
  const names = new Map(documents.map((document) => [document.id, document.title]));
  return <div className={`activity-list${expanded ? " activity-list-expanded" : ""}`}>{events.map((event) => {
    const success = event.outcome === "allowed";
    return <div className="activity-item" key={event.id}><span className={`activity-icon activity-${event.action}`}>
      {event.action === "upload" ? <Upload size={17} /> : event.action === "download" ? <ArrowDownToLine size={17} /> :
      event.action === "preview" ? <Eye size={17} /> : event.action === "role_change" ? <UserRound size={17} /> :
      event.action === "grant" ? <Users size={17} /> : <X size={17} />}</span>
      <div className="activity-description"><b>{actionLabels[event.action] ?? event.action}</b>
        <span>{event.document_id ? names.get(event.document_id) ?? "A document" : "Workspace"}</span>
        {expanded && <small>{event.actor_id ? `Actor ${event.actor_id}` : "System action"}{event.details.target_user ? ` · Target ${String(event.details.target_user)}` : ""}
          {event.details.new_role ? ` · Role ${String(event.details.previous_role)} → ${String(event.details.new_role)}` : ""}</small>}
        {expanded && <small className={success ? "outcome-allowed" : "outcome-denied"}>{success ? "Completed" : event.outcome}</small>}</div>
      <time dateTime={event.created_at}>{formatDate(event.created_at)}</time>
    </div>;
  })}</div>;
}

function SharingPage({ documents, onShare, onSearchUsers }: {
  documents: Document[];
  onShare: (payload: ShareRequest) => Promise<void>;
  onSearchUsers: (query: string) => Promise<UserProfile[]>;
}) {
  const [documentId, setDocumentId] = useState("");
  const [query, setQuery] = useState("");
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [recipientId, setRecipientId] = useState("");
  const [scope, setScope] = useState<"person" | "all">("person");
  const [permission, setPermission] = useState<"read" | "edit">("read");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function findUsers() {
    setError("");
    setBusy(true);
    try {
      setUsers(await onSearchUsers(query.trim()));
      setRecipientId("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not search for users.");
    } finally {
      setBusy(false);
    }
  }

  async function submit(action: "grant" | "revoke") {
    setError("");
    setBusy(true);
    try {
      await onShare({
        action,
        document_id: documentId,
        permission,
        ...(scope === "all" ? { all_users: true } : { user_id: recipientId }),
      });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not update sharing.");
    } finally {
      setBusy(false);
    }
  }

  const canSubmit = Boolean(documentId) && (scope === "all" || Boolean(recipientId));
  return <>
    <PageHeading eyebrow="CONTROLLED ACCESS" title="Sharing" description="Share your documents with a selected registered user or every currently registered TrustVault user." />
    <section className="panel sharing-panel">
      <div className="sharing-intro"><span className="sharing-illustration"><Users size={23} /></span><div><h2>Manage document access</h2>
        <p>Recipients get access to this document only. Access is checked on every preview or download.</p></div></div>
      {error && <div role="alert" className="notice notice-error"><X size={17} />{error}</div>}
      {documents.length === 0 ? <EmptyState icon={<FolderOpen size={23} />} title="No owned documents"
        description="Upload a document first. You can share documents you own." /> :
        <div className="sharing-form">
          <label>Choose a document<select value={documentId} onChange={(event) => setDocumentId(event.target.value)} required>
            <option value="">Select a document…</option>{documents.map((document) => <option key={document.id} value={document.id}>{document.title}</option>)}</select></label>
          <fieldset className="share-scope"><legend>Recipients</legend>
            <label><input type="radio" name="share-scope" checked={scope === "person"} onChange={() => setScope("person")} /> One registered user</label>
            <label><input type="radio" name="share-scope" checked={scope === "all"} onChange={() => setScope("all")} /> All signed-in users (global)</label>
          </fieldset>
          {scope === "person" && <div className="recipient-search">
            <label htmlFor="recipient-query">Search by name or email</label>
            <div className="recipient-search-row">
              <input id="recipient-query" type="search" value={query} onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); void findUsers(); } }}
                placeholder="Type at least two characters" />
              <button className="button-secondary" disabled={busy || query.trim().length < 2} onClick={() => void findUsers()}>
                <Search size={16} /> Search
              </button>
            </div>
            {users.length > 0 && <div className="recipient-results" role="listbox" aria-label="Search results">
              {users.map((user) => <button type="button" key={user.id} className={recipientId === user.id ? "recipient-selected" : ""}
                onClick={() => setRecipientId(user.id)}>
                <b>{user.display_name || user.email}</b><span>{user.email}</span>
              </button>)}
            </div>}
            {query.length >= 2 && users.length === 0 && <p className="form-hint">No matching registered users. Try another name or email.</p>}
            {recipientId && <p className="form-hint">Selected: {users.find((user) => user.id === recipientId)?.email}</p>}
          </div>}
          {scope === "all" && <p className="global-share-warning">This grants access to every other registered user now. Future users will not be added automatically.</p>}
          <label>Permission<select value={permission} onChange={(event) => setPermission(event.target.value as "read" | "edit")}>
            <option value="read">Read only — preview, no app download</option><option value="edit">Edit access — preview and download</option></select></label>
          <div className="share-actions"><button className="button-primary" disabled={busy || !canSubmit} onClick={() => void submit("grant")}>
            {busy ? <LoaderCircle size={17} className="spin" /> : <Users size={17} />} Grant access</button>
            <button className="button-secondary" disabled={busy || !canSubmit}
              onClick={() => { if (window.confirm("Revoke this user's access to the selected document?")) void submit("revoke"); }}>
              <X size={16} /> Revoke access</button></div>
        </div>}
    </section>
    <div className="permission-tip"><LockKeyhole size={17} /><span><b>Owners stay in control.</b> Only the document owner can share or revoke it. Read-only recipients can preview but the download endpoint also denies them.</span></div>
  </>;
}

function UserManagementPage({ onSearchUsers, onUpdateRole }: {
  onSearchUsers: (query: string) => Promise<UserProfile[]>;
  onUpdateRole: (userId: string, role: Role) => Promise<void>;
}) {
  const [query, setQuery] = useState("");
  const [users, setUsers] = useState<UserProfile[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function search() {
    setBusy(true);
    setError("");
    try {
      setUsers(await onSearchUsers(query.trim()));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not search users.");
    } finally {
      setBusy(false);
    }
  }

  async function changeRole(user: UserProfile, role: Role) {
    setBusy(true);
    setError("");
    try {
      await onUpdateRole(user.id, role);
      setUsers((current) => current.map((item) => item.id === user.id ? { ...item, role } : item));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not update this user's role.");
    } finally {
      setBusy(false);
    }
  }

  return <>
    <PageHeading eyebrow="ADMINISTRATION" title="User management" description="Search registered users by name or email and change their application role. All changes are added to the audit history." />
    <section className="panel user-management-panel">
      {error && <div role="alert" className="notice notice-error"><X size={17} />{error}</div>}
      <div className="recipient-search-row">
        <input type="search" aria-label="Search users by name or email" value={query} onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); void search(); } }}
          placeholder="Search by name or email (at least two characters)" />
        <button className="button-primary" disabled={busy || query.trim().length < 2} onClick={() => void search()}>
          {busy ? <LoaderCircle size={17} className="spin" /> : <Search size={16} />} Search users
        </button>
      </div>
      <div className="user-results">
        {users.map((user) => <div className="user-result" key={user.id}>
          <span className="user-result-avatar">{initials(user.email)}</span>
          <span className="user-result-info"><b>{user.display_name || user.email}</b><small>{user.email}</small></span>
          <label>Role<select aria-label={`Role for ${user.email}`} value={user.role ?? "viewer"} disabled={busy}
            onChange={(event) => void changeRole(user, event.target.value as Role)}>
            <option value="viewer">Viewer</option><option value="owner">Owner</option><option value="admin">Admin</option>
          </select></label>
        </div>)}
        {!busy && query.trim().length >= 2 && users.length === 0 && <p className="form-hint">No users found for that search.</p>}
      </div>
    </section>
  </>;
}

function PreviewDialog({ preview, onClose }: { preview: Preview; onClose: () => void }) {
  return <div className="preview-backdrop" onClick={onClose}>
    <section className="preview-dialog" role="dialog" aria-modal="true" aria-labelledby="preview-title" onClick={(event) => event.stopPropagation()}>
      <header><div><h2 id="preview-title">{preview.document.title}</h2><p>{preview.document.original_filename}</p></div>
        <button className="icon-button" aria-label="Close preview" onClick={onClose}><X size={19} /></button></header>
      <iframe title={`Preview of ${preview.document.title}`} src={`${preview.url}#toolbar=0&navpanes=0`} sandbox="allow-scripts" />
      <footer>{preview.document.owned || preview.document.permission === "edit" ? "You have download access from the document list." : "Read-only access: preview only. Download is disabled."}</footer>
    </section>
  </div>;
}

function DocumentRow({ document, onPreview }: { document: Document; onPreview: (document: Document) => void }) {
  return <div className="recent-document"><span className="file-icon"><FileText size={18} /></span>
    <span className="recent-doc-name"><b>{document.title}</b><small>{document.original_filename}</small></span>
    <span className="category-pill">{document.category || "general"}</span>
    <button className="icon-button" aria-label={`Preview ${document.title}`} onClick={() => onPreview(document)}><Eye size={17} /></button>
  </div>;
}

function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p>{description}</p></div>{action}</div>;
}

function EmptyState({ icon, title, description, action }: { icon: ReactNode; title: string; description: string; action?: ReactNode }) {
  return <div className="empty-state"><span className="empty-icon">{icon}</span><b>{title}</b><p>{description}</p>{action}</div>;
}

function LoadingInline() {
  return <div className="loading-inline"><LoaderCircle size={19} className="spin" /> Loading secure data…</div>;
}
