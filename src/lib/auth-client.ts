import type { Session } from "@supabase/supabase-js";
import { supabase } from "@/integrations/supabase/client";
import type { AppRole } from "@/lib/app-data";
import { clearDemoSession } from "@/lib/demo-auth";
import { recordLoginEvent, recordLogoutEvent } from "@/lib/user-activity.functions";
import { checkAuthRateLimit } from "@/lib/rate-limit.functions";
import { checkAuthAllowed } from "@/lib/auth-controls.functions";
import { trackEvent } from "@/lib/tracking";
import { clearSessionTimers } from "@/lib/session-timeout";

const LOGIN_EVENT_KEY = "edumaster.login_event_id";

export function clearClientAuthStorage(options: { all?: boolean } = {}) {
  if (typeof window === "undefined") return;
  try {
    if (options.all) {
      window.sessionStorage.clear();
      window.localStorage.clear();
      return;
    }
    window.sessionStorage.clear();
    for (const key of Object.keys(window.localStorage)) {
      if (
        key === LOGIN_EVENT_KEY ||
        key.startsWith("sb-") ||
        key.startsWith("edumaster.auth") ||
        key.startsWith("edumaster.session") ||
        key.startsWith("edumaster.force_logout") ||
        key === "edumaster.demo_session" ||
        key === "edumaster.last_activity" ||
        key === "edumaster.remember_me"
      ) {
        window.localStorage.removeItem(key);
      }
    }
  } catch {
    /* noop */
  }
}

/**
 * Translate the JSON envelope produced by `checkAuthRateLimit` (server fn)
 * into a friendly UI error. The server fn throws `Error(JSON.stringify(...))`
 * when the IP exceeds the auth bucket; surface the retry hint to the caller.
 */
async function gateAuth(action: "login" | "signup" | "password_reset") {
  try {
    await checkAuthRateLimit({ data: { action } });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    try {
      const parsed = JSON.parse(msg);
      if (parsed?.error === "rate_limited") {
        throw new Error(
          `Too many ${action.replace("_", " ")} attempts. Try again in ${parsed.retry_after_seconds}s.`,
        );
      }
    } catch {
      /* not a rate-limit envelope — fall through */
    }
    // Network blip or RPC error — fail open to avoid locking users out.
    console.warn("[auth] rate-limit gate skipped", e);
  }
}

export type AuthUser = {
  id: string;
  name: string;
  email: string;
  role: AppRole;
};

function rolesFromAppMetadata(appMetadata: Record<string, unknown> | undefined): string[] {
  const role = typeof appMetadata?.role === "string" ? appMetadata.role : null;
  const roles = Array.isArray(appMetadata?.roles) ? appMetadata.roles : [];
  return [role, ...roles].filter((r): r is string => typeof r === "string" && r.trim().length > 0);
}

function pickPrimaryRole(roles: string[]): AppRole {
  const rank = ["super_admin", "admin", "moderator", "student", "user"];
  if (roles.length === 0) return null;
  return [...new Set(roles)].sort((a, b) => {
    const ai = rank.indexOf(a);
    const bi = rank.indexOf(b);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  })[0];
}

// H-3: readLocalAuthSnapshot was previously used as a role fallback when
// the user_roles lookup timed out. That fallback has been removed — role
// is now derived strictly from the server response (fail-closed to
// "student"). The helper is intentionally dropped to prevent reintroduction.

export async function signInWithEmail(
  email: string,
  password: string,
  options: { intent?: "student" | "admin" } = {},
) {
  await gateAuth("login");
  // NOTE: The student-login kill-switch is enforced AFTER authentication so we
  // can read the actual role. Admins / super-admins are always allowed. Admin
  // login pages should pass intent: "admin" to skip the check entirely (defence
  // in depth — admin login must never be blocked).
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) {
    // Supabase returns a generic message for banned accounts. Translate it.
    if (/banned|disabled|user.*not.*allowed/i.test(error.message ?? "")) {
      throw new Error("Your account has been banned. Please contact support.");
    }
    throw error;
  }

  // Post-sign-in ban check (covers app-level user_bans rows that Supabase's
  // native ban_duration may not yet reflect on first login). If banned,
  // tear down the session immediately and surface a friendly message.
  try {
    const uid = data.user?.id;
    if (uid) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { data: banned } = await (supabase as any).rpc("is_user_banned", { _user_id: uid });
      if (banned === true) {
        await supabase.auth.signOut().catch(() => undefined);
        throw new Error("Your account has been banned. Please contact support.");
      }
    }
  } catch (e) {
    if (e instanceof Error && /banned/i.test(e.message)) throw e;
    // Fail open on RPC errors — guard will catch it post-login.
  }

  // Resolve role from user_roles (admin / super_admin / moderator / student / user)
  let role: AppRole = pickPrimaryRole(
    rolesFromAppMetadata(data.user?.app_metadata as Record<string, unknown>),
  );
  try {
    const uid = data.user?.id;
    if (uid) {
      const { data: roleRows } = await supabase
        .from("user_roles")
        .select("role")
        .eq("user_id", uid);
      const roles = (roleRows ?? []).map((r) => r.role as string);
      role = pickPrimaryRole(roles) ?? role;
    }
  } catch (e) {
    // Do not invent a role if lookup fails. Admin access is separately
    // verified server-side, and UI role labels should wait for real data.
    console.warn("[auth] role lookup after sign-in failed", e);
  }

  const isPrivileged = role === "admin" || role === "super_admin" || role === "moderator";
  if (options.intent !== "admin" && !isPrivileged) {
    try {
      const r = await checkAuthAllowed({ data: { kind: "login" } });
      if (!r.allowed) {
        // Block student access: tear down the session we just created.
        await supabase.auth.signOut().catch(() => undefined);
        throw new Error(
          r.message ?? "Student login is temporarily unavailable. Please try again later.",
        );
      }
    } catch (e) {
      if (
        e instanceof Error &&
        /unavailable|disabled|maintenance|temporarily/i.test(e.message)
      ) {
        throw e;
      }
      // Otherwise fail-open (network blip) and let the login proceed.
    }
  }
  // Best-effort: track login event for analytics — FIRE-AND-FORGET so it
  // never blocks the sign-in resolution (was adding 200-1500ms perceived
  // latency before dashboard redirect).
  void (async () => {
    try {
      const ua = typeof navigator !== "undefined" ? navigator.userAgent : "";
      const res = await recordLoginEvent({ data: { user_agent: ua } });
      if (typeof window !== "undefined" && res?.event_id) {
        localStorage.setItem(LOGIN_EVENT_KEY, res.event_id);
      }
      trackEvent({ event_type: "login", metadata: { method: "password" } });
    } catch (err) {
      console.warn("[auth] login event tracking failed", err);
    }
  })();
  return data;
}

export async function signUpWithEmail(input: {
  email: string;
  password: string;
  displayName?: string;
  phone?: string;
  level?: string;
  referralSource?: string;
}) {
  await gateAuth("signup");
  // Student-signup kill-switch. Public /signup creates student accounts only;
  // admin / super-admin accounts are provisioned via the admin user-management
  // flow and are NOT gated by this switch.
  try {
    const r = await checkAuthAllowed({ data: { kind: "signup" } });
    if (!r.allowed) {
      throw new Error(
        r.message ?? "New registrations are temporarily unavailable. Please try again later.",
      );
    }
  } catch (e) {
    if (e instanceof Error && /unavailable|disabled|maintenance|temporarily/i.test(e.message)) {
      throw e;
    }
  }
  const redirectTo =
    typeof window !== "undefined" ? `${window.location.origin}/dashboard` : undefined;
  const { data, error } = await supabase.auth.signUp({
    email: input.email,
    password: input.password,
    options: {
      emailRedirectTo: redirectTo,
      data: {
        ...(input.displayName ? { display_name: input.displayName } : {}),
        ...(input.phone ? { phone: input.phone } : {}),
        ...(input.level ? { level: input.level } : {}),
        ...(input.referralSource ? { referral_source: input.referralSource } : {}),
      },
    },
  });
  if (error) {
    if (/already.*registered|already.*exists|user.*exists/i.test(error.message ?? "")) {
      throw new Error(
        "This email is already registered. If your account was banned, please contact support — banned accounts cannot be re-registered.",
      );
    }
    throw error;
  }
  return data;
}

export async function resetPasswordForEmail(email: string) {
  await gateAuth("password_reset");
  const redirectTo =
    typeof window !== "undefined" ? `${window.location.origin}/reset-password` : undefined;
  const { error } = await supabase.auth.resetPasswordForEmail(email, { redirectTo });
  if (error) throw error;
}

export async function updatePassword(newPassword: string) {
  const { error } = await supabase.auth.updateUser({ password: newPassword });
  if (error) throw error;
}

export async function signOut() {
  clearDemoSession();
  // Best-effort: close out the login session
  try {
    if (typeof window !== "undefined") {
      const eventId = localStorage.getItem(LOGIN_EVENT_KEY);
      if (eventId) {
        await recordLogoutEvent({ data: { event_id: eventId } });
        localStorage.removeItem(LOGIN_EVENT_KEY);
      }
      try {
        trackEvent({ event_type: "logout" });
      } catch {
        /* swallow */
      }
    }
  } catch (err) {
    console.warn("[auth] logout event tracking failed", err);
  }
  const { error } = await supabase.auth.signOut();
  // Always clear the remember-me flag + last-activity stamp so the next
  // sign-in starts from a clean default (sessionStorage-only).
  clearSessionTimers();
  clearClientAuthStorage();
  // 403 session_not_found just means the server already forgot the session —
  // local storage is cleared either way, so don't surface it to the UI.
  if (error && !/session.*not.*found|session_not_found|403/i.test(error.message ?? "")) {
    throw error;
  }
}

export async function fetchSessionUser(session?: Session | null): Promise<AuthUser | null> {
  const resolvedSession = session ?? (await supabase.auth.getSession()).data.session;
  if (!resolvedSession?.user) return null;

  const userId = resolvedSession.user.id;
  const email = resolvedSession.user.email ?? "";

  // Race profile/role lookups against an 8s timeout so a stalled network
  // on production never blocks the auth state from settling. If a lookup
  // times out we still return a usable AuthUser from the verified session,
  // but the role is downgraded to "student" — see H-3 below.
  const withTimeout = <T>(p: PromiseLike<T>, ms: number, fallback: T): Promise<T> =>
    new Promise((resolve) => {
      const t = setTimeout(() => {
        console.warn("[auth] profile/role lookup timed out after", ms, "ms");
        resolve(fallback);
      }, ms);
      Promise.resolve(p).then(
        (v) => {
          clearTimeout(t);
          resolve(v);
        },
        (e) => {
          clearTimeout(t);
          console.warn("[auth] lookup error", e);
          resolve(fallback);
        },
      );
    });

  const [profileRes, rolesRes, banRes] = await Promise.all([
    withTimeout(
      supabase
        .from("profiles")
        .select("display_name,deleted_at,status")
        .eq("id", userId)
        .maybeSingle() as unknown as PromiseLike<{
          data: { display_name?: string; deleted_at?: string | null; status?: string | null } | null;
        }>,
      4000,
      { data: undefined } as unknown as {
        data: { display_name?: string; deleted_at?: string | null; status?: string | null } | null | undefined;
      },
    ),
    withTimeout(
      supabase.from("user_roles").select("role").eq("user_id", userId) as unknown as PromiseLike<{
        data: { role: string }[] | null;
      }>,
      4000,
      { data: null } as { data: { role: string }[] | null },
    ),
    withTimeout(
      (supabase as unknown as {
        rpc: (n: string, a: Record<string, unknown>) => Promise<{ data: boolean | null }>;
      }).rpc("is_user_banned", { _user_id: userId }),
      4000,
      { data: null } as { data: boolean | null },
    ),
  ]);

  const profile = profileRes.data;
  const roles = rolesRes.data;
  if (profile === null || profile?.deleted_at || ["suspended", "deleted", "banned"].includes(profile?.status ?? "")) {
    return null;
  }
  if (banRes.data === true) return null;
  // H-3: NEVER fall back to a localStorage snapshot for role. A tampered
  // snapshot could otherwise grant admin UI access during a brief
  // network blip. Fail closed to "student" — admin routes still gate
  // on a fresh server-verified `verifyAdminAccess()` call (H-4), so a
  // legitimate admin sees the real role within one round trip.
  const metadataRole = roleFromAppMetadata(resolvedSession.user.app_metadata as Record<string, unknown>);
  const role: AppRole = Array.isArray(roles)
    ? roles.some((r) => r.role === "super_admin")
      ? "super_admin"
      : roles.some((r) => r.role === "admin")
        ? "admin"
        : roles.some((r) => r.role === "moderator")
          ? "moderator"
          : (metadataRole ?? "student")
    : (metadataRole ?? "student");

  return {
    id: userId,
    name: profile?.display_name ?? email.split("@")[0] ?? "Learner",
    email,
    role,
  };
}
