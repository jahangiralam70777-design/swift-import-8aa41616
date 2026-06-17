import {
  createFileRoute,
  Outlet,
  redirect,
  useNavigate,
  useLocation,
} from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { AdminSidebar } from "@/components/admin/AdminSidebar";
import { useAppStore, hasLocalAuthSession } from "@/stores/app-store";
import { supabase } from "@/integrations/supabase/client";
import { verifyAdminAccess, type VerifyAdminAccessResult } from "@/lib/admin-verify.functions";
import { useServerFn } from "@tanstack/react-start";

export const Route = createFileRoute("/admin")({
  // Admin session lives in localStorage (Supabase). SSR-skip + a
  // synchronous beforeLoad gate prevents admin chrome from being
  // streamed to anonymous visitors. Server-verified role check still
  // runs inside <AdminGate /> against `user_roles`.
  ssr: false,
  beforeLoad: ({ location }) => {
    if (typeof window === "undefined") return;
    if (location.pathname === "/admin/login") return; // public sub-route
    if (!hasLocalAuthSession()) {
      throw redirect({ to: "/admin/login" });
    }
  },
  component: AdminLayout,
  head: () => ({
    meta: [
      { title: "Admin Control Center · CA Aspire BD" },
      { name: "robots", content: "noindex, nofollow" },
      {
        name: "description",
        content:
          "Manage students, exams, resources and platform analytics from the premium glassmorphism CA Aspire BD admin dashboard.",
      },
    ],
  }),
});

const ADMIN_VERIFIED_KEY = "admin-verified-at";
const ADMIN_VERIFIED_TTL_MS = 5 * 60_000;

function readRecentVerification(): boolean {
  if (typeof window === "undefined") return false;
  try {
    const raw = window.sessionStorage.getItem(ADMIN_VERIFIED_KEY);
    if (!raw) return false;
    const ts = Number(raw);
    return Number.isFinite(ts) && Date.now() - ts < ADMIN_VERIFIED_TTL_MS;
  } catch {
    return false;
  }
}

function AdminGate({ children }: { children: React.ReactNode }) {
  const user = useAppStore((s) => s.user);
  const refreshAuth = useAppStore((s) => s.refreshAuth);
  const navigate = useNavigate();
  const verifyAdmin = useServerFn(verifyAdminAccess);

  // Optimistic render: the synchronous beforeLoad gate already verified a
  // local Supabase session exists, so paint the dashboard immediately and
  // re-verify role in the background. Only redirect if the server returns
  // a definitive non-admin response.
  const [blocked, setBlocked] = useState(false);

  useEffect(() => {
    if (!user && hasLocalAuthSession()) void refreshAuth({ force: true });
  }, [refreshAuth, user]);

  useEffect(() => {
    if (readRecentVerification()) return;
    let cancelled = false;
    (async () => {
      try {
        const result = (await verifyAdmin()) as VerifyAdminAccessResult;
        if (cancelled) return;
        if (result?.degraded) return;
        if (!result?.isAdmin) {
          setBlocked(true);
          navigate({ to: "/admin/login", replace: true });
          return;
        }
        try {
          window.sessionStorage.setItem(ADMIN_VERIFIED_KEY, String(Date.now()));
        } catch {
          /* ignore */
        }
      } catch (error) {
        console.warn("[admin-route] verifyAdmin failed", error);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [navigate, verifyAdmin]);

  if (blocked) return null;
  return <>{children}</>;
}

function AdminLayout() {
  const path = useLocation({ select: (l) => l.pathname });

  // The admin login page lives at /admin/login but must be publicly reachable
  // (no sidebar, no gate) so unauthenticated admins can sign in.
  if (path === "/admin/login") {
    return (
      <div className="relative min-h-dvh overflow-x-hidden bg-background text-foreground">
        <div className="pointer-events-none fixed inset-0 -z-10 bg-hero-glow opacity-60" />
        <Outlet />
      </div>
    );
  }

  // H-4: AdminSidebar must NOT render until `verifyAdminAccess` confirms.
  // Previously it was a sibling of <AdminGate/> and therefore visible to
  // anyone hitting /admin (revealing the admin nav structure). It now
  // lives inside the gate, so non-admins see only the gate's loading /
  // forbidden / demo card.
  return (
    <div className="relative min-h-dvh overflow-x-hidden bg-background text-foreground">
      <div className="pointer-events-none fixed inset-0 -z-10 bg-hero-glow opacity-60" />
      <div className="pointer-events-none fixed left-10 top-20 -z-10 h-72 w-72 rounded-full bg-[var(--neon-purple)]/20 blur-3xl animate-pulse-glow" />
      <div className="pointer-events-none fixed right-10 bottom-10 -z-10 h-80 w-80 rounded-full bg-[var(--neon-blue)]/20 blur-3xl animate-pulse-glow" />
      <div className="pointer-events-none fixed left-1/2 top-1/3 -z-10 h-64 w-64 rounded-full bg-fuchsia-500/10 blur-3xl animate-pulse-glow" />

      <div className="mx-auto flex max-w-[1600px] gap-4 px-4 py-4 sm:px-6">
        <AdminGate>
          <AdminSidebar />
          <div className="pointer-events-auto min-w-0 flex-1 space-y-4">
            <Outlet />
          </div>
        </AdminGate>
      </div>
    </div>
  );
}
