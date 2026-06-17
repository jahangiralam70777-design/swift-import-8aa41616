import { useEffect, useRef } from "react";
import { useRouterState } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { pingStudySession } from "@/lib/study-tracker.functions";

/**
 * Heartbeats an ACTIVE-engagement study session.
 *
 * A heartbeat is only sent when ALL three are true:
 *   1. the tab is visible (not backgrounded / minimized),
 *   2. the window currently has focus,
 *   3. the user has interacted within the last `IDLE_TIMEOUT_MS`
 *      (mouse move, mouse down, key press, scroll, touch, wheel).
 *
 * This ensures Usage 7d / Total Time reflect real engagement instead of
 * "left the laptop open all day" login duration.
 */
const HEARTBEAT_INTERVAL_MS = 60_000;
const IDLE_TIMEOUT_MS = 90_000; // 1.5 min of no input → idle
const INITIAL_SEED_MS = 20_000;

export function StudyHeartbeat() {
  const ping = useServerFn(pingStudySession);
  const pathname = useRouterState({ select: (r) => r.location.pathname });
  const lastActivity = useRef<number>(Date.now());
  const focused = useRef<boolean>(
    typeof document !== "undefined" ? document.hasFocus() : true,
  );

  useEffect(() => {
    let cancelled = false;
    const moduleKey = (pathname || "/").replace(/^\/+/, "").split("/")[0] || "dashboard";

    const markActive = () => {
      lastActivity.current = Date.now();
    };
    const onFocus = () => {
      focused.current = true;
      markActive();
    };
    const onBlur = () => {
      focused.current = false;
    };
    const onVis = () => {
      if (document.visibilityState === "visible") markActive();
    };

    // Passive listeners — cheap, fire-and-forget.
    const opts: AddEventListenerOptions = { passive: true };
    window.addEventListener("mousemove", markActive, opts);
    window.addEventListener("mousedown", markActive, opts);
    window.addEventListener("keydown", markActive, opts);
    window.addEventListener("scroll", markActive, opts);
    window.addEventListener("wheel", markActive, opts);
    window.addEventListener("touchstart", markActive, opts);
    window.addEventListener("touchmove", markActive, opts);
    window.addEventListener("focus", onFocus);
    window.addEventListener("blur", onBlur);
    document.addEventListener("visibilitychange", onVis);

    const isActive = () =>
      document.visibilityState === "visible" &&
      focused.current &&
      Date.now() - lastActivity.current < IDLE_TIMEOUT_MS;

    const tick = async () => {
      if (cancelled) return;
      if (!isActive()) return;
      try {
        // The server clamps deltas against last_heartbeat_at; we just signal
        // "still actively here". A malicious client cannot inflate time.
        await ping({ data: { module: moduleKey } });
      } catch {
        /* analytics is best-effort */
      }
    };

    const seed = window.setTimeout(() => {
      void tick();
    }, INITIAL_SEED_MS);
    const interval = window.setInterval(() => {
      void tick();
    }, HEARTBEAT_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearTimeout(seed);
      window.clearInterval(interval);
      window.removeEventListener("mousemove", markActive);
      window.removeEventListener("mousedown", markActive);
      window.removeEventListener("keydown", markActive);
      window.removeEventListener("scroll", markActive);
      window.removeEventListener("wheel", markActive);
      window.removeEventListener("touchstart", markActive);
      window.removeEventListener("touchmove", markActive);
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("blur", onBlur);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [pathname, ping]);

  return null;
}
