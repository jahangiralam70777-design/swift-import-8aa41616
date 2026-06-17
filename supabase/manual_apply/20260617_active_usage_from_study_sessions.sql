-- ============================================================
-- 20260617_active_usage_from_study_sessions.sql
-- ------------------------------------------------------------
-- Apply manually via the SQL editor.
--
-- Previously `Usage 7d`, `Usage 24h`, `Usage 30d`, `avg_session_seconds`,
-- and per-user `total_usage_seconds` were derived from
-- `user_login_events.duration_seconds` — i.e. raw login→logout duration.
-- That counts idle / backgrounded / "left the tab open all day" minutes
-- and dramatically over-reports engagement.
--
-- Real engagement is already tracked by the in-app StudyHeartbeat, which
-- only pings while the tab is visible AND the user has interacted in the
-- last ~90s. Heartbeats accumulate into `study_sessions.duration_seconds`.
--
-- This migration redefines the two analytics RPCs to read engagement-time
-- from `study_sessions` instead of `user_login_events`. The TS server
-- functions (`adminUserAnalytics`, `adminTopUsers`, `adminListUsers`) also
-- recompute these values defensively, so the UI is correct even before
-- this migration runs — but running this migration keeps the database
-- definitions in sync with what the API returns.
--
-- Counts (active_24h/7d/30d, total_logins) still come from user_login_events,
-- because "did the user log in" is independent of "how much did they use it".
-- ============================================================

CREATE OR REPLACE FUNCTION public.admin_user_analytics()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE result jsonb;
BEGIN
  IF NOT public.has_role(auth.uid(), 'admin'::app_role)
     AND NOT public.has_role(auth.uid(), 'super_admin'::app_role) THEN
    RAISE EXCEPTION 'Forbidden: admin role required';
  END IF;

  SELECT jsonb_build_object(
    'total_users', (SELECT count(*) FROM public.profiles WHERE deleted_at IS NULL),
    'deleted_users', (SELECT count(*) FROM public.profiles WHERE deleted_at IS NOT NULL),
    'active_24h', (SELECT count(DISTINCT user_id) FROM public.user_login_events WHERE login_at >= now() - interval '24 hours'),
    'active_7d', (SELECT count(DISTINCT user_id) FROM public.user_login_events WHERE login_at >= now() - interval '7 days'),
    'active_30d', (SELECT count(DISTINCT user_id) FROM public.user_login_events WHERE login_at >= now() - interval '30 days'),
    'lifetime_active', (SELECT count(DISTINCT user_id) FROM public.user_login_events),
    'total_logins', (SELECT count(*) FROM public.user_login_events),
    'avg_session_seconds', COALESCE((
      SELECT avg(duration_seconds)::bigint
      FROM public.study_sessions
      WHERE duration_seconds > 0
    ), 0),
    'usage_24h', COALESCE((
      SELECT sum(duration_seconds)::bigint
      FROM public.study_sessions
      WHERE last_heartbeat_at >= now() - interval '24 hours'
    ), 0),
    'usage_7d', COALESCE((
      SELECT sum(duration_seconds)::bigint
      FROM public.study_sessions
      WHERE last_heartbeat_at >= now() - interval '7 days'
    ), 0),
    'usage_30d', COALESCE((
      SELECT sum(duration_seconds)::bigint
      FROM public.study_sessions
      WHERE last_heartbeat_at >= now() - interval '30 days'
    ), 0)
  ) INTO result;

  RETURN result;
END $$;

CREATE OR REPLACE FUNCTION public.admin_top_users(_order text DEFAULT 'most', _limit integer DEFAULT 10)
RETURNS TABLE (
  user_id uuid,
  display_name text,
  total_login_count integer,
  total_usage_seconds bigint,
  last_login_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF NOT public.has_role(auth.uid(), 'admin'::app_role)
     AND NOT public.has_role(auth.uid(), 'super_admin'::app_role) THEN
    RAISE EXCEPTION 'Forbidden: admin role required';
  END IF;

  IF _order = 'least' THEN
    RETURN QUERY
      SELECT
        p.id,
        p.display_name,
        p.total_login_count,
        COALESCE(s.usage_seconds, 0)::bigint AS total_usage_seconds,
        p.last_login_at
      FROM public.profiles p
      LEFT JOIN (
        SELECT user_id, sum(duration_seconds)::bigint AS usage_seconds
        FROM public.study_sessions
        GROUP BY user_id
      ) s ON s.user_id = p.id
      WHERE p.deleted_at IS NULL
      ORDER BY total_usage_seconds ASC, p.total_login_count ASC
      LIMIT _limit;
  ELSE
    RETURN QUERY
      SELECT
        p.id,
        p.display_name,
        p.total_login_count,
        COALESCE(s.usage_seconds, 0)::bigint AS total_usage_seconds,
        p.last_login_at
      FROM public.profiles p
      LEFT JOIN (
        SELECT user_id, sum(duration_seconds)::bigint AS usage_seconds
        FROM public.study_sessions
        GROUP BY user_id
      ) s ON s.user_id = p.id
      WHERE p.deleted_at IS NULL
      ORDER BY total_usage_seconds DESC NULLS LAST, p.total_login_count DESC
      LIMIT _limit;
  END IF;
END $$;

GRANT EXECUTE ON FUNCTION public.admin_user_analytics() TO authenticated;
GRANT EXECUTE ON FUNCTION public.admin_top_users(text, integer) TO authenticated;
