export const ROLE_DISPLAY_NAMES: Record<string, string> = {
  admin: "Admin",
  moderator: "Moderator",
  user: "User",
  student: "Student",
  super_admin: "Super Admin",
};

export function getRoleDisplayName(role: string | null | undefined): string {
  if (!role) return "Unassigned";
  return ROLE_DISPLAY_NAMES[role] ?? role;
}
