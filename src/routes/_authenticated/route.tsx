import { createFileRoute, Outlet, redirect } from "@tanstack/react-router";
import { supabase } from "@/integrations/supabase/client";
import { AppShell } from "@/components/vsoc/AppShell";

export const Route = createFileRoute("/_authenticated")({
  ssr: false,
  beforeLoad: async () => {
    // DEV peek switch: set VITE_DEV_LOGIN=1 in .env to skip the login wall.
    // Only active in `vite dev`; the Lovable/production build always gates.
    if (import.meta.env.DEV && import.meta.env.VITE_DEV_LOGIN === "1") {
      return { user: { id: "dev-local", email: "dev@local" } as never };
    }
    const { data } = await supabase.auth.getUser();
    if (!data.user) throw redirect({ to: "/auth" });
    return { user: data.user };
  },
  component: () => (
    <AppShell>
      <Outlet />
    </AppShell>
  ),
});
