import { createFileRoute } from "@tanstack/react-router";
import { authenticateCronRequest } from "@/integrations/supabase/cron-auth";

export const Route = createFileRoute("/api/public/cron/feeds")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const authFailure = await authenticateCronRequest(request);
        if (authFailure) return authFailure;
        const body = (await request.json().catch(() => ({}))) as { sources?: string[] };
        const wanted = new Set(Array.isArray(body.sources) ? body.sources : ["kev", "epss"]);
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { syncKev, syncEpss } = await import("@/lib/feeds.server");
        const results = [];
        if (wanted.has("kev")) results.push(await syncKev(supabaseAdmin));
        if (wanted.has("epss")) results.push(await syncEpss(supabaseAdmin));
        return Response.json({ results });
      },
    },
  },
});
