import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export const Route = createFileRoute("/reset-password")({
  head: () => ({
    meta: [
      { title: "Reset password — vSOC" },
      { name: "description", content: "Choose a new password for your vSOC account." },
      { property: "og:title", content: "Reset password — vSOC" },
      { property: "og:description", content: "Reset your vSOC password." },
    ],
  }),
  component: Reset,
});

function Reset() {
  const navigate = useNavigate();
  const [pw, setPw] = useState("");
  return (
    <div className="grid min-h-screen place-items-center px-4">
      <form className="panel w-full max-w-sm space-y-3 p-6" onSubmit={async (e) => {
        e.preventDefault();
        const { error } = await supabase.auth.updateUser({ password: pw });
        if (error) return toast.error(error.message);
        toast.success("Password updated");
        navigate({ to: "/" });
      }}>
        <h1 className="text-xl font-semibold">Set a new password</h1>
        <Input type="password" minLength={8} value={pw} onChange={(e) => setPw(e.target.value)} placeholder="New password" required />
        <Button type="submit" className="w-full">Update password</Button>
      </form>
    </div>
  );
}
