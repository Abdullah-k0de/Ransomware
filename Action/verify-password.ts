// supabase/functions/verify-password/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

serve(async (req: Request) => {
  const { user_id, password } = await req.json();
  if (!user_id || !password) {
    return new Response(JSON.stringify({ valid: false, reason: "Missing fields" }), { status: 400 });
  }

  const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

  // Look up the stored password
  const res = await fetch(`${supabaseUrl}/rest/v1/encryption_keys?user_id=eq.${user_id}`, {
    headers: {
      "apikey": serviceKey,
      "Authorization": `Bearer ${serviceKey}`,
    },
  });

  const data = await res.json();
  if (!Array.isArray(data) || data.length === 0) {
    return new Response(JSON.stringify({ valid: false }), { status: 200 });
  }

  const storedPassword = data[0].password;
  return new Response(JSON.stringify({ valid: storedPassword === password }), {
    headers: { "Content-Type": "application/json" },
  });
});
