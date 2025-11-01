// supabase/functions/verify-password/index.ts
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

// Serves HTTP requests
serve(async (req: Request) => {
  // Extracts user_id and password from request body
  const { user_id, password } = await req.json();
  // Checks for missing fields
  if (!user_id || !password) {
    return new Response(JSON.stringify({ valid: false, reason: "Missing fields" }), { status: 400 });
  }

  // Retrieves Supabase URL and service key from environment
  const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

  // Fetches stored password from Supabase
  const res = await fetch(`${supabaseUrl}/rest/v1/encryption_keys?user_id=eq.${user_id}`, {
    headers: {
      "apikey": serviceKey,
      "Authorization": `Bearer ${serviceKey}`,
    },
  });

  // Parses response data
  const data = await res.json();
  // Checks if data exists
  if (!Array.isArray(data) || data.length === 0) {
    return new Response(JSON.stringify({ valid: false }), { status: 200 });
  }

  // Retrieves stored password
  const storedPassword = data[0].password;
  // Compares passwords and returns validity
  return new Response(JSON.stringify({ valid: storedPassword === password }), {
    headers: { "Content-Type": "application/json" },
  });
});