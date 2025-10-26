// supabase/functions/store-credentials/index.ts
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

serve(async (req: Request) => {
  const clientKey = req.headers.get("x-shared-key");
  const expectedKey = Deno.env.get("EDGE_SHARED_KEY");

  if (clientKey !== expectedKey) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
  }

  try {
    const { user_id } = await req.json();
    if (!user_id) {
      return new Response(JSON.stringify({ error: "Missing user_id" }), { status: 400 });
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    // 1. Check if user_id already exists
    const selectRes = await fetch(
      `${supabaseUrl}/rest/v1/encryption_keys?user_id=eq.${user_id}`,
      {
        headers: {
          "apikey": serviceKey,
          "Authorization": `Bearer ${serviceKey}`,
        },
      }
    );

    if (!selectRes.ok) {
      const err = await selectRes.text();
      return new Response(JSON.stringify({ error: err }), { status: 500 });
    }

    const existing = await selectRes.json();

    if (Array.isArray(existing) && existing.length > 0) {
      // User already exists → just return stored password
      return new Response(
        JSON.stringify({ password: existing[0].password, reused: true }),
        { headers: { "Content-Type": "application/json" }, status: 200 }
      );
    }

    // 2. If not found, generate a new password
    const newPassword = crypto.randomUUID();

    // 3. Insert into Supabase
    const insertRes = await fetch(`${supabaseUrl}/rest/v1/encryption_keys`, {
      method: "POST",
      headers: {
        "apikey": serviceKey,
        "Authorization": `Bearer ${serviceKey}`,
        "Content-Type": "application/json",
        "Prefer": "return=representation",
      },
      body: JSON.stringify({ user_id, password: newPassword }),
    });

    if (!insertRes.ok) {
      const err = await insertRes.text();
      return new Response(JSON.stringify({ error: err }), { status: 500 });
    }

    const inserted = await insertRes.json();
    return new Response(
      JSON.stringify({ password: inserted[0].password, reused: false }),
      { headers: { "Content-Type": "application/json" }, status: 200 }
    );

  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
});
