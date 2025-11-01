// supabase/functions/store-credentials/index.ts
import { serve } from "https://deno.land/std@0.177.0/http/server.ts";

// Serves HTTP requests
serve(async (req: Request) => {
  // Retrieves client key from headers
  const clientKey = req.headers.get("x-shared-key");
  // Retrieves expected key from environment
  const expectedKey = Deno.env.get("EDGE_SHARED_KEY");

  // Validates shared key
  if (clientKey !== expectedKey) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
  }

  try {
    // Extracts user_id from request body
    const { user_id } = await req.json();
    // Checks for missing user_id
    if (!user_id) {
      return new Response(JSON.stringify({ error: "Missing user_id" }), { status: 400 });
    }

    // Retrieves Supabase URL and service key from environment
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

    // 1. Check if user_id already exists
    // Fetches existing encryption keys for user_id
    const selectRes = await fetch(
      `${supabaseUrl}/rest/v1/encryption_keys?user_id=eq.${user_id}`,
      {
        headers: {
          "apikey": serviceKey,
          "Authorization": `Bearer ${serviceKey}`,
        },
      }
    );

    // Handles fetch error
    if (!selectRes.ok) {
      const err = await selectRes.text();
      return new Response(JSON.stringify({ error: err }), { status: 500 });
    }

    // Parses existing data
    const existing = await selectRes.json();

    // Checks if user already exists
    if (Array.isArray(existing) && existing.length > 0) {
      // User already exists → just return stored password
      return new Response(
        JSON.stringify({ password: existing[0].password, reused: true }),
        { headers: { "Content-Type": "application/json" }, status: 200 }
      );
    }

    // 2. If not found, generate a new password
    // Generates new UUID password
    const newPassword = crypto.randomUUID();

    // 3. Insert into Supabase
    // Inserts new encryption key into Supabase
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

    // Handles insert error
    if (!insertRes.ok) {
      const err = await insertRes.text();
      return new Response(JSON.stringify({ error: err }), { status: 500 });
    }

    // Parses inserted data
    const inserted = await insertRes.json();
    // Returns new password
    return new Response(
      JSON.stringify({ password: inserted[0].password, reused: false }),
      { headers: { "Content-Type": "application/json" }, status: 200 }
    );

  // Catches any errors
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), { status: 500 });
  }
});