import Config

# In production set VIDEO_CONF_SIGNING_SECRET to a high-entropy value shared by
# join nodes. The development default is intentionally only for local use.
config :video_conf,
  signing_secret:
    System.get_env("VIDEO_CONF_SIGNING_SECRET") ||
      "dev-only-insecure-secret-please-change-32+bytes",
  pbkdf2_iterations: 20_000,
  join_ticket_ttl_seconds: 60,
  waiting_token_ttl_seconds: 900,
  guest_invite_ttl_seconds: 86_400

config :video_conf, :limits,
  # Every HTTP/DTMF attempt, keyed by network source. Local ETS counts per node;
  # production should use a shared sliding-window store at the edge.
  source_attempts: {120, 60_000},
  principal_attempts: {60, 60_000},
  # Failed credential/meeting guesses. Crossing this asks for a short PoW/CAPTCHA
  # instead of permanently locking an account or meeting (which enables DoS).
  source_failures: {10, 600_000},
  meeting_source_failures: {5, 600_000},
  meeting_failures: {500, 600_000},
  hard_source_failures: {120, 600_000}

import_config "#{config_env()}.exs"
