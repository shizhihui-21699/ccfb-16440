import Config

config :video_conf,
  signing_secret: "test-signing-secret-at-least-32-bytes-long",
  pbkdf2_iterations: 1,
  pow_difficulty: 1
