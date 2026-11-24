import Config

# Enforce a real shared secret in production releases. In dev/test the values
# from config.exs/config/test.exs are sufficient.
if config_env() == :prod do
  secret = System.get_env("VIDEO_CONF_SIGNING_SECRET")

  if is_nil(secret) or byte_size(secret) < 32 do
    raise """
    VIDEO_CONF_SIGNING_SECRET must be set to at least 32 random bytes in production.
    Generate one with: mix run -e 'IO.puts(Base.encode64(:crypto.strong_rand_bytes(32)))'
    """
  end

  config :video_conf, signing_secret: secret
end
