defmodule VideoConf.Credentials do
  @moduledoc """
  Slow-hashed user/PSTN codes and cryptographically random numeric identifiers.

  Meeting IDs are nine digits for humans and DTMF. They are identifiers, not
  secrets; security must never rely on the ID alone.
  """

  @algo "pbkdf2_sha256"

  @doc "Generates a nine-digit meeting number from 100000000 to 999999999."
  def generate_meeting_id do
    Integer.to_string(100_000_000 + :crypto.strong_rand_range(900_000_000))
  end

  @doc "Generates a fixed-length decimal code, allowing leading zeroes."
  def generate_numeric_code(length \\ 6) when length >= 4 and length <= 12 do
    length
    |> then(&:crypto.strong_rand_range(Integer.pow(10, &1)))
    |> Integer.to_string()
    |> String.pad_leading(length, "0")
  end

  def hash(secret, opts \\ [])

  def hash(secret, opts) when is_binary(secret) and byte_size(secret) > 0 do
    iterations = opts[:iterations] || iterations()
    salt = opts[:salt] || :crypto.strong_rand_bytes(16)
    derived = :crypto.pbkdf2_hmac(:sha256, secret, salt, iterations, 32)

    [
      @algo,
      Integer.to_string(iterations),
      Base.url_encode64(salt, padding: false),
      Base.url_encode64(derived, padding: false)
    ]
    |> Enum.join("$")
  end

  def hash(_empty, _opts), do: nil

  @doc "Verifies a secret in constant-ish time. A missing hash performs dummy work."
  def verify(secret, stored_hash)

  def verify(secret, @algo <> "$" <> rest) when is_binary(secret) do
    with [iterations_text, salt_b64, hash_b64] <- String.split(rest, "$"),
         {iterations, ""} <- Integer.parse(iterations_text),
         {:ok, salt} <- Base.url_decode64(salt_b64, padding: false),
         {:ok, expected} <- Base.url_decode64(hash_b64, padding: false) do
      actual = :crypto.pbkdf2_hmac(:sha256, secret, salt, iterations, byte_size(expected))
      byte_size(actual) == byte_size(expected) and :crypto.hash_equals(actual, expected)
    else
      _ -> false
    end
  end

  def verify(_secret, nil) do
    # Reduce timing differences between "meeting does not exist" and
    # "meeting exists but password is wrong".
    verify("dummy-password-for-timing", dummy_hash())
    false
  end

  def verify(_secret, _malformed), do: false

  def numeric?(value) when is_binary(value), do: Regex.match?(~r/^[0-9]{4,12}$/, value)
  def numeric?(_), do: false

  @doc """
  Fast peppered verifier for the hot join path.

  The pepper comes from `VIDEO_CONF_SIGNING_SECRET` (or a KMS-backed value in
  production). A database/ETS leak without the pepper cannot be brute-forced at
  HMAC speed. The PBKDF2 hash is still retained as defense in depth.
  """
  def fast_hash(secret, context) when is_binary(secret) and is_binary(context) do
    tag = :crypto.mac(:hmac, :sha256, pepper(), context <> ":" <> secret)
    "hmac_sha256$" <> Base.url_encode64(tag, padding: false)
  end

  def fast_verify(secret, stored_hash, context)
      when is_binary(secret) and is_binary(stored_hash) and is_binary(context) do
    expected = fast_hash(secret, context)
    byte_size(expected) == byte_size(stored_hash) and :crypto.hash_equals(expected, stored_hash)
  end

  def fast_verify(_secret, _stored_hash, _context), do: false

  defp pepper do
    Application.get_env(:video_conf, :signing_secret) ||
      raise "signing secret/pepper is not configured"
  end

  defp dummy_hash do
    hash("dummy-password-for-timing", iterations: 1, salt: <<0::128>>)
  end

  defp iterations do
    Application.get_env(:video_conf, :pbkdf2_iterations, 20_000)
  end
end
