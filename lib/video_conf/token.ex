defmodule VideoConf.Token do
  @moduledoc """
  Small HMAC-signed, expiring tokens used for SSO assertions, guest invites,
  waiting-room handles, short-lived join tickets and proof-of-work challenges.

  The token is opaque and not encrypted. Do not put secrets in claims.
  """

  @version "v1"

  @type claims :: %{optional(String.t()) => String.t() | integer()}

  @spec sign(map(), keyword()) :: String.t()
  def sign(claims, opts \\ []) when is_map(claims) do
    now = opts[:now] || System.system_time(:second)
    ttl = opts[:ttl] || 3600
    secret = opts[:secret] || secret!()

    full_claims =
      claims
      |> Map.new(fn {k, v} -> {to_string(k), v} end)
      |> Map.put_new("iat", now)
      |> Map.put_new("exp", now + ttl)
      |> Enum.map(fn {k, v} -> {to_string(k), to_string(v)} end)
      |> URI.encode_query()

    body = @version <> "." <> b64_encode(full_claims)
    signature = sign_body(body, secret)
    body <> "." <> signature
  end

  @spec verify(String.t(), keyword()) :: {:ok, map()} | {:error, :invalid_token | :expired}
  def verify(token, opts \\ [])

  def verify(@version <> "." <> rest, opts) when is_binary(rest) do
    secret = opts[:secret] || secret!()
    now = opts[:now] || System.system_time(:second)

    with [payload_b64, signature] <- String.split(rest, ".", parts: 2),
         body = @version <> "." <> payload_b64,
         expected <- sign_body(body, secret),
         true <- safe_equal?(signature, expected),
         {:ok, payload} <- b64_decode(payload_b64),
         claims <- URI.decode_query(payload),
         :ok <- check_expiry(claims, now),
         :ok <- check_expected_claims(claims, opts[:expect] || %{}) do
      {:ok, claims}
    else
      {:error, :expired} -> {:error, :expired}
      _ -> {:error, :invalid_token}
    end
  end

  def verify(_token, _opts), do: {:error, :invalid_token}

  @spec get_integer(map(), String.t(), integer() | nil) :: integer() | nil
  def get_integer(claims, key, default \\ nil) do
    case Integer.parse(to_string(Map.get(claims, key, ""))) do
      {value, ""} -> value
      _ -> default
    end
  end

  @spec random_id(non_neg_integer(), String.t()) :: String.t()
  def random_id(bytes \\ 18, prefix \\ "") do
    prefix <> b64_encode(:crypto.strong_rand_bytes(bytes))
  end

  defp sign_body(body, secret) when byte_size(secret) >= 16 do
    :crypto.mac(:hmac, :sha256, secret, body) |> b64_encode()
  end

  defp safe_equal?(left, right) when is_binary(left) and is_binary(right) do
    byte_size(left) == byte_size(right) and :crypto.hash_equals(left, right)
  end

  defp safe_equal?(_, _), do: false

  defp check_expiry(claims, now) do
    case get_integer(claims, "exp") do
      nil -> {:error, :invalid_token}
      exp when exp >= now -> :ok
      _ -> {:error, :expired}
    end
  end

  defp check_expected_claims(claims, expected) do
    matching =
      Enum.all?(expected, fn {key, value} ->
        Map.get(claims, to_string(key)) == to_string(value)
      end)

    if matching, do: :ok, else: {:error, :invalid_token}
  end

  defp b64_encode(binary), do: Base.url_encode64(binary, padding: false)
  defp b64_decode(string), do: Base.url_decode64(string, padding: false)

  defp secret! do
    case Application.get_env(:video_conf, :signing_secret) do
      secret when is_binary(secret) and byte_size(secret) >= 32 ->
        secret

      _ ->
        raise "video_conf signing_secret must be configured with at least 32 bytes"
    end
  end
end
