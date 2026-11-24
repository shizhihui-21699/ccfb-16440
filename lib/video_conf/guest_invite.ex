defmodule VideoConf.GuestInvite do
  @moduledoc """
  Time-boxed external-guest invite token.

  The link fragment can carry this token. It proves that a host invited this
  guest, while the guest may still be placed in the waiting room depending on
  meeting policy.
  """

  alias VideoConf.Token

  def issue(meeting, guest_id, opts \\ []) do
    ttl = opts[:ttl] || Application.get_env(:video_conf, :guest_invite_ttl_seconds, 86_400)
    role = opts[:role] || :guest
    jti = opts[:jti] || Token.random_id(12)

    Token.sign(
      %{
        "typ" => "guest_invite",
        "mid" => meeting.id,
        "gid" => guest_id,
        "role" => to_string(role),
        "jti" => jti
      },
      ttl: ttl,
      now: opts[:now]
    )
  end

  def verify(token, meeting_id, opts \\ []) do
    expected = %{"typ" => "guest_invite", "mid" => meeting_id}

    with {:ok, claims} <- Token.verify(token, Keyword.put(opts, :expect, expected)),
         false <- VideoConf.Store.jti_revoked?(claims["jti"]) do
      {:ok, claims}
    else
      true -> {:error, :revoked}
      error -> error
    end
  end

  def revoke!(token) do
    # Verification is intentionally not required here because hosts may revoke
    # an already-expired token's jti after parsing it elsewhere if desired.
    case VideoConf.Token.verify(token) do
      {:ok, %{"jti" => jti, "exp" => exp}} ->
        ttl = max(String.to_integer(exp) - System.system_time(:second), 1)
        VideoConf.Store.revoke_jti(jti, ttl)

      _ ->
        :error
    end
  end
end
