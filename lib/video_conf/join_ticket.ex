defmodule VideoConf.JoinTicket do
  @moduledoc """
  Short-lived ticket exchanged with the media edge.

  The media servers can verify the HMAC ticket locally; they do not need to call
  the meeting GenServer for every participant or reconnect.
  """

  alias VideoConf.Token

  def issue(meeting, identity, role \\ :participant, opts \\ []) do
    ttl = Application.get_env(:video_conf, :join_ticket_ttl_seconds, 60)
    jti = opts[:jti] || Token.random_id(12)

    Token.sign(
      %{
        "typ" => "join_ticket",
        "mid" => meeting.id,
        "pid" => identity.principal_id,
        "org" => identity.org_id || "",
        "role" => to_string(role),
        "jti" => jti
      },
      Keyword.put_new(opts, :ttl, ttl)
    )
  end

  def verify(token, meeting_id, opts \\ []) do
    expected = %{"typ" => "join_ticket", "mid" => meeting_id}

    case Token.verify(token, Keyword.update(opts, :expect, expected, &Map.merge(&1, expected))) do
      {:ok, claims} ->
        if VideoConf.Store.jti_revoked?(claims["jti"]) do
          {:error, :revoked}
        else
          {:ok, claims}
        end

      error ->
        error
    end
  end
end
