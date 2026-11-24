defmodule VideoConf do
  @moduledoc """
  Public API for secure video-conference admission.

  Typical web request:

      assertion = VideoConf.Identity.issue_assertion(%{
        principal_id: "user_123",
        org_id: "acme",
        email: "alice@acme.com"
      })

      VideoConf.join(%{
        meeting_id: meeting.id,
        assertion: assertion,
        source_ip: "203.0.113.10"
      })

  PSTN gateway request after collecting the nine-digit meeting ID and PIN:

      VideoConf.dial_in(%{
        meeting_id: meeting.id,
        pin: "123456",
        call_id: call_id,
        caller_number: "+1555010000"
      })
  """

  alias VideoConf.{Admission, Identity, Store}

  def create_meeting(attrs), do: Store.create_meeting(attrs)
  def get_meeting(id), do: Store.get_meeting(id)

  @doc """
  Creates a meeting and binds host/org to a verified SSO assertion.

  HTTP controllers should use this rather than passing `host_id`/`org_id` from
  client parameters. `create_meeting/1` is the lower-level bootstrap/test API.
  """
  def create_meeting_for_host(host_assertion, attrs) when is_binary(host_assertion) do
    with {:ok, host} <- Identity.verify_assertion(host_assertion) do
      attrs =
        attrs
        |> Map.new()
        |> Map.put(:host_id, host.principal_id)
        |> Map.put(:org_id, host.org_id)

      Store.create_meeting(attrs)
    end
  end

  def join(attrs), do: Admission.join(attrs)

  @doc "Use only behind a gateway/session layer that has already authenticated the identity."
  def join_from_trusted_gateway(attrs), do: Admission.join_trusted(attrs)

  def dial_in(attrs) when is_list(attrs) or is_map(attrs) do
    attrs
    |> Map.new()
    |> Map.put(:dial_in?, true)
    |> Admission.join()
  end

  def lock(meeting_id, host), do: Admission.lock(meeting_id, host, true)
  def unlock(meeting_id, host), do: Admission.lock(meeting_id, host, false)

  def approve(meeting_id, waiting_id, host, opts \\ []),
    do: Admission.approve(meeting_id, waiting_id, host, opts)

  def reject(meeting_id, waiting_id, host, opts \\ []) do
    {reason, opts} = Keyword.pop(opts, :reason, :rejected_by_host)
    Admission.reject(meeting_id, waiting_id, host, reason, opts)
  end

  def admit_all(meeting_id, host), do: Admission.admit_all(meeting_id, host)

  def list_waiting(meeting_id, host, limit \\ 100),
    do: Admission.list_waiting(meeting_id, host, limit)

  def poll_waiting(token, opts \\ []), do: Admission.poll_waiting(token, opts)

  def activate_media_session(ticket, meeting), do: VideoConf.Presence.activate(ticket, meeting)
  def leave_media_session(meeting_id, jti), do: VideoConf.Presence.leave(meeting_id, jti)
  def presence_count(meeting_id), do: VideoConf.Presence.count(meeting_id)

  def issue_guest_invite(meeting_id, host, guest_id, opts \\ []),
    do: Admission.issue_guest_invite(meeting_id, host, guest_id, opts)

  def host_assertion(host_id, org_id, attrs \\ []) do
    attrs
    |> Map.new()
    |> Map.merge(%{principal_id: host_id, org_id: org_id})
    |> Identity.issue_assertion()
  end
end
