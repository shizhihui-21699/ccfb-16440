defmodule VideoConf.Admission.Decision do
  @moduledoc "Result of a join attempt."

  @enforce_keys [:status]
  defstruct [
    :status,
    :reason,
    :public_reason,
    :meeting_id,
    :ticket,
    :role,
    :waiting_id,
    :waiting_token,
    :retry_after_ms,
    :challenge_token,
    :claims,
    :debug
  ]

  @type status ::
          :admitted | :waiting | :denied | :challenge | :rate_limited | :unavailable

  def admitted(meeting, ticket, role, claims \\ %{}) do
    %__MODULE__{
      status: :admitted,
      reason: :admitted,
      public_reason: nil,
      meeting_id: meeting.id,
      ticket: ticket,
      role: role,
      claims: claims
    }
  end

  def waiting(meeting, waiting_id, waiting_token) do
    %__MODULE__{
      status: :waiting,
      reason: :waiting_room,
      public_reason: "Waiting for host approval",
      meeting_id: meeting.id,
      waiting_id: waiting_id,
      waiting_token: waiting_token
    }
  end

  def denied(meeting_or_id, reason, public_reason \\ nil) do
    meeting_id =
      case meeting_or_id do
        %{id: id} -> id
        id when is_binary(id) -> id
        _ -> nil
      end

    %__MODULE__{
      status: :denied,
      reason: reason,
      public_reason: public_reason || public_message(reason),
      meeting_id: meeting_id
    }
  end

  def challenge(source_key) do
    token = VideoConf.ProofOfWork.issue_challenge(source_key)

    %__MODULE__{
      status: :challenge,
      reason: :additional_verification_required,
      public_reason: "Complete the quick verification to continue",
      challenge_token: token
    }
  end

  def rate_limited(retry_after_ms) do
    %__MODULE__{
      status: :rate_limited,
      reason: :rate_limited,
      public_reason: "Too many attempts. Please wait and try again.",
      retry_after_ms: retry_after_ms
    }
  end

  def unavailable do
    %__MODULE__{
      status: :unavailable,
      reason: :service_unavailable,
      public_reason: "Service is starting. Please retry shortly.",
      retry_after_ms: 1_000
    }
  end

  defp public_message(:invalid_meeting_or_credential), do: "Meeting ID or join code is incorrect"
  defp public_message(:meeting_locked), do: "Meeting is locked by the host"

  defp public_message(:organization_only),
    do: "This meeting is restricted to signed-in organization members"

  defp public_message(:banned), do: "You cannot rejoin this meeting"
  defp public_message(reason), do: reason |> to_string() |> String.replace("_", " ")
end
