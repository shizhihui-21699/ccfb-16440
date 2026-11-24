defmodule VideoConf.Meeting do
  @moduledoc """
  Meeting policy and credential hashes.

  Hot join paths read this struct directly from an ETS table. Policy writes are
  rare and serialized by `VideoConf.Store`.
  """

  alias VideoConf.Credentials

  @enforce_keys [:id, :org_id, :host_id]
  defstruct [
    :id,
    :org_id,
    :host_id,
    :title,
    passcode_hash: nil,
    passcode_fast_hash: nil,
    passcode_numeric?: false,
    dial_in_pin_hash: nil,
    dial_in_pin_fast_hash: nil,
    allowed_org_ids: MapSet.new(),
    # :org_only | :org_and_invites | :anyone_with_passcode
    access_policy: :org_and_invites,
    external_guests_enabled?: true,
    waiting_room?: true,
    require_credential_to_wait?: false,
    auto_admit_org_members?: true,
    auto_admit_invited_guests?: true,
    auto_admit_passcode_guests?: false,
    large_event?: false,
    locked?: false,
    capacity: 10_000,
    bulk_admit_before_ms: 0,
    banned_principal_ids: MapSet.new(),
    banned_source_keys: MapSet.new(),
    inserted_at_ms: 0,
    updated_at_ms: 0,
    version: 1
  ]

  @type t :: %__MODULE__{}

  @doc """
  Builds a meeting. Plaintext `:passcode` and `:dial_in_pin` are hashed and are
  not retained on the struct.
  """
  def build(attrs) when is_map(attrs) or is_list(attrs) do
    attrs = Map.new(attrs)
    now = attrs[:now_ms] || System.system_time(:millisecond)
    id = attrs[:id] || Credentials.generate_meeting_id()

    if not valid_meeting_id?(id) do
      raise ArgumentError, "meeting id must be exactly nine digits"
    end

    org_id = Map.fetch!(attrs, :org_id)
    host_id = Map.fetch!(attrs, :host_id)
    passcode = attrs[:passcode]
    dial_in_pin = attrs[:dial_in_pin]

    if not is_nil(passcode) and (not is_binary(passcode) or String.length(passcode) < 4) do
      raise ArgumentError, "passcode must be a string of at least 4 characters"
    end

    if dial_in_pin && not Credentials.numeric?(dial_in_pin) do
      raise ArgumentError, "dial-in PIN must contain 4-12 digits"
    end

    allowed_org_ids =
      [org_id | List.wrap(attrs[:allowed_org_ids] || [])]
      |> MapSet.new()

    meeting = %__MODULE__{
      id: id,
      org_id: org_id,
      host_id: host_id,
      title: attrs[:title] || "Video meeting #{id}",
      passcode_hash: Credentials.hash(passcode),
      passcode_fast_hash: passcode && Credentials.fast_hash(passcode, "meeting-passcode"),
      passcode_numeric?: is_binary(passcode) and Credentials.numeric?(passcode),
      dial_in_pin_hash: Credentials.hash(dial_in_pin),
      dial_in_pin_fast_hash: dial_in_pin && Credentials.fast_hash(dial_in_pin, "dial-in-pin"),
      allowed_org_ids: allowed_org_ids,
      access_policy: attrs[:access_policy] || :org_and_invites,
      external_guests_enabled?: Map.get(attrs, :external_guests_enabled?, true),
      waiting_room?: Map.get(attrs, :waiting_room?, true),
      require_credential_to_wait?: Map.get(attrs, :require_credential_to_wait?, false),
      auto_admit_org_members?: Map.get(attrs, :auto_admit_org_members?, true),
      auto_admit_invited_guests?: Map.get(attrs, :auto_admit_invited_guests?, true),
      auto_admit_passcode_guests?: Map.get(attrs, :auto_admit_passcode_guests?, false),
      large_event?: Map.get(attrs, :large_event?, false),
      locked?: Map.get(attrs, :locked?, false),
      capacity: attrs[:capacity] || 10_000,
      banned_principal_ids: attrs[:banned_principal_ids] || MapSet.new(),
      banned_source_keys: attrs[:banned_source_keys] || MapSet.new(),
      inserted_at_ms: now,
      updated_at_ms: now
    }

    {:ok, meeting}
  end

  def build!(attrs) do
    {:ok, meeting} = build(attrs)
    meeting
  end

  def valid_meeting_id?(id), do: is_binary(id) and Regex.match?(~r/^[0-9]{9}$/, id)

  def dial_in_credential_available?(%__MODULE__{} = meeting) do
    not is_nil(meeting.dial_in_pin_hash) or
      (meeting.passcode_numeric? and not is_nil(meeting.passcode_hash))
  end

  def verify_dial_in_code(%__MODULE__{} = meeting, code) when is_binary(code) do
    cond do
      is_binary(meeting.dial_in_pin_fast_hash) ->
        Credentials.fast_verify(code, meeting.dial_in_pin_fast_hash, "dial-in-pin")

      is_binary(meeting.dial_in_pin_hash) ->
        Credentials.verify(code, meeting.dial_in_pin_hash)

      meeting.passcode_numeric? and is_binary(meeting.passcode_fast_hash) ->
        Credentials.fast_verify(code, meeting.passcode_fast_hash, "meeting-passcode")

      meeting.passcode_numeric? and is_binary(meeting.passcode_hash) ->
        Credentials.verify(code, meeting.passcode_hash)

      true ->
        Credentials.verify(code, nil)
        false
    end
  end

  def verify_dial_in_code(%__MODULE__{}, _), do: false

  def verify_passcode(%__MODULE__{passcode_hash: nil}, nil), do: :not_set
  def verify_passcode(%__MODULE__{passcode_hash: nil}, _code), do: :not_set

  def verify_passcode(%__MODULE__{passcode_hash: hash}, nil) when is_binary(hash),
    do: :missing

  def verify_passcode(%__MODULE__{} = meeting, code) when is_binary(code) do
    verified? =
      cond do
        is_binary(meeting.passcode_fast_hash) ->
          Credentials.fast_verify(code, meeting.passcode_fast_hash, "meeting-passcode")

        is_binary(meeting.passcode_hash) ->
          Credentials.verify(code, meeting.passcode_hash)

        true ->
          false
      end

    if verified?, do: :ok, else: :invalid
  end
end
