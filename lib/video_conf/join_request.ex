defmodule VideoConf.JoinRequest do
  @moduledoc """
  A normalized join attempt from web/app, SIP/H.323 gateway or PSTN DTMF flow.
  """

  alias VideoConf.Identity

  @enforce_keys [:meeting_id]
  defstruct [
    :meeting_id,
    assertion: nil,
    identity: Identity.anonymous(),
    passcode: nil,
    pin: nil,
    guest_token: nil,
    resume_token: nil,
    pow_token: nil,
    pow_nonce: nil,
    source_ip: nil,
    device_id: nil,
    call_id: nil,
    caller_number: nil,
    dial_in?: false,
    # Set only by a trusted API gateway after verifying an OIDC/session token.
    trusted_edge?: false,
    now_ms: nil
  ]

  @type t :: %__MODULE__{}

  @doc """
  Builds a request from ordinary API/controller params.

  `:trusted_edge?` is deliberately ignored here so a client cannot escalate by
  adding that key. Code running behind an already-authenticated gateway should
  call `new_trusted!/1` through `VideoConf.join_from_trusted_gateway/1`.
  """
  def new!(attrs) do
    attrs = attrs |> Map.new() |> Map.put(:trusted_edge?, false)
    build(attrs)
  end

  @doc "Builds a request while preserving a server-authenticated trusted identity."
  def new_trusted!(attrs) do
    attrs = attrs |> Map.new() |> Map.put(:trusted_edge?, true)
    build(attrs)
  end

  defp build(attrs) do
    dial_in? = attrs[:dial_in?] == true or attrs[:dial_in] == true

    call_id =
      attrs[:call_id] ||
        if(dial_in?, do: VideoConf.Token.random_id(8, "call_"), else: nil)

    attrs = Map.put(attrs, :call_id, call_id)

    identity =
      case attrs[:identity] do
        %Identity{} = identity -> identity
        map when is_map(map) -> Identity.new(map)
        _ -> maybe_dial_in_identity(Map.put(attrs, :dial_in?, dial_in?))
      end

    %__MODULE__{
      meeting_id: attrs[:meeting_id],
      assertion: attrs[:assertion],
      identity: identity,
      passcode: attrs[:passcode],
      pin: attrs[:pin],
      guest_token: attrs[:guest_token],
      resume_token: attrs[:resume_token],
      pow_token: attrs[:pow_token],
      pow_nonce: attrs[:pow_nonce],
      source_ip: attrs[:source_ip],
      device_id: attrs[:device_id],
      call_id: call_id,
      caller_number: attrs[:caller_number],
      dial_in?: dial_in?,
      trusted_edge?: attrs[:trusted_edge?] == true,
      now_ms: attrs[:now_ms]
    }
  end

  def source_key(%__MODULE__{} = request) do
    cond do
      is_binary(request.source_ip) and request.source_ip != "" ->
        "ip:" <> request.source_ip

      is_binary(request.device_id) and request.device_id != "" ->
        "dev:" <> request.device_id

      request.dial_in? and is_binary(request.caller_number) and request.caller_number != "" ->
        # Only use this when the PSTN/SIP gateway attests the caller number.
        "tel:" <> request.caller_number

      request.dial_in? and is_binary(request.call_id) ->
        "call:" <> request.call_id

      true ->
        "source:unknown"
    end
  end

  def principal_key(%__MODULE__{identity: %{principal_id: id}}) when is_binary(id), do: "p:" <> id
  def principal_key(_), do: "p:anonymous"

  defp maybe_dial_in_identity(attrs) do
    if attrs[:dial_in?] == true or attrs[:dial_in] == true do
      call_id = attrs[:call_id] || VideoConf.Token.random_id(8, "call_")
      Identity.dial_in(call_id, caller_number: attrs[:caller_number])
    else
      Identity.anonymous(attrs[:source_ip] || "unknown")
    end
  end
end
