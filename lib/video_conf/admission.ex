defmodule VideoConf.Admission do
  @moduledoc """
  Stateless-ish admission policy and waiting-room workflow.

  The hot path reads meeting policy from ETS and verifies HMAC/PBKDF2 material;
  it does not serialize all joins through one meeting process. Expensive host
  decisions are low-frequency and use atomic ETS transitions.
  """

  alias VideoConf.{
    Credentials,
    GuestInvite,
    Identity,
    JoinRequest,
    JoinTicket,
    Meeting,
    ProofOfWork,
    RateLimiter,
    Store,
    Token,
    WaitingRoom
  }

  alias VideoConf.Admission.Decision

  ## Join flow

  def join(attrs) do
    attrs
    |> JoinRequest.new!()
    |> run_join()
  end

  @doc """
  Join path for a trusted API gateway/session plug that has already verified
  the user and supplies a server-built `%Identity{}`. Never expose this
  function directly to unvalidated request params.
  """
  def join_trusted(attrs) do
    attrs
    |> JoinRequest.new_trusted!()
    |> run_join()
  end

  defp run_join(request0) do
    request = with_now(request0)
    source = JoinRequest.source_key(request)

    with :ok <- enforce_source_attempt_limit(request, source),
         {:ok, request} <- resolve_identity(request),
         :ok <- enforce_principal_attempt_limit(request, source) do
      join_after_rate_limit(request, source)
    else
      {:limit, %Decision{} = limited} -> limited
      {:error, %Decision{} = decision} -> decision
    end
  end

  defp join_after_rate_limit(request, source) do
    if not Meeting.valid_meeting_id?(request.meeting_id) do
      equalize_credential_timing(request)
      register_failure("invalid-id", source, request.now_ms)
      Decision.denied(request.meeting_id || "000000000", :invalid_meeting_or_credential)
    else
      case Store.get_meeting(request.meeting_id) do
        {:error, :not_found} ->
          handle_unknown_meeting(request, source)

        {:error, :not_ready} ->
          Decision.unavailable()

        {:ok, meeting} ->
          handle_existing_meeting(meeting, request, source)
      end
    end
  end

  defp handle_unknown_meeting(request, source) do
    # Perform comparable fast-pepper verification work and count guessing, but
    # do not reveal whether the nine-digit meeting exists.
    equalize_credential_timing(request)

    case register_failure(request.meeting_id, source, request.now_ms) do
      {:challenge, decision} -> decision
      {:rate_limited, decision} -> decision
      :ok -> Decision.denied(request.meeting_id, :invalid_meeting_or_credential)
    end
  end

  defp equalize_credential_timing(request) do
    Credentials.fast_hash(request.passcode || "dummy-passcode", "meeting-passcode")

    if request.dial_in? do
      Credentials.fast_hash(
        request.pin || request.passcode || "000000",
        "dial-in-pin"
      )
    end

    :ok
  rescue
    _ -> :ok
  end

  defp handle_existing_meeting(meeting, request0, source) do
    now = request0.now_ms

    {resume_claims, request} = valid_resume(meeting, request0)

    with :ok <- check_ban(meeting, request, source),
         :ok <- check_lock(meeting, request, resume_claims != nil) do
      cond do
        resume_claims != nil ->
          role = resume_claims["role"] || "participant"

          # Keep the same jti so Presence treats token rotation/reconnect as
          # the same seat instead of double-counting or rejecting at capacity.
          ticket =
            JoinTicket.issue(meeting, request.identity, role,
              now: seconds(now),
              jti: resume_claims["jti"]
            )

          Decision.admitted(meeting, ticket, String.to_existing_atom(role), resume_claims)

        Identity.verified_host?(request.identity, meeting) ->
          ticket = JoinTicket.issue(meeting, request.identity, :host, now: seconds(now))
          Decision.admitted(meeting, ticket, :host)

        true ->
          join_as_non_host(meeting, request, source, now)
      end
    else
      {:error, %Decision{} = decision} -> decision
    end
  end

  defp join_as_non_host(meeting, request, source, now) do
    trusted_identity? =
      Identity.verified_org_member?(request.identity, meeting.allowed_org_ids) or
        valid_guest_token?(meeting, request)

    risk_result =
      if trusted_identity?,
        do: :ok,
        else: risk_gate(meeting, request, source, now)

    case risk_result do
      {:challenge, decision} ->
        decision

      :ok ->
        case authenticate(meeting, request, source, now) do
          {:credential_failure, decision} ->
            decision

          {:ok, auth} ->
            clear_source_failures_on_success(meeting, source, auth, now)
            decide(meeting, request, auth, now)
        end
    end
  end

  ## Host controls

  def lock(meeting_id, host, locked? \\ true) do
    with_host(meeting_id, host, fn _meeting ->
      Store.update_meeting(meeting_id, &%{&1 | locked?: locked?})
    end)
  end

  def unlock(meeting_id, host), do: lock(meeting_id, host, false)

  def set_waiting_room(meeting_id, host, enabled?) do
    with_host(meeting_id, host, fn _meeting ->
      Store.update_meeting(meeting_id, &%{&1 | waiting_room?: enabled?})
    end)
  end

  def admit_all(meeting_id, host, now_ms \\ System.system_time(:millisecond)) do
    with_host(meeting_id, host, fn meeting ->
      pending = WaitingRoom.count_pending(meeting_id, meeting.bulk_admit_before_ms)

      with {:ok, updated} <-
             Store.update_meeting(meeting_id, &%{&1 | bulk_admit_before_ms: now_ms}) do
        {:ok, %{meeting: updated, admitted: pending}}
      end
    end)
  end

  def approve(meeting_id, waiting_id, host, opts \\ []) do
    with_host(meeting_id, host, fn meeting ->
      now = opts[:now_ms] || System.system_time(:millisecond)

      with {:ok, waiting} <- WaitingRoom.get(meeting_id, waiting_id) do
        role = opts[:role] || :participant
        ticket = JoinTicket.issue(meeting, waiting.identity, role, now: seconds(now))

        case WaitingRoom.record_decision(
               meeting_id,
               waiting_id,
               :approved,
               host_principal(host),
               ticket,
               now
             ) do
          {:ok, %{status: :approved} = decision} ->
            {:ok, Map.put(decision, :ticket, ticket)}

          {:ok, %{status: :rejected}} ->
            {:error, :already_rejected}

          other ->
            other
        end
      end
    end)
  end

  def reject(meeting_id, waiting_id, host, reason \\ :rejected_by_host, opts \\ []) do
    with_host(meeting_id, host, fn _meeting ->
      now = opts[:now_ms] || System.system_time(:millisecond)

      case WaitingRoom.record_decision(
             meeting_id,
             waiting_id,
             :rejected,
             host_principal(host),
             nil,
             now
           ) do
        {:ok, %{status: :rejected} = decision} ->
          {:ok, Map.put(decision, :reason, reason)}

        {:ok, %{status: :approved}} ->
          {:error, :already_approved}

        other ->
          other
      end
    end)
  end

  def list_waiting(meeting_id, host, limit \\ 100) do
    with_host(meeting_id, host, fn meeting ->
      {:ok, WaitingRoom.list_pending(meeting_id, meeting.bulk_admit_before_ms, limit)}
    end)
  end

  def issue_guest_invite(meeting_id, host, guest_id, opts \\ []) do
    with_host(meeting_id, host, fn meeting ->
      {:ok, GuestInvite.issue(meeting, guest_id, opts)}
    end)
  end

  def poll_waiting(waiting_token, opts \\ []) do
    now = opts[:now_ms] || System.system_time(:millisecond)

    with {:ok, claims} <- Token.verify(waiting_token, now: seconds(now)),
         "waiting" <- Map.get(claims, "typ"),
         meeting_id <- claims["mid"],
         waiting_id <- claims["wid"],
         {:ok, meeting} <- Store.get_meeting(meeting_id),
         {:ok, waiting} <- WaitingRoom.get(meeting_id, waiting_id) do
      cond do
        waiting.expires_at_ms < now ->
          {:ok, Decision.denied(meeting, :waiting_expired)}

        meeting.bulk_admit_before_ms >= waiting.requested_at_ms ->
          ticket = JoinTicket.issue(meeting, waiting.identity, :participant, now: seconds(now))
          {:ok, Decision.admitted(meeting, ticket, :participant, %{"bulk" => "true"})}

        true ->
          case WaitingRoom.get_decision(meeting_id, waiting_id) do
            {:ok, %{status: :approved}} ->
              # Issue a fresh short-lived ticket on each poll. The ticket stored
              # on the decision is an audit record and may already be close to
              # its 60-second expiry if the client polled late.
              ticket =
                JoinTicket.issue(meeting, waiting.identity, :participant, now: seconds(now))

              {:ok, Decision.admitted(meeting, ticket, :participant)}

            {:ok, %{status: :rejected}} ->
              {:ok, Decision.denied(meeting, :rejected_by_host)}

            :pending ->
              {:ok, Decision.waiting(meeting, waiting_id, waiting_token)}
          end
      end
    else
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_waiting_token}
    end
  end

  ## Rate limiting and risk

  defp enforce_source_attempt_limit(request, source) do
    limits = config(:limits, default_limits())
    {source_limit, source_window} = limits[:source_attempts]

    hit_limit({:attempt, :source, source}, source_limit, source_window, request.now_ms)
  end

  defp enforce_principal_attempt_limit(request, source) do
    limits = config(:limits, default_limits())
    {principal_limit, principal_window} = limits[:principal_attempts]

    # Before identity verification the client can supply any principal id, so
    # key unverified callers by source instead of their self-declared id.
    key =
      if request.identity.verified_org? do
        {:attempt, :principal, JoinRequest.principal_key(request)}
      else
        {:attempt, :unverified_source, source}
      end

    hit_limit(key, principal_limit, principal_window, request.now_ms)
  end

  defp hit_limit(key, limit, window, now) do
    case RateLimiter.hit(key, limit, window, now) do
      {:ok, _count} ->
        :ok

      {:error, :rate_limited, retry_after} ->
        {:limit, Decision.rate_limited(retry_after)}

      {:error, :rate_limiter_unavailable, retry_after} ->
        {:limit, Decision.rate_limited(retry_after)}
    end
  end

  defp risk_gate(meeting, request, source, now) do
    limits = config(:limits, default_limits())
    {soft_limit, window} = limits[:source_failures]
    {meeting_source_limit, _window} = limits[:meeting_source_failures]
    {meeting_limit, meeting_window} = limits[:meeting_failures]

    source_failures = RateLimiter.peek({:failure, :source, source}, window, now)

    meeting_source_failures =
      RateLimiter.peek({:failure, :meeting_source, meeting.id, source}, window, now)

    meeting_failures =
      RateLimiter.peek({:failure, :meeting, meeting.id}, meeting_window, now)

    suspicious? =
      source_failures >= soft_limit or
        meeting_source_failures >= meeting_source_limit or
        meeting_failures >= meeting_limit

    if suspicious? do
      case ProofOfWork.verify_solution(
             request.pow_token,
             source,
             request.pow_nonce,
             now: seconds(now)
           ) do
        :ok -> :ok
        {:error, _} -> {:challenge, Decision.challenge(source)}
      end
    else
      :ok
    end
  end

  defp clear_source_failures_on_success(meeting, source, auth, now) do
    if auth.method in [:passcode, :dial_pin, :guest_token] do
      limits = config(:limits, default_limits())
      {_hard_limit, hard_window} = limits[:hard_source_failures]

      RateLimiter.reset_key({:failure, :source, source}, hard_window, now)

      RateLimiter.reset_key(
        {:failure, :meeting_source, meeting.id, source},
        hard_window,
        now
      )
    end

    :ok
  end

  defp register_failure(meeting_id, source, now) do
    limits = config(:limits, default_limits())
    {soft_limit, _window} = limits[:source_failures]
    {meeting_source_limit, _} = limits[:meeting_source_failures]
    {meeting_global_limit, meeting_global_window} = limits[:meeting_failures]
    {hard_limit, hard_window} = limits[:hard_source_failures]
    # Global meeting guessing wave. The threshold is checked by risk_gate; the
    # high counter cap only keeps the atomic counter well-defined.
    RateLimiter.hit(
      {:failure, :meeting, meeting_id},
      max(meeting_global_limit * 100, 100_000),
      meeting_global_window,
      now
    )

    # Use the hard counter/window as the canonical source-failure counter. The
    # soft threshold is derived from its count.
    case RateLimiter.hit({:failure, :source, source}, hard_limit, hard_window, now) do
      {:error, :rate_limited, retry_after} ->
        {:rate_limited, Decision.rate_limited(retry_after)}

      {:ok, source_count} ->
        {:ok, meeting_source_count} =
          RateLimiter.hit(
            {:failure, :meeting_source, meeting_id, source},
            hard_limit,
            hard_window,
            now
          )

        cond do
          meeting_source_count >= meeting_source_limit ->
            {:challenge, Decision.challenge(source)}

          source_count >= soft_limit ->
            {:challenge, Decision.challenge(source)}

          true ->
            :ok
        end
    end
  end

  ## Authentication and policy

  defp resolve_identity(%JoinRequest{assertion: assertion} = request)
       when is_binary(assertion) do
    case Identity.verify_assertion(assertion) do
      {:ok, identity} -> {:ok, %{request | identity: identity}}
      {:error, _} -> {:error, Decision.denied("000000000", :invalid_assertion)}
    end
  end

  defp resolve_identity(%JoinRequest{trusted_edge?: true} = request), do: {:ok, request}

  defp resolve_identity(%JoinRequest{identity: identity} = request) do
    # Never trust a raw client-supplied verified org identity or copied proof.
    scrubbed = %{
      identity
      | verified_org?: false,
        proof: nil,
        auth_method: identity.auth_method || :anonymous
    }

    {:ok, %{request | identity: scrubbed}}
  end

  defp valid_resume(meeting, request) do
    if is_binary(request.resume_token) do
      case JoinTicket.verify(request.resume_token, meeting.id) do
        {:ok, claims} ->
          identity = %Identity{
            principal_id: claims["pid"],
            org_id: empty_to_nil(claims["org"]),
            auth_method: :resume,
            verified_org?: claims["role"] in ["host", "participant"]
          }

          {claims, %{request | identity: identity}}

        _ ->
          {nil, request}
      end
    else
      {nil, request}
    end
  end

  defp check_ban(meeting, request, source) do
    if MapSet.member?(meeting.banned_principal_ids, request.identity.principal_id) or
         MapSet.member?(meeting.banned_source_keys, source) do
      {:error, Decision.denied(meeting, :banned)}
    else
      :ok
    end
  end

  defp check_lock(_meeting, _request, true = _resume?), do: :ok

  defp check_lock(meeting, request, false) do
    if meeting.locked? and not Identity.verified_host?(request.identity, meeting) do
      {:error, Decision.denied(meeting, :meeting_locked)}
    else
      :ok
    end
  end

  defp authenticate(meeting, request, source, now) do
    cond do
      valid_guest_token?(meeting, request) ->
        {:ok, %{method: :guest_token, role: guest_role(request.guest_token, meeting.id)}}

      request.dial_in? ->
        authenticate_dial_in(meeting, request, source, now)

      is_binary(request.passcode) ->
        case Meeting.verify_passcode(meeting, request.passcode) do
          :ok ->
            {:ok, %{method: :passcode, role: :participant}}

          :invalid ->
            failure_or_deny(meeting, source, now, :invalid_meeting_or_credential)

          :not_set ->
            {:ok, %{method: :none, role: :participant}}
        end

      true ->
        {:ok, %{method: :none, role: :participant}}
    end
  end

  defp authenticate_dial_in(meeting, request, source, now) do
    code = request.pin || request.passcode

    cond do
      not is_binary(code) or not Credentials.numeric?(code) ->
        {:credential_failure, Decision.denied(meeting, :numeric_pin_required)}

      Meeting.verify_dial_in_code(meeting, code) ->
        {:ok, %{method: :dial_pin, role: :participant}}

      true ->
        failure_or_deny(meeting, source, now, :invalid_meeting_or_credential)
    end
  end

  defp failure_or_deny(meeting, source, now, reason) do
    case register_failure(meeting.id, source, now) do
      {:challenge, decision} -> {:credential_failure, decision}
      {:rate_limited, decision} -> {:credential_failure, decision}
      :ok -> {:credential_failure, Decision.denied(meeting, reason)}
    end
  end

  defp decide(meeting, request, auth, now) do
    org_member? = Identity.verified_org_member?(request.identity, meeting.allowed_org_ids)
    invited? = auth.method == :guest_token and meeting.external_guests_enabled?
    passcode_ok? = auth.method in [:passcode, :dial_pin]

    {trust, authorized?} =
      cond do
        org_member? -> {:org_member, true}
        invited? -> {:invited_guest, true}
        passcode_ok? and meeting.access_policy == :anyone_with_passcode -> {:passcode_guest, true}
        passcode_ok? -> {:passcode_guest, false}
        true -> {:anonymous, false}
      end

    auto_bypass? =
      meeting.large_event? or
        case trust do
          :org_member -> meeting.auto_admit_org_members?
          :invited_guest -> meeting.auto_admit_invited_guests?
          :passcode_guest -> meeting.auto_admit_passcode_guests?
          :anonymous -> false
        end

    cond do
      authorized? and (not meeting.waiting_room? or auto_bypass?) ->
        ticket = JoinTicket.issue(meeting, request.identity, auth.role, now: seconds(now))
        Decision.admitted(meeting, ticket, auth.role, %{"trust" => to_string(trust)})

      meeting.waiting_room? and can_enter_waiting_room?(meeting, trust, auth) ->
        create_waiting_decision(meeting, request, trust, now)

      authorized? and not meeting.waiting_room? ->
        ticket = JoinTicket.issue(meeting, request.identity, auth.role, now: seconds(now))
        Decision.admitted(meeting, ticket, auth.role)

      true ->
        reason =
          if meeting.access_policy == :org_only,
            do: :organization_only,
            else: :authentication_required

        Decision.denied(meeting, reason)
    end
  end

  defp can_enter_waiting_room?(meeting, trust, auth) do
    cond do
      trust in [:org_member, :invited_guest] -> true
      not meeting.require_credential_to_wait? -> true
      auth.method in [:passcode, :dial_pin, :guest_token] -> true
      true -> false
    end
  end

  defp create_waiting_decision(meeting, request, trust, now) do
    source = JoinRequest.source_key(request)

    {:ok, waiting} =
      WaitingRoom.create(meeting.id, request.identity,
        reason: trust,
        source_key: source,
        now_ms: now
      )

    token =
      Token.sign(
        %{
          "typ" => "waiting",
          "mid" => meeting.id,
          "wid" => waiting.id,
          "pid" => request.identity.principal_id
        },
        ttl: Application.get_env(:video_conf, :waiting_token_ttl_seconds, 900),
        now: seconds(now)
      )

    Decision.waiting(meeting, waiting.id, token)
  end

  defp valid_guest_token?(meeting, request) do
    is_binary(request.guest_token) and
      match?({:ok, _}, GuestInvite.verify(request.guest_token, meeting.id))
  end

  defp guest_role(token, meeting_id) do
    case GuestInvite.verify(token, meeting_id) do
      {:ok, %{"role" => role}} -> String.to_existing_atom(role)
      _ -> :guest
    end
  rescue
    ArgumentError -> :guest
  end

  ## Host helper

  defp with_host(meeting_id, %Identity{} = host, fun) do
    with {:ok, meeting} <- Store.get_meeting(meeting_id),
         true <- Identity.verified_host?(host, meeting) do
      fun.(meeting)
    else
      false -> {:error, :not_authorized}
      {:error, :not_found} -> {:error, :not_found}
      other -> other
    end
  end

  defp with_host(meeting_id, assertion, fun) when is_binary(assertion) do
    case Identity.verify_assertion(assertion) do
      {:ok, host} -> with_host(meeting_id, host, fun)
      _ -> {:error, :not_authorized}
    end
  end

  defp host_principal(%Identity{principal_id: id}), do: id
  defp host_principal(_), do: "host"

  ## Helpers

  defp with_now(%JoinRequest{now_ms: nil} = request),
    do: %{request | now_ms: System.system_time(:millisecond)}

  defp with_now(request), do: request

  defp seconds(ms), do: div(ms, 1000)

  defp empty_to_nil(""), do: nil
  defp empty_to_nil(value), do: value

  defp config(key, default) do
    Application.get_env(:video_conf, key, default)
  end

  defp default_limits do
    [
      source_attempts: {120, 60_000},
      principal_attempts: {60, 60_000},
      source_failures: {10, 600_000},
      meeting_source_failures: {5, 600_000},
      meeting_failures: {500, 600_000},
      hard_source_failures: {120, 600_000}
    ]
  end
end
