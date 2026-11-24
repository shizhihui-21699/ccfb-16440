defmodule VideoConf.AdmissionTest do
  use ExUnit.Case, async: false

  alias VideoConf.{Identity, ProofOfWork, RateLimiter}
  alias VideoConf.Admission.Decision

  setup do
    RateLimiter.reset()

    host_assertion =
      Identity.issue_assertion(%{principal_id: "host-1", org_id: "acme"})

    {:ok, meeting} =
      VideoConf.create_meeting(%{
        org_id: "acme",
        host_id: "host-1",
        passcode: "secret-code",
        dial_in_pin: "246810",
        waiting_room?: true
      })

    %{meeting: meeting, host_assertion: host_assertion}
  end

  defp unique_source, do: "test-" <> Integer.to_string(System.unique_integer([:positive]))

  defp org_user(id \\ "alice", org \\ "acme") do
    Identity.issue_assertion(%{principal_id: id, org_id: org, email: "#{id}@example.com"})
  end

  test "verified organization member is admitted without waiting", %{meeting: meeting} do
    decision =
      VideoConf.join(%{
        meeting_id: meeting.id,
        assertion: org_user(),
        source_ip: unique_source()
      })

    assert %Decision{status: :admitted, role: :participant} = decision
    assert is_binary(decision.ticket)

    assert {:ok, claims} = VideoConf.JoinTicket.verify(decision.ticket, meeting.id)
    assert claims["pid"] == "alice"
  end

  test "create_meeting_for_host binds host and org to the verified assertion" do
    attacker_controlled_attrs = %{
      host_id: "someone-else",
      org_id: "evil-org",
      title: "forced values should be overwritten"
    }

    host_assertion =
      Identity.issue_assertion(%{principal_id: "verified-host", org_id: "acme"})

    assert {:ok, meeting} =
             VideoConf.create_meeting_for_host(host_assertion, attacker_controlled_attrs)

    assert meeting.host_id == "verified-host"
    assert meeting.org_id == "acme"
  end

  test "raw client input cannot forge verified organization identity or trusted edge", %{
    meeting: meeting
  } do
    forged = %Identity{
      principal_id: "mallory",
      org_id: "acme",
      verified_org?: true,
      proof: "forged-proof"
    }

    decision =
      VideoConf.join(%{
        meeting_id: meeting.id,
        source_ip: unique_source(),
        identity: forged,
        # Must be ignored on the public join path.
        trusted_edge?: true
      })

    assert decision.status == :waiting

    assert {:error, :not_authorized} = VideoConf.lock(meeting.id, forged)
  end

  test "external guest token admits invited guest", %{
    meeting: meeting,
    host_assertion: host
  } do
    assert {:ok, token} =
             VideoConf.issue_guest_invite(meeting.id, host, "guest-42", ttl: 600)

    decision =
      VideoConf.join(%{
        meeting_id: meeting.id,
        guest_token: token,
        display_name: "External Guest",
        source_ip: unique_source()
      })

    assert decision.status == :admitted
    assert decision.claims["trust"] == "invited_guest"
  end

  test "waiting guest can be approved and then poll an admission ticket", %{
    meeting: meeting,
    host_assertion: host
  } do
    source = unique_source()

    waiting =
      VideoConf.join(%{
        meeting_id: meeting.id,
        source_ip: source,
        identity: Identity.new(principal_id: "external-1", display_name: "External One")
      })

    assert waiting.status == :waiting
    assert is_binary(waiting.waiting_token)

    assert {:ok, approval} =
             VideoConf.approve(meeting.id, waiting.waiting_id, host)

    assert approval.status == :approved
    assert is_binary(approval.ticket)

    assert {:ok, admitted} = VideoConf.poll_waiting(waiting.waiting_token)
    assert admitted.status == :admitted
    assert is_binary(admitted.ticket)
  end

  test "host can reject a waiting participant", %{meeting: meeting, host_assertion: host} do
    waiting =
      VideoConf.join(%{meeting_id: meeting.id, source_ip: unique_source()})

    assert {:ok, _} = VideoConf.reject(meeting.id, waiting.waiting_id, host)
    assert {:ok, rejected} = VideoConf.poll_waiting(waiting.waiting_token)
    assert rejected.status == :denied
    assert rejected.reason == :rejected_by_host
  end

  test "reject after approval is a conflict, and host id alone does not cross organizations", %{
    meeting: meeting,
    host_assertion: host
  } do
    waiting = VideoConf.join(%{meeting_id: meeting.id, source_ip: unique_source()})

    assert {:ok, _} = VideoConf.approve(meeting.id, waiting.waiting_id, host)
    assert {:error, :already_approved} = VideoConf.reject(meeting.id, waiting.waiting_id, host)

    foreign_host =
      Identity.issue_assertion(%{principal_id: "host-1", org_id: "not-acme"})

    assert {:error, :not_authorized} = VideoConf.lock(meeting.id, foreign_host)
  end

  test "admit all uses one cutoff instead of rewriting every waiting row", %{
    meeting: meeting,
    host_assertion: host
  } do
    one = VideoConf.join(%{meeting_id: meeting.id, source_ip: unique_source()})
    two = VideoConf.join(%{meeting_id: meeting.id, source_ip: unique_source()})

    assert {:ok, %{admitted: 2}} = VideoConf.admit_all(meeting.id, host)
    assert {:ok, first} = VideoConf.poll_waiting(one.waiting_token)
    assert {:ok, second} = VideoConf.poll_waiting(two.waiting_token)

    assert first.status == :admitted
    assert second.status == :admitted
  end

  test "locked meeting rejects new participants but admits host and valid resume ticket", %{
    meeting: meeting,
    host_assertion: host
  } do
    source = unique_source()

    admitted =
      VideoConf.join(%{meeting_id: meeting.id, assertion: org_user("bob"), source_ip: source})

    assert admitted.status == :admitted
    assert {:ok, _} = VideoConf.lock(meeting.id, host)

    locked_out =
      VideoConf.join(%{
        meeting_id: meeting.id,
        assertion: org_user("carol"),
        source_ip: unique_source()
      })

    assert locked_out.status == :denied
    assert locked_out.reason == :meeting_locked

    reconnected =
      VideoConf.join(%{
        meeting_id: meeting.id,
        resume_token: admitted.ticket,
        source_ip: source
      })

    assert reconnected.status == :admitted

    host_decision =
      VideoConf.join(%{
        meeting_id: meeting.id,
        assertion: host,
        source_ip: unique_source()
      })

    assert host_decision.status == :admitted
    assert host_decision.role == :host
  end

  test "PSTN caller can join with digits-only PIN and then be approved", %{
    meeting: meeting,
    host_assertion: host
  } do
    waiting =
      VideoConf.dial_in(%{
        meeting_id: meeting.id,
        pin: "246810",
        call_id: "call-123",
        caller_number: "+15550101234"
      })

    assert waiting.status == :waiting

    assert {:ok, _} = VideoConf.approve(meeting.id, waiting.waiting_id, host)
    assert {:ok, admitted} = VideoConf.poll_waiting(waiting.waiting_token)
    assert admitted.status == :admitted
  end

  test "PSTN rejects non-numeric or wrong PIN", %{meeting: meeting} do
    bad_format =
      VideoConf.dial_in(%{meeting_id: meeting.id, pin: "abc", call_id: "call-bad-format"})

    assert bad_format.status == :denied
    assert bad_format.reason == :numeric_pin_required

    {:ok, pin_meeting} =
      VideoConf.create_meeting(%{org_id: "acme", host_id: "h", dial_in_pin: "111222"})

    wrong =
      VideoConf.dial_in(%{meeting_id: pin_meeting.id, pin: "999888", call_id: "call-wrong"})

    assert wrong.status == :denied
  end

  test "organization-only meeting denies members of other organizations", %{} do
    RateLimiter.reset()

    {:ok, meeting} =
      VideoConf.create_meeting(%{
        org_id: "acme",
        host_id: "host-1",
        access_policy: :org_only,
        waiting_room?: false
      })

    decision =
      VideoConf.join(%{
        meeting_id: meeting.id,
        assertion: org_user("outsider", "globex"),
        source_ip: unique_source()
      })

    assert decision.status == :denied
    assert decision.reason == :organization_only

    member =
      VideoConf.join(%{
        meeting_id: meeting.id,
        assertion: org_user("insider", "acme"),
        source_ip: unique_source()
      })

    assert member.status == :admitted
  end

  test "repeated wrong codes trigger proof-of-work, which allows the next correct attempt", %{
    meeting: meeting
  } do
    source = unique_source()

    decisions =
      for _ <- 1..4 do
        VideoConf.join(%{
          meeting_id: meeting.id,
          passcode: "wrong",
          source_ip: source
        })
      end

    assert Enum.all?(decisions, &(&1.status == :denied))

    challenged =
      VideoConf.join(%{meeting_id: meeting.id, passcode: "wrong", source_ip: source})

    assert challenged.status == :challenge
    assert is_binary(challenged.challenge_token)

    # Without a solved challenge, even a correct code is asked to verify.
    still_challenged =
      VideoConf.join(%{
        meeting_id: meeting.id,
        passcode: "secret-code",
        source_ip: source
      })

    assert still_challenged.status == :challenge

    assert {:ok, solution} = ProofOfWork.solve(challenged.challenge_token)

    solved =
      VideoConf.join(%{
        meeting_id: meeting.id,
        passcode: "secret-code",
        source_ip: source,
        pow_token: solution.challenge_token,
        pow_nonce: solution.nonce
      })

    # Default policy recognizes the code but passcode guests do not bypass the
    # waiting room unless the host enables that option.
    assert solved.status == :waiting
  end

  test "nonexistent and wrong-code responses use the same public reason", %{meeting: meeting} do
    source = unique_source()

    missing =
      VideoConf.join(%{meeting_id: "999999999", passcode: "whatever", source_ip: source <> "-a"})

    wrong =
      VideoConf.join(%{
        meeting_id: meeting.id,
        passcode: "nope",
        source_ip: source <> "-b"
      })

    assert missing.status == :denied
    assert wrong.status == :denied
    assert missing.public_reason == wrong.public_reason
  end
end
