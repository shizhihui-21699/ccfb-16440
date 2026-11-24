defmodule VideoConf.PresenceTest do
  use ExUnit.Case, async: false

  alias VideoConf.{Presence, RateLimiter}

  setup do
    RateLimiter.reset()
    :ok
  end

  test "ticket activation is idempotent and enforces the meeting capacity" do
    {:ok, meeting} =
      VideoConf.create_meeting(%{
        org_id: "cap-org",
        host_id: "cap-host",
        waiting_room?: false,
        auto_admit_org_members?: true,
        capacity: 2
      })

    assertion = fn id ->
      VideoConf.Identity.issue_assertion(%{principal_id: id, org_id: "cap-org"})
    end

    first = VideoConf.join(%{meeting_id: meeting.id, assertion: assertion.("u1")})
    second = VideoConf.join(%{meeting_id: meeting.id, assertion: assertion.("u2")})
    third = VideoConf.join(%{meeting_id: meeting.id, assertion: assertion.("u3")})

    assert :ok = Presence.activate(first.ticket, meeting)
    assert :ok = Presence.activate(second.ticket, meeting)
    assert :ok = Presence.activate(first.ticket, meeting)
    assert Presence.count(meeting.id) == 2

    # Reconnect rotates the outer ticket but keeps the same seat jti.
    resumed =
      VideoConf.join(%{meeting_id: meeting.id, resume_token: first.ticket})

    assert resumed.status == :admitted

    {:ok, original_claims} = VideoConf.JoinTicket.verify(first.ticket, meeting.id)
    {:ok, resumed_claims} = VideoConf.JoinTicket.verify(resumed.ticket, meeting.id)
    assert resumed_claims["jti"] == original_claims["jti"]
    assert :ok = Presence.activate(resumed.ticket, meeting)
    assert Presence.count(meeting.id) == 2

    assert {:error, :meeting_full} = Presence.activate(third.ticket, meeting)
    assert Presence.count(meeting.id) == 2

    assert :ok = Presence.leave(meeting.id, original_claims["jti"])
    assert Presence.count(meeting.id) == 1
  end
end
