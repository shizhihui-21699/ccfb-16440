defmodule VideoConf.ScaleTest do
  use ExUnit.Case, async: false

  alias VideoConf.{Identity, RateLimiter, WaitingRoom}

  @moduletag :scale
  @participants 10_000

  setup do
    RateLimiter.reset()
    :ok
  end

  test "10,000 large-event attendees receive tickets without host serialization" do
    {:ok, meeting} =
      VideoConf.create_meeting(%{
        org_id: "launch-org",
        host_id: "launch-host",
        access_policy: :anyone_with_passcode,
        passcode: "launch-pass",
        large_event?: true,
        waiting_room?: true,
        capacity: 100_000
      })

    {microseconds, results} =
      :timer.tc(fn ->
        1..@participants
        |> Task.async_stream(
          fn i ->
            source_ip =
              "10.0.#{i |> div(255) |> rem(255)}.#{rem(i, 255)}"

            VideoConf.join(%{
              meeting_id: meeting.id,
              passcode: "launch-pass",
              source_ip: source_ip
            })
          end,
          max_concurrency: max(System.schedulers_online() * 8, 32),
          timeout: 60_000
        )
        |> Enum.to_list()
      end)

    decisions = for {:ok, decision} <- results, do: decision
    admitted = Enum.count(decisions, &(&1.status == :admitted))

    assert admitted == @participants,
           "expected all participants admitted, got #{admitted}: #{inspect(Enum.take(decisions, 3))}"

    ms = microseconds / 1_000
    IO.puts("\n10k join decisions: #{Float.round(ms, 1)} ms total")
    IO.puts("throughput: #{Float.round(@participants / (ms / 1_000), 1)} joins/s")
  end

  test "admit-all handles 10,000 waiting requests with one policy cutoff" do
    host = Identity.issue_assertion(%{principal_id: "host-bulk", org_id: "bulk-org"})

    {:ok, meeting} =
      VideoConf.create_meeting(%{
        org_id: "bulk-org",
        host_id: "host-bulk",
        waiting_room?: true
      })

    1..@participants
    |> Task.async_stream(
      fn i ->
        identity = Identity.new(principal_id: "waiter-#{i}")
        WaitingRoom.create(meeting.id, identity, now_ms: 1_000 + i)
      end,
      max_concurrency: max(System.schedulers_online() * 8, 32),
      timeout: 60_000
    )
    |> Stream.run()

    assert WaitingRoom.count_pending(meeting.id, 0) == @participants
    assert {:ok, %{admitted: @participants}} = VideoConf.admit_all(meeting.id, host)
    assert WaitingRoom.list_pending(meeting.id, System.system_time(:millisecond), :infinity) == []
  end
end
