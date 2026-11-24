defmodule VideoConf.JoinRequestTest do
  use ExUnit.Case, async: true

  alias VideoConf.JoinRequest

  test "generated PSTN call id is written back to request and identity" do
    request = JoinRequest.new!(%{meeting_id: "123456789", dial_in?: true})

    assert is_binary(request.call_id)
    assert String.starts_with?(request.call_id, "call_")
    assert request.identity.principal_id == "pstn:" <> request.call_id
    assert JoinRequest.source_key(request) == "call:" <> request.call_id
  end

  test "public constructor ignores trusted_edge escalation" do
    request =
      JoinRequest.new!(%{
        meeting_id: "123456789",
        trusted_edge?: true,
        identity: %VideoConf.Identity{principal_id: "u", verified_org?: true}
      })

    refute request.trusted_edge?
  end
end
