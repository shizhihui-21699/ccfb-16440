defmodule VideoConf.ProofOfWorkTest do
  use ExUnit.Case, async: false

  alias VideoConf.ProofOfWork

  test "a solved nonce can be consumed only once" do
    source = "pow-source-" <> Integer.to_string(System.unique_integer([:positive]))
    challenge = ProofOfWork.issue_challenge(source, difficulty: 1)

    assert {:ok, %{challenge_token: ^challenge, nonce: nonce}} =
             ProofOfWork.solve(challenge)

    assert :ok = ProofOfWork.verify_solution(challenge, source, nonce)

    assert {:error, :proof_already_used} =
             ProofOfWork.verify_solution(challenge, source, nonce)
  end

  test "solutions are bound to the source key" do
    challenge = ProofOfWork.issue_challenge("source-a", difficulty: 1)
    {:ok, %{nonce: nonce}} = ProofOfWork.solve(challenge)

    assert {:error, :invalid_proof_of_work} =
             ProofOfWork.verify_solution(challenge, "source-b", nonce)
  end
end
