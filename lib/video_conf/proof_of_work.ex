defmodule VideoConf.ProofOfWork do
  @moduledoc """
  Small hashcash-style challenge used only after suspicious guessing.

  Normal org members and event attendees never see this. The difficulty is the
  number of leading zero hexadecimal nibbles required.
  """

  alias VideoConf.Token

  def issue_challenge(source_key, opts \\ []) do
    difficulty = opts[:difficulty] || Application.get_env(:video_conf, :pow_difficulty, 3)
    ttl = opts[:ttl] || 180

    Token.sign(
      %{
        "typ" => "pow_challenge",
        "src" => source_key,
        "d" => difficulty,
        "jti" => Token.random_id(8)
      },
      ttl: ttl,
      now: opts[:now]
    )
  end

  @doc "Brute-forces a solution. Primarily useful for tests, scripts and clients."
  def solve(challenge_token, opts \\ []) do
    with {:ok, claims} <- Token.verify(challenge_token, now: opts[:now]) do
      difficulty = Token.get_integer(claims, "d", 3)

      nonce =
        0
        |> Stream.iterate(&(&1 + 1))
        |> Enum.find(&valid_hash?(challenge_token, &1, difficulty))

      {:ok, %{challenge_token: challenge_token, nonce: nonce}}
    end
  end

  def verify_solution(challenge_token, source_key, nonce, opts \\ []) do
    now = opts[:now] || System.system_time(:second)

    with {:ok, claims} <-
           Token.verify(challenge_token,
             now: now,
             expect: %{"typ" => "pow_challenge", "src" => source_key}
           ),
         difficulty <- Token.get_integer(claims, "d", 3),
         true <- is_integer(nonce) and nonce >= 0,
         true <- valid_hash?(challenge_token, nonce, difficulty),
         :ok <- consume_solution(claims, nonce, now) do
      :ok
    else
      {:error, :already_used} -> {:error, :proof_already_used}
      _ -> {:error, :invalid_proof_of_work}
    end
  end

  def valid_hash?(challenge_token, nonce, difficulty)
      when is_binary(challenge_token) and is_integer(nonce) and is_integer(difficulty) do
    hash =
      :crypto.hash(:sha256, challenge_token <> ":" <> Integer.to_string(nonce))
      |> Base.encode16(case: :lower)

    String.starts_with?(hash, String.duplicate("0", difficulty))
  end

  defp consume_solution(%{"jti" => jti} = claims, nonce, now) do
    exp = Token.get_integer(claims, "exp", now + 180)
    ttl_seconds = max(exp - now, 1)
    VideoConf.Store.consume_once("pow_solution", {jti, nonce}, ttl_seconds, now)
  end

  defp consume_solution(_claims, _nonce, _now), do: {:error, :invalid_proof_of_work}
end
