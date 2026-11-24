defmodule VideoConf.CredentialsTest do
  use ExUnit.Case, async: true

  alias VideoConf.Credentials

  test "meeting IDs are exactly nine digits" do
    ids = for _ <- 1..1_000, do: Credentials.generate_meeting_id()

    assert Enum.all?(ids, &Regex.match?(~r/^\d{9}$/, &1))
    assert length(Enum.uniq(ids)) > 990
  end

  test "numeric codes preserve leading zeroes" do
    code = Credentials.generate_numeric_code(8)
    assert Regex.match?(~r/^\d{8}$/, code)
  end

  test "password hashes verify and reject wrong values" do
    hash = Credentials.hash("correct horse", iterations: 1)

    assert String.starts_with?(hash, "pbkdf2_sha256$1$")
    assert Credentials.verify("correct horse", hash)
    refute Credentials.verify("wrong horse", hash)
    refute Credentials.verify("anything", nil)
  end
end
