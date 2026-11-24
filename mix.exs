defmodule VideoConf.MixProject do
  use Mix.Project

  def project do
    [
      app: :video_conf,
      version: "0.1.0",
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: []
    ]
  end

  def application do
    [
      mod: {VideoConf.Application, []},
      extra_applications: [:logger, :crypto]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
