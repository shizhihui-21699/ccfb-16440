defmodule VideoConf.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      VideoConf.Store,
      VideoConf.WaitingRoom,
      VideoConf.Presence,
      VideoConf.RateLimiter
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: VideoConf.Supervisor)
  end
end
