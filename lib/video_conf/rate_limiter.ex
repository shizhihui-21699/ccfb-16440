defmodule VideoConf.RateLimiter do
  @moduledoc """
  Fixed-window ETS counters.

  The hot operation is an atomic `:ets.update_counter/4`. In a multi-node
  deployment run the same interface over a shared store/edge service so an
  attacker cannot multiply the budget by hitting different nodes.
  """

  use GenServer

  @table :vc_rate_counters

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    :ets.new(@table, [
      :named_table,
      :set,
      :public,
      write_concurrency: true,
      read_concurrency: true
    ])

    schedule_cleanup()
    {:ok, %{}}
  end

  @doc """
  Counts one hit against `key`.

  `limit` is the maximum number for the window. Returns the current count on
  success and retry-after milliseconds when over the limit.
  """
  def hit(key, limit, window_ms, now_ms \\ System.system_time(:millisecond))
      when limit >= 0 and window_ms > 0 do
    window_start = div(now_ms, window_ms) * window_ms
    expires_at_ms = window_start + window_ms
    bucket = {key, window_start}

    count =
      :ets.update_counter(
        @table,
        bucket,
        {2, 1},
        {bucket, 0, expires_at_ms}
      )

    if count <= limit do
      {:ok, count}
    else
      {:error, :rate_limited, max(expires_at_ms - now_ms, 1)}
    end
  rescue
    ArgumentError ->
      # The limiter is unavailable. Fail closed for unauthenticated sensitive
      # joins in production; tests start the supervised process.
      {:error, :rate_limiter_unavailable, 1_000}
  end

  def reset do
    try do
      :ets.delete_all_objects(@table)
    rescue
      ArgumentError -> :ok
    end

    :ok
  end

  @doc "Returns the count in the current fixed window without incrementing it."
  def peek(key, window_ms, now_ms \\ System.system_time(:millisecond)) do
    window_start = div(now_ms, window_ms) * window_ms
    bucket = {key, window_start}

    case :ets.lookup(@table, bucket) do
      [{^bucket, count, _expires_at}] -> count
      [] -> 0
    end
  rescue
    ArgumentError -> 0
  end

  @doc "Clears one current-window counter, for example after a successful credential."
  def reset_key(key, window_ms, now_ms \\ System.system_time(:millisecond)) do
    window_start = div(now_ms, window_ms) * window_ms
    :ets.delete(@table, {key, window_start})
    :ok
  rescue
    ArgumentError -> :ok
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup(System.system_time(:millisecond))
    schedule_cleanup()
    {:noreply, state}
  end

  defp cleanup(now_ms) do
    :ets.foldl(
      fn
        {bucket, _count, expires_at_ms}, :ok when expires_at_ms <= now_ms ->
          :ets.delete(@table, bucket)
          :ok

        _object, :ok ->
          :ok
      end,
      :ok,
      @table
    )
  rescue
    ArgumentError -> :ok
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, 60_000)
  end
end
