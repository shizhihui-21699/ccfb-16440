defmodule VideoConf.Presence do
  @moduledoc """
  Atomic media-session/capacity accounting.

  Admission issues a short-lived ticket; the media edge exchanges that ticket
  through `activate/2`. The same ticket `jti` is idempotent, so client retries
  do not consume two seats. ETS counters avoid a single GenServer per join.
  """

  use GenServer

  alias VideoConf.JoinTicket

  @sessions_table :vc_presence_sessions
  @counts_table :vc_presence_counts

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    :ets.new(@sessions_table, [:named_table, :set, :public, write_concurrency: true])

    :ets.new(@counts_table, [
      :named_table,
      :set,
      :public,
      write_concurrency: true,
      read_concurrency: true
    ])

    {:ok, %{}}
  end

  def activate(ticket, meeting, now_ms \\ System.system_time(:millisecond))

  def activate(ticket, meeting, now_ms) when is_binary(ticket) do
    with {:ok, claims} <- JoinTicket.verify(ticket, meeting.id) do
      activate_claims(claims, meeting, now_ms)
    end
  end

  def activate_claims(%{"jti" => jti, "pid" => pid}, meeting, now_ms) do
    session_key = {meeting.id, jti}

    case :ets.insert_new(@sessions_table, {session_key, pid, now_ms}) do
      false ->
        :ok

      true ->
        count =
          :ets.update_counter(@counts_table, meeting.id, {2, 1}, {meeting.id, 0})

        if count <= meeting.capacity do
          :ok
        else
          # Last writer backs out atomically; activation remains the hard cap.
          :ets.delete(@sessions_table, session_key)
          :ets.update_counter(@counts_table, meeting.id, {2, -1})
          {:error, :meeting_full}
        end
    end
  rescue
    ArgumentError -> {:error, :presence_unavailable}
  end

  def leave(meeting_id, jti) when is_binary(meeting_id) and is_binary(jti) do
    case :ets.take(@sessions_table, {meeting_id, jti}) do
      [_session] ->
        :ets.update_counter(@counts_table, meeting_id, {2, -1}, {meeting_id, 0})
        :ok

      [] ->
        :ok
    end
  rescue
    ArgumentError -> :ok
  end

  def count(meeting_id) do
    case :ets.lookup(@counts_table, meeting_id) do
      [{^meeting_id, count}] -> count
      [] -> 0
    end
  rescue
    ArgumentError -> 0
  end
end
