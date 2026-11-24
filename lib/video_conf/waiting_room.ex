defmodule VideoConf.WaitingRoom do
  @moduledoc """
  ETS-backed waiting room.

  Requests are keyed by `{meeting_id, waiting_id}` and decision insertion is
  atomic (`:ets.insert_new/2`), so duplicate host clicks or concurrent tabs
  cannot produce two conflicting decisions. A host-wide "admit everyone" writes
  one cutoff on the meeting instead of updating tens of thousands of rows.
  """

  use GenServer

  @table :vc_waiting_requests
  @decisions_table :vc_waiting_decisions

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@decisions_table, [:named_table, :set, :public, read_concurrency: true])
    {:ok, %{}}
  end

  def create(meeting_id, identity, attrs \\ []) do
    now = attrs[:now_ms] || System.system_time(:millisecond)
    waiting_id = VideoConf.Token.random_id(16, "wr_")

    request = %{
      id: waiting_id,
      meeting_id: meeting_id,
      principal_id: identity.principal_id,
      identity: identity,
      display_name: identity.display_name,
      reason: attrs[:reason] || :waiting_room,
      source_key: attrs[:source_key],
      requested_at_ms: now,
      expires_at_ms: now + (attrs[:ttl_ms] || 15 * 60_000)
    }

    true = :ets.insert_new(@table, {{meeting_id, waiting_id}, now, request})
    {:ok, request}
  end

  def get(meeting_id, waiting_id) do
    case :ets.lookup(@table, {meeting_id, waiting_id}) do
      [{{^meeting_id, ^waiting_id}, _requested_at, request}] -> {:ok, request}
      [] -> {:error, :not_found}
    end
  rescue
    ArgumentError -> {:error, :not_ready}
  end

  @doc "Atomically records the first decision. Later decisions return the first one."
  def record_decision(meeting_id, waiting_id, status, decided_by, ticket, now_ms)
      when status in [:approved, :rejected] do
    key = {meeting_id, waiting_id}
    decision = {key, status, decided_by, now_ms, ticket}

    case :ets.insert_new(@decisions_table, decision) do
      true ->
        {:ok, decision_to_map(decision)}

      false ->
        get_decision(meeting_id, waiting_id)
    end
  end

  def get_decision(meeting_id, waiting_id) do
    case :ets.lookup(@decisions_table, {meeting_id, waiting_id}) do
      [{key, status, decided_by, at, ticket}] ->
        {:ok,
         %{
           key: key,
           status: status,
           decided_by: decided_by,
           decided_at_ms: at,
           ticket: ticket
         }}

      [] ->
        :pending
    end
  rescue
    ArgumentError -> :pending
  end

  @doc "Lists requests that have neither an individual decision nor a bulk-admit cutoff."
  def list_pending(meeting_id, bulk_admit_before_ms \\ 0, limit \\ 100) do
    @table
    |> :ets.match_object({{meeting_id, :_}, :_, :_})
    |> Enum.map(fn {_key, _requested_at, request} -> request end)
    |> Enum.reject(fn request ->
      match?({:ok, _}, get_decision(meeting_id, request.id)) or
        request.requested_at_ms <= bulk_admit_before_ms
    end)
    |> Enum.sort_by(& &1.requested_at_ms)
    |> then(fn requests ->
      if limit == :infinity, do: requests, else: Enum.take(requests, limit)
    end)
  rescue
    ArgumentError -> []
  end

  def count_pending(meeting_id, bulk_admit_before_ms \\ 0) do
    meeting_id
    |> list_pending(bulk_admit_before_ms, :infinity)
    |> length()
  end

  defp decision_to_map({key, status, decided_by, at, ticket}) do
    %{key: key, status: status, decided_by: decided_by, decided_at_ms: at, ticket: ticket}
  end
end
