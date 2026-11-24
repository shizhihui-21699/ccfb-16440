defmodule VideoConf.Store do
  @moduledoc """
  ETS-backed meeting/policy store and short-lived token revocation list.

  ETS gives all join nodes/processes concurrent reads without routing every join
  through one meeting GenServer. Replace this module with Postgres + a cached
  policy layer in a multi-node production deployment.
  """

  use GenServer

  alias VideoConf.Meeting

  @meetings_table :vc_meetings
  @revoked_jtis_table :vc_revoked_jtis
  @consumed_once_table :vc_consumed_once

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def meetings_table, do: @meetings_table

  @impl true
  def init(_opts) do
    :ets.new(@meetings_table, [:named_table, :set, :public, read_concurrency: true])
    :ets.new(@revoked_jtis_table, [:named_table, :set, :public, read_concurrency: true])

    :ets.new(@consumed_once_table, [
      :named_table,
      :set,
      :public,
      write_concurrency: true,
      read_concurrency: true
    ])

    {:ok, %{}}
  end

  @doc "Builds and stores a meeting, retrying the astronomically unlikely ID collision."
  def create_meeting(attrs) do
    with {:ok, meeting} <- Meeting.build(attrs) do
      GenServer.call(__MODULE__, {:create_meeting, meeting, 5})
    end
  end

  def get_meeting(id) when is_binary(id) do
    case :ets.lookup(@meetings_table, id) do
      [{^id, meeting}] -> {:ok, meeting}
      [] -> {:error, :not_found}
    end
  rescue
    ArgumentError -> {:error, :not_ready}
  end

  def update_meeting(id, fun) when is_binary(id) and is_function(fun, 1) do
    GenServer.call(__MODULE__, {:update_meeting, id, fun})
  end

  def put_meeting(%Meeting{} = meeting) do
    true = :ets.insert(@meetings_table, {meeting.id, meeting})
    {:ok, meeting}
  end

  def revoke_jti(jti, ttl_seconds \\ 86_400) when is_binary(jti) do
    expires_at = System.system_time(:second) + ttl_seconds
    :ets.insert(@revoked_jtis_table, {jti, expires_at})
    :ok
  end

  def jti_revoked?(jti) when is_binary(jti) do
    now = System.system_time(:second)

    case :ets.lookup(@revoked_jtis_table, jti) do
      [{^jti, expires_at}] when expires_at > now ->
        true

      [{^jti, _expired}] ->
        :ets.delete(@revoked_jtis_table, jti)
        false

      [] ->
        false
    end
  rescue
    ArgumentError -> false
  end

  def jti_revoked?(_), do: false

  @doc """
  Atomically consumes a short-lived key exactly once.

  Returns `:ok` for the first consumer and `{:error, :already_used}` for a
  replay before TTL expiry. Expired rows are removed lazily.
  """
  def consume_once(namespace, key, ttl_seconds, now_seconds \\ System.system_time(:second))
      when is_binary(namespace) and ttl_seconds > 0 do
    id = {namespace, key}
    expires_at = now_seconds + ttl_seconds

    case :ets.insert_new(@consumed_once_table, {id, expires_at}) do
      true ->
        :ok

      false ->
        case :ets.lookup(@consumed_once_table, id) do
          [{^id, existing_expiry}] when existing_expiry > now_seconds ->
            {:error, :already_used}

          _ ->
            :ets.delete(@consumed_once_table, id)

            case :ets.insert_new(@consumed_once_table, {id, expires_at}) do
              true -> :ok
              false -> {:error, :already_used}
            end
        end
    end
  rescue
    ArgumentError -> {:error, :store_unavailable}
  end

  @impl true
  def handle_call({:create_meeting, meeting, attempts}, _from, state) do
    {:reply, insert_with_id_retry(meeting, attempts), state}
  end

  @impl true
  def handle_call({:update_meeting, id, fun}, _from, state) do
    reply =
      case get_meeting(id) do
        {:ok, meeting} ->
          updated =
            meeting
            |> fun.()
            |> Map.update!(:version, &(&1 + 1))
            |> Map.put(:updated_at_ms, System.system_time(:millisecond))

          :ets.insert(@meetings_table, {id, updated})
          {:ok, updated}

        error ->
          error
      end

    {:reply, reply, state}
  end

  defp insert_with_id_retry(meeting, attempts) do
    case :ets.insert_new(@meetings_table, {meeting.id, meeting}) do
      true ->
        {:ok, meeting}

      false when attempts > 0 ->
        meeting
        |> Map.put(:id, VideoConf.Credentials.generate_meeting_id())
        |> insert_with_id_retry(attempts - 1)

      false ->
        {:error, :id_collision}
    end
  end
end
