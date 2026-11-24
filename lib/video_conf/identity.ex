defmodule VideoConf.Identity do
  @moduledoc """
  Authenticated caller identity.

  `verified_org?: true` must only be set after verifying an SSO/OIDC assertion
  or a trusted internal session token. Client-submitted profile fields are not
  enough to establish organization membership.
  """

  @enforce_keys [:principal_id]
  defstruct [
    :principal_id,
    :org_id,
    :email,
    display_name: "Participant",
    auth_method: :anonymous,
    verified_org?: false,
    caller_number: nil,
    proof: nil,
    roles: []
  ]

  @type t :: %__MODULE__{}

  def new(attrs) when is_map(attrs) or is_list(attrs) do
    struct!(__MODULE__, attrs)
  end

  @doc """
  Issues the HMAC equivalent of an SSO assertion.

  Call this only from a trusted authentication boundary after verifying OIDC/
  SAML/session material. Never pass raw client parameters directly into this
  function; anyone who can call it with arbitrary claims can mint an identity.
  Production deployments normally verify the IdP's JWT/JWKS instead and do not
  expose this signing helper to request-handling code.
  """
  def issue_assertion(attrs, opts \\ []) do
    principal_id = fetch!(attrs, :principal_id)
    org_id = fetch!(attrs, :org_id)

    claims = %{
      "typ" => "org_assertion",
      "pid" => principal_id,
      "org" => org_id,
      "email" => attrs[:email] || attrs["email"],
      "name" => attrs[:display_name] || attrs[:name] || "Participant"
    }

    VideoConf.Token.sign(claims, Keyword.put_new(opts, :ttl, 300))
  end

  def verify_assertion(token, opts \\ [])

  def verify_assertion(token, opts) when is_binary(token) do
    with {:ok, claims} <- VideoConf.Token.verify(token, opts),
         "org_assertion" <- Map.get(claims, "typ") do
      {:ok,
       %__MODULE__{
         principal_id: claims["pid"],
         org_id: claims["org"],
         email: claims["email"],
         display_name: claims["name"] || "Participant",
         auth_method: :sso,
         verified_org?: true,
         proof: token
       }}
    else
      _ -> {:error, :invalid_assertion}
    end
  end

  def verify_assertion(_, _opts), do: {:error, :invalid_assertion}

  def dial_in(call_id, attrs \\ []) do
    %__MODULE__{
      principal_id: "pstn:" <> call_id,
      display_name: attrs[:display_name] || "Phone participant",
      caller_number: attrs[:caller_number],
      auth_method: :phone,
      # Caller ID is metadata, not proof. It may be used as a risk signal only.
      verified_org?: false
    }
  end

  def anonymous(source_key \\ "anonymous") do
    %__MODULE__{principal_id: "anon:" <> source_key, auth_method: :anonymous}
  end

  def verified_org_member?(%__MODULE__{verified_org?: false}, _org_ids), do: false

  def verified_org_member?(%__MODULE__{verified_org?: true, org_id: org_id}, allowed_org_ids) do
    MapSet.member?(allowed_org_ids, org_id)
  end

  def host?(
        %__MODULE__{principal_id: host_id, org_id: org_id, verified_org?: true},
        %{host_id: host_id, org_id: org_id}
      ),
      do: true

  def host?(_identity, _meeting), do: false

  @doc "True when the struct carries a currently valid HMAC/SSO proof for itself."
  def proof_valid?(%__MODULE__{
        proof: token,
        principal_id: principal_id,
        org_id: org_id
      })
      when is_binary(token) do
    expected = %{
      "typ" => "org_assertion",
      "pid" => principal_id,
      "org" => org_id
    }

    match?({:ok, _}, VideoConf.Token.verify(token, expect: expected))
  end

  def proof_valid?(_identity), do: false

  @doc "Host check used by security-sensitive operations; raw forged structs fail."
  def verified_host?(identity, meeting) do
    host?(identity, meeting) and proof_valid?(identity)
  end

  defp fetch!(attrs, key) when is_map(attrs), do: Map.fetch!(attrs, key)
  defp fetch!(attrs, key) when is_list(attrs), do: Keyword.fetch!(attrs, key)
end
