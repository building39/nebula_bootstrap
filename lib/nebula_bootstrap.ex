defmodule NebulaBootstrap do

  require Logger

  defmacro acl_authenticated do
    quote do
      %{
          aceflags: "OBJECT_INHERIT, CONTAINER_INHERIT",
          acemask: "READ",
          acetype: "ALLOW",
          identifier: "AUTHENTICATED@"
      }
    end
  end

  defmacro acl_authenticated_inherited do
    quote do
      %{
          aceflags: "INHERITED, OBJECT_INHERIT, CONTAINER_INHERIT",
          acemask: "READ",
          acetype: "ALLOW",
          identifier: "AUTHENTICATED@"
      }
    end
  end

  defmacro acl_owner do
    quote do
      %{
          aceflags: "OBJECT_INHERIT, CONTAINER_INHERIT",
          acemask: "ALL_PERMS",
          acetype: "ALLOW",
          identifier: "OWNER@"
      }
    end
  end

  defmacro acl_owner_inherited do
    quote do
      %{
          aceflags: "INHERITED, OBJECT_INHERIT, CONTAINER_INHERIT",
          acemask: "ALL_PERMS",
          acetype: "ALLOW",
          identifier: "OWNER@"
      }
    end
  end

  defmacro capabilities_uri do
    "/cdmi_capabilities/"
  end

  defmacro system_domain_uri do
    "/cdmi_domains/system_domain/"
  end

  def main(args) do
    args |> parse_args |> process
  end

  def process([]) do
    IO.puts("No arguments given")
  end
  def process({options, bootstrap_file}) do
    IO.puts("Bootstrapping from file: #{bootstrap_file}")
    for n <- options, do: IO.inspect(n)
    {:adminid, adminid} = List.keyfind(options, :adminid, 0)
    Logger.debug("Admin id: #{adminid}")
    System.put_env("CRC16_NIF_PATH", System.cwd() <> "/deps/elcrc16/priv/")
    {root_oid, root_key} = Cdmioid.generate(45241)
    create_root({root_oid, root_key}, adminid)
    {domaincontainer_oid, domaincontainer_key} = Cdmioid.generate(45241)
    create_domains_container({domaincontainer_oid, domaincontainer_key}, root_oid, adminid)
    {sysdomain_oid, sysdomain_key} = Cdmioid.generate(45241)
    create_system_domain({sysdomain_oid, sysdomain_key}, domaincontainer_oid, adminid)
    {members_oid, members_key} = Cdmioid.generate(45241)
    create_domain_members_container({members_oid, members_key}, sysdomain_oid, adminid)
  end

  defp parse_args(args) do
    {options, bootstrap_file, _errors} = OptionParser.parse(args,
      switches: [host: :string,
                 port: :integer,
                 adminid: :string,
                 adminpw: :string,
                 crc16nifpath: :string
                ]
    )
    {options, bootstrap_file}
  end

  defp create_root({oid, key}, adminid) do
    timestamp = make_timestamp()
    object = %{capabilitiesURI: "#{capabilities_uri}",
               children: ["cdmi_domains/",
                          "system_configuration/",
                          "cdmi_capabilities/"],
               "childrenrange": "0-2",
               completionStatus: "complete",
               domainURI: "#{system_domain_uri}",
               metadata:
                %{cdmi_acls: [
                  acl_owner,
                  acl_authenticated],
                cdmi_atime: "#{timestamp}",
                cdmi_ctime: "#{timestamp}",
                cdmi_mtime: "#{timestamp}",
                cdmi_owner: "#{adminid}"},
              objectID: "#{oid}",
              objectName: "/",
              objectType: "application/cdmi-container"}
    search_parm = get_domain_hash(object.domainURI) <> "/"
    cdmi_object = %{cdmi: object,
                    sp: "#{search_parm}"}
    response = GenServer.call(Metadata, {:put, key, cdmi_object})
    Logger.debug("Root object:")
    IO.inspect(response)
  end

  @doc """
  Create the domains container.
  """
  defp create_domains_container({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
            capabilitiesURI: "#{capabilities_uri}",
            children: [
                "system_domain/"
            ],
            childrenrange: "0-0",
            completionStatus: "complete",
            domainURI: "#{system_domain_uri}",
            metadata: %{
                cdmi_acls: [
                    acl_owner_inherited,
                    acl_authenticated_inherited
                ],
                cdmi_atime: "#{timestamp}",
                cdmi_ctime: "#{timestamp}",
                cdmi_mtime: "#{timestamp}",
                cdmi_owner: "#{adminid}"
            },
            objectID: "#{oid}",
            objectName: "cdmi_domains/",
            objectType: "application/cdmi-container",
            parentID: "#{parentid}",
            parentURI: "/"
        }
        search_parm = get_domain_hash(object.domainURI) <> "/cdmi_domains/"
        cdmi_object = %{cdmi: object,
                        sp: "#{search_parm}"}
        response = GenServer.call(Metadata, {:put, key, cdmi_object})
        Logger.debug("Domains container:")
        IO.inspect(response)
  end

  @doc """
  Create the system domain object.
  """
  defp create_system_domain({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{capabilitiesURI: "#{capabilities_uri}",
            children: [
                "cdmi_domain_members/",
                "cdmi_domain_summary/"
            ],
            childrenrange: "0-1",
            completionStatus: "complete",
            domainURI: "#{system_domain_uri}",
            metadata: %{
                cdmi_acls: [
                  acl_owner,
                  acl_authenticated,
                  acl_owner_inherited,
                  acl_authenticated_inherited
                ],
                cdmi_atime: "#{timestamp}",
                cdmi_ctime: "#{timestamp}",
                cdmi_mtime: "#{timestamp}",
                cdmi_owner: "#{adminid}"
            },
            objectID: "#{oid}",
            objectName: "system_domain/",
            objectType: "application/cdmi-domain",
            parentID: "#{parentid}",
            parentURI: "/cdmi_domains/"
        }
        search_parm = get_domain_hash(object.domainURI) <> "/cdmi_domains/system_domain/"
        cdmi_object = %{cdmi: object,
                        sp: "#{search_parm}"}
        response = GenServer.call(Metadata, {:put, key, cdmi_object})
        Logger.debug("System domain object:")
        IO.inspect(response)
  end

  @doc """
  Create the domain members container.
  """
  defp create_domain_members_container({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{capabilitiesURI: "#{capabilities_uri}",
            children: [
                "#{adminid}"
            ],
            childrenrange: "0-0",
            completionStatus: "complete",
            domainURI: "#{system_domain_uri}",
            metadata: %{
                cdmi_acls: [
                  acl_owner,
                  acl_authenticated,
                  acl_owner_inherited,
                  acl_authenticated_inherited
                ],
                cdmi_atime: "#{timestamp}",
                cdmi_ctime: "#{timestamp}",
                cdmi_mtime: "#{timestamp}",
                cdmi_owner: "#{adminid}"
            },
            objectID: "#{oid}",
            objectName: "cdmi_domain_members/",
            objectType: "application/cdmi-container",
            parentID: "#{parentid}",
            parentURI: "/cdmi_domains/system_domain/"
        }
        search_parm = get_domain_hash(object.domainURI) <>
                      "/cdmi_domains/system_domain/cdmi_domain_members/"
        cdmi_object = %{cdmi: object,
                        sp: "#{search_parm}"}
        response = GenServer.call(Metadata, {:put, key, cdmi_object})
        Logger.debug("Domain members container:")
        IO.inspect(response)
  end

  @doc """
  Create the administrator member object.
  """
  defp create_system_domain({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{capabilitiesURI: "#{capabilities_uri}",
            children: [
                "cdmi_domain_members/",
                "cdmi_domain_summary/"
            ],
            childrenrange: "0-1",
            completionStatus: "complete",
            domainURI: "#{system_domain_uri}",
            metadata: %{
                cdmi_acls: [
                  acl_owner,
                  acl_authenticated,
                  acl_owner_inherited,
                  acl_authenticated_inherited
                ],
                cdmi_atime: "#{timestamp}",
                cdmi_ctime: "#{timestamp}",
                cdmi_mtime: "#{timestamp}",
                cdmi_owner: "#{adminid}"
            },
            objectID: "#{oid}",
            objectName: "system_domain/",
            objectType: "application/cdmi-domain",
            parentID: "#{parentid}",
            parentURI: "/cdmi_domains/"
        }
        search_parm = get_domain_hash(object.domainURI) <> "/cdmi_domains/system/domain/"
        cdmi_object = %{cdmi: object,
                        sp: "#{search_parm}"}
        response = GenServer.call(Metadata, {:put, key, cdmi_object})
        Logger.debug("System domain object:")
        IO.inspect(response)
  end

  @doc """
  Calculate a hash for a domain.
  """
  @spec get_domain_hash(string) :: string
  def get_domain_hash(domain) when is_list(domain) do
    get_domain_hash(<<domain>>)
  end
  @spec get_domain_hash(binary) :: string
  def get_domain_hash(domain) when is_binary(domain) do
    :crypto.hmac(:sha, <<"domain">>, domain)
    |> Base.encode16
    |> String.downcase
  end

  defp make_timestamp() do
    {{year, month, day}, {hour, minute, second}} =
      :calendar.now_to_universal_time(:os.timestamp)
    List.flatten(:io_lib.format("~4..0w-~2..0w-~2..0wT~2..0w:~2..0w:~2..0w.000000Z",
      [year, month, day, hour, minute, second]))
  end
end
