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

  defmacro value_hash_methods do
    quote do
      [
        "MD5",
        "RIPEMD160",
        "SHA1",
        "SHA224",
        "SHA256",
        "SHA384",
        "SHA512"
      ]
    end
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
    System.put_env("CRC16_NIF_PATH", System.cwd() <> "/deps/elcrc16/priv/")
    {root_oid, root_key} = Cdmioid.generate(45241)
    create_root({root_oid, root_key}, adminid)

    {capabilities_oid, capabilities_key} = Cdmioid.generate(45241)
    create_capabilities({capabilities_oid, capabilities_key}, root_oid, adminid)

    {capabilities_container_oid, capabilities_container_key} = Cdmioid.generate(45241)
    create_capabilities_container({capabilities_container_oid,
                                   capabilities_container_key},
                                  capabilities_oid, adminid)

    {capabilities_dataobject_oid, capabilities_dataobject_key} = Cdmioid.generate(45241)
    create_capabilities_dataobject({capabilities_dataobject_oid,
                                    capabilities_dataobject_key},
                                   capabilities_oid, adminid)

    {capabilities_domain_oid, capabilities_domain_key} = Cdmioid.generate(45241)
    create_capabilities_domain({capabilities_domain_oid, capabilities_domain_key},
                               capabilities_oid, adminid)



    {capabilities_container_perm_oid, capabilities_container_perm_key} = Cdmioid.generate(45241)
    create_capabilities_container_perm({capabilities_container_perm_oid,
                                        capabilities_container_perm_key},
                                       capabilities_container_oid, adminid)

    {capabilities_dataobject_perm_oid, capabilities_dataobject_perm_key} = Cdmioid.generate(45241)
    create_capabilities_dataobject_perm({capabilities_dataobject_perm_oid,
                                         capabilities_dataobject_perm_key},
                                        capabilities_dataobject_oid, adminid)

    {capabilities_domain_member_oid, capabilities_domain_member_key} = Cdmioid.generate(45241)
    create_capabilities_domain_member({capabilities_domain_member_oid,
                                         capabilities_domain_member_key},
                                        capabilities_domain_oid, adminid)

    {domaincontainer_oid, domaincontainer_key} = Cdmioid.generate(45241)
    create_domains_container({domaincontainer_oid, domaincontainer_key}, root_oid, adminid)

    {sysdomain_oid, sysdomain_key} = Cdmioid.generate(45241)
    create_system_domain({sysdomain_oid, sysdomain_key}, domaincontainer_oid, adminid)

    {members_oid, members_key} = Cdmioid.generate(45241)
    create_domain_members_container({members_oid, members_key}, sysdomain_oid, adminid)

    {summary_oid, summary_key} = Cdmioid.generate(45241)
    create_domain_summary({summary_oid, summary_key}, sysdomain_oid, adminid)

    for period <- ["daily", "weekly", "monthly", "yearly"] do
      {period_oid, period_key} = Cdmioid.generate(45241)
      create_domain_summary_period({period_oid, period_key}, summary_oid, adminid, period)
    end

    {:adminpw, pswd} = List.keyfind(options, :adminpw, 0)
    {admin_oid, admin_key} = Cdmioid.generate(45241)
    create_administrator_member({admin_oid, admin_key}, members_oid, adminid, pswd)

    {sysconfig_oid, sysconfig_key} = Cdmioid.generate(45241)
    create_sysconfig({sysconfig_oid, sysconfig_key}, root_oid, adminid)

    {domain_maps_oid, domain_maps_key} = Cdmioid.generate(45241)
    create_domain_maps({domain_maps_oid, domain_maps_key}, sysconfig_oid, adminid)

    {env_vars_oid, env_vars_key} = Cdmioid.generate(45241)
    create_env_vars({env_vars_oid, env_vars_key}, sysconfig_oid, adminid)

  end

  defp parse_args(args) do
    {options, bootstrap_file, _errors} = OptionParser.parse(args,
      switches: [
        host: :string,
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
    object = %{
      capabilitiesURI: "#{capabilities_uri}",
      children: [
        "cdmi_domains/",
        "system_configuration/",
        "cdmi_capabilities/"
      ],
      childrenrange: "0-2",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri}",
      metadata: %{
        cdmi_acls: [
          acl_owner,
          acl_authenticated
        ],
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_owner: "#{adminid}"},
      objectID: "#{oid}",
      objectName: "/",
      objectType: "application/cdmi-container"
    }
    search_parm = get_domain_hash(object.domainURI) <> "/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the capabilities object.
  """
  defp create_capabilities({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
      capabilities: %{
        cdmi_copy_dataobject_from_queue: "false",
        cdmi_copy_queue_by_ID: "false",
        cdmi_create_reference_by_ID: "false",
        cdmi_create_value_range_by_ID: "false",
        cdmi_dataobjects: "true",
        cdmi_deserialize_dataobject_by_ID: "false",
        cdmi_deserialize_queue_by_ID: "false",
        cdmi_domains: "true",
        cdmi_export_cifs: "false",
        cdmi_export_iscsi: "false",
        cdmi_export_nfs: "false",
        cdmi_export_occi_iscsi: "false",
        cdmi_export_webdav: "false",
        cdmi_logging: "false",
        cdmi_metadata_maxitems: 1024,
        cdmi_metadata_maxsize: 8192,
        cdmi_metadata_maxtotalsize: 8388608,
        cdmi_multipart_mime: "false",
        cdmi_notification: "false",
        cdmi_object_access_by_ID: "true",
        cdmi_object_copy_from_local: "false",
        cdmi_object_copy_from_remote: "false",
        cdmi_object_move_from_ID: "false",
        cdmi_object_move_from_local: "false",
        cdmi_object_move_from_remote: "false",
        cdmi_object_move_to_ID: "false",
        cdmi_post_dataobject_by_ID: "false",
        cdmi_post_queue_by_ID: "false",
        cdmi_query: "false",
        cdmi_query_contains: "false",
        cdmi_query_regex: "false",
        cdmi_query_tags: "false",
        cdmi_query_value: "false",
        cdmi_queues: "false",
        cdmi_references: "false",
        cdmi_security_access_control: "false",
        cdmi_security_audit: "false",
        cdmi_security_data_integrity: "true",
        cdmi_security_immutability: "false",
        cdmi_security_sanitization: "false",
        cdmi_serialization_json: "false",
        cdmi_serialize_container_ID: "false",
        cdmi_serialize_dataobject_to_ID: "false",
        cdmi_serialize_domain_to_ID: "false",
        cdmi_serialize_queue_to_ID: "false",
        cdmi_snapshots: "false"
      },
      children: [
        "container/",
        "dataobject/",
        "domain/"
      ],
      childrenrange: "0-2",
      objectID: "#{oid}",
      objectName: "cdmi_capabilities/",
      objectType: "application/cdmi-capability",
      parentID: "#{parentid}",
      parentURI: "/"
    }
    search_parm = get_domain_hash(system_domain_uri) <> "/cdmi_capabilities/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the capabilities container object.
  """
  defp create_capabilities_container({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
      capabilities: %{
        cdmi_RPO: "false",
        cdmi_RTO: "false",
        cdmi_acl: "true",
        cdmi_acount: "false",
        cdmi_assignedsize: "false",
        cdmi_atime: "true",
        cdmi_authentication_methods: [
          "anonymous",
          "basic"
        ],
        cdmi_copy_container: "false",
        cdmi_copy_dataobject: "false",
        cdmi_create_container: "true",
        cdmi_create_dataobject: "true",
        cdmi_create_queue: "false",
        cdmi_create_reference: "false",
        cdmi_create_value_range: "false",
        cdmi_ctime: "true",
        cdmi_data_autodelete: "false",
        cdmi_data_dispersion: "false",
        cdmi_data_holds: "false",
        cdmi_data_redundancy: "",
        cdmi_data_retention: "false",
        cdmi_delete_container: "true",
        cdmi_deserialize_container: "false",
        cdmi_deserialize_dataobject: "false",
        cdmi_deserialize_queue: "false",
        cdmi_encryption: [],
        cdmi_export_container_cifs: "false",
        cdmi_export_container_iscsi: "false",
        cdmi_export_container_nfs: "false",
        cdmi_export_container_occi: "false",
        cdmi_export_container_webdav: "false",
        cdmi_geographic_placement: "false",
        cdmi_immediate_redundancy: "",
        cdmi_infrastructure_redundancy: "",
        cdmi_latency: "false",
        cdmi_list_children: "true",
        cdmi_list_children_range: "true",
        cdmi_mcount: "false",
        cdmi_modify_deserialize_container: "false",
        cdmi_modify_metadata: "true",
        cdmi_move_container: "false",
        cdmi_move_dataobject: "false",
        cdmi_mtime: "true",
        cdmi_post_dataobject: "false",
        cdmi_post_queue: "false",
        cdmi_read_metadata: "true",
        cdmi_read_value: "false",
        cdmi_read_value_range: "false",
        cdmi_sanitization_method: [],
        cdmi_serialize_container: "false",
        cdmi_serialize_dataobject: "false",
        cdmi_serialize_domain: "false",
        cdmi_serialize_queue: "false",
        cdmi_size: "true",
        cdmi_snapshot: "false",
        cdmi_throughput: "false",
        cdmi_value_hash: value_hash_methods
      },
      children: [
        "permanent/"
      ],
      childrenrange: "0-0",
      objectID: "#{oid}",
      objectName: "container/",
      objectType: "application/cdmi-capability",
      parentID: "#{parentid}",
      parentURI: "/cdmi_capabilities/"
    }
    search_parm = get_domain_hash(system_domain_uri) <> "/cdmi_capabilities/container/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    response = GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the capabilities container permanent object.
  """
  defp create_capabilities_container_perm({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
      capabilities: %{
        cdmi_RPO: "false",
        cdmi_RTO: "false",
        cdmi_acl: "true",
        cdmi_acount: "false",
        cdmi_assignedsize: "false",
        cdmi_atime: "true",
        cdmi_authentication_methods: [
          "anonymous",
          "basic"
        ],
        cdmi_copy_container: "false",
        cdmi_copy_dataobject: "false",
        cdmi_create_container: "true",
        cdmi_create_dataobject: "true",
        cdmi_create_queue: "false",
        cdmi_create_reference: "false",
        cdmi_create_value_range: "false",
        cdmi_ctime: "true",
        cdmi_data_autodelete: "false",
        cdmi_data_dispersion: "false",
        cdmi_data_holds: "false",
        cdmi_data_redundancy: "",
        cdmi_data_retention: "false",
        cdmi_delete_container: "true",
        cdmi_deserialize_container: "false",
        cdmi_deserialize_dataobject: "false",
        cdmi_deserialize_queue: "false",
        cdmi_encryption: [],
        cdmi_export_container_cifs: "false",
        cdmi_export_container_iscsi: "false",
        cdmi_export_container_nfs: "false",
        cdmi_export_container_occi: "false",
        cdmi_export_container_webdav: "false",
        cdmi_geographic_placement: "false",
        cdmi_immediate_redundancy: "",
        cdmi_infrastructure_redundancy: "",
        cdmi_latency: "false",
        cdmi_list_children: "true",
        cdmi_list_children_range: "true",
        cdmi_mcount: "false",
        cdmi_modify_deserialize_container: "false",
        cdmi_modify_metadata: "true",
        cdmi_move_container: "false",
        cdmi_move_dataobject: "false",
        cdmi_mtime: "true",
        cdmi_post_dataobject: "false",
        cdmi_post_queue: "false",
        cdmi_read_metadata: "true",
        cdmi_read_value: "false",
        cdmi_read_value_range: "false",
        cdmi_sanitization_method: [],
        cdmi_serialize_container: "false",
        cdmi_serialize_dataobject: "false",
        cdmi_serialize_domain: "false",
        cdmi_serialize_queue: "false",
        cdmi_size: "true",
        cdmi_snapshot: "false",
        cdmi_throughput: "false",
        cdmi_value_hash: value_hash_methods
      },
      objectID: "#{oid}",
      objectName: "permanent/",
      objectType: "application/cdmi-capability",
      parentID: "#{parentid}",
      parentURI: "/cdmi_capabilities/container/"
    }
    search_parm = get_domain_hash(system_domain_uri) <> "/cdmi_capabilities/container/permanent/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    response = GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the capabilities domain object.
  """
  defp create_capabilities_domain({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
      capabilities: %{
        cdmi_RPO: "false",
        cdmi_RTO: "false",
        cdmi_acl: "true",
        cdmi_acount: "false",
        cdmi_assignedsize: "false",
        cdmi_atime: "true",
        cdmi_authentication_methods: [
#          "anonymous",
          "basic"
        ],
        cdmi_copy_domain: "false",
        cdmi_create_domain: "true",
        cdmi_ctime: "true",
        cdmi_data_autodelete: "false",
        cdmi_data_dispersion: "false",
        cdmi_data_holds: "false",
        cdmi_data_redundancy: "",
        cdmi_data_retention: "false",
        cdmi_delete_domain: "true",
        cdmi_deserialize_domain: "false",
        cdmi_domain_members: "true",
        cdmi_domain_summary: "true",
        cdmi_encryption: [],
        cdmi_geographic_placement: "false",
        cdmi_immediate_redundancy: "",
        cdmi_infrastructure_redundancy: "",
        cdmi_latency: "false",
        cdmi_list_children: "true",
        cdmi_mcount: "false",
        cdmi_modify_deserialize_domain: "false",
        cdmi_modify_metadata: "true",
        cdmi_move_domain: "false",
        cdmi_mtime: "true",
        cdmi_read_metadata: "true",
        cdmi_sanitization_method: [],
        cdmi_size: "true",
        cdmi_throughput: "false",
        cdmi_value_hash: value_hash_methods
      },
      children: [
        "member/"
      ],
      childrenrange: "0-0",
      objectID: "#{oid}",
      objectName: "domain/",
      objectType: "application/cdmi-capability",
      parentID: "#{parentid}",
      parentURI: "/cdmi_capabilities/"
    }
    search_parm = get_domain_hash(system_domain_uri) <> "/cdmi_capabilities/domain/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    response = GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the capabilities dataobject object.
  """
  defp create_capabilities_dataobject({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
      capabilities: %{
        cdmi_RPO: "false",
        cdmi_RTO: "false",
        cdmi_acl: "true",
        cdmi_acount: "false",
        cdmi_assignedsize: "false",
        cdmi_atime: "true",
        cdmi_authentication_methods: [
#          "anonymous",
          "basic"
        ],
        cdmi_ctime: "true",
        cdmi_data_autodelete: "false",
        cdmi_data_dispersion: "false",
        cdmi_data_holds: "false",
        cdmi_data_redundancy: "",
        cdmi_data_retention: "false",
        cdmi_delete_dataobject: "true",
        cdmi_encryption: [],
        cdmi_geographic_placement: "false",
        cdmi_immediate_redundancy: "",
        cdmi_infrastructure_redundancy: "",
        cdmi_latency: "false",
        cdmi_mcount: "false",
        cdmi_modify_deserialize_dataobject: "false",
        cdmi_modify_metadata: "true",
        cdmi_modify_value: "true",
        cdmi_modify_value_range: "true",
        cdmi_mtime: "true",
        cdmi_read_metadata: "true",
        cdmi_read_value: "true",
        cdmi_read_value_range: "true",
        cdmi_sanitization_method: [],
        cdmi_size: "true",
        cdmi_throughput: "false",
        cdmi_value_hash: value_hash_methods
      },
      children: [
        "permanent/"
      ],
      childrenrange: "0-0",
      objectID: "#{oid}",
      objectName: "dataobject/",
      objectType: "application/cdmi-capability",
      parentID: "#{parentid}",
      parentURI: "/cdmi_capabilities/"
    }
    search_parm = get_domain_hash(system_domain_uri) <> "/cdmi_capabilities/dataobject/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    response = GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the capabilities dataobject permanent object.
  """
  defp create_capabilities_dataobject_perm({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
      capabilities: %{
        cdmi_RPO: "false",
        cdmi_RTO: "false",
        cdmi_acl: "true",
        cdmi_acount: "false",
        cdmi_assignedsize: "false",
        cdmi_atime: "true",
        cdmi_authentication_methods: [
          "anonymous",
          "basic"
        ],
        cdmi_ctime: "true",
        cdmi_data_autodelete: "false",
        cdmi_data_dispersion: "false",
        cdmi_data_holds: "false",
        cdmi_data_redundancy: "",
        cdmi_data_retention: "false",
        cdmi_encryption: [],
        cdmi_geographic_placement: "false",
        cdmi_immediate_redundancy: "",
        cdmi_infrastructure_redundancy: "",
        cdmi_latency: "false",
        cdmi_mcount: "false",
        cdmi_modify_deserialize_dataobject: "false",
        cdmi_modify_metadata: "true",
        cdmi_modify_value: "true",
        cdmi_modify_value_range: "true",
        cdmi_mtime: "true",
        cdmi_read_metadata: "true",
        cdmi_read_value: "true",
        cdmi_read_value_range: "true",
        cdmi_sanitization_method: [],
        cdmi_size: "true",
        cdmi_throughput: "false",
        cdmi_value_hash: value_hash_methods
      },
      objectID: "#{oid}",
      objectName: "permanent/",
      objectType: "application/cdmi-capability",
      parentID: "#{parentid}",
      parentURI: "/cdmi_capabilities/dataobject/"
    }
    search_parm = get_domain_hash(system_domain_uri) <> "/cdmi_capabilities/dataobject/permanent/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the capabilities domain member object.
  """
  defp create_capabilities_domain_member({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
      capabilities: %{
        cdmi_delete_dataobject: "true",
        cdmi_modify_deserialize_dataobject: "false",
        cdmi_modify_metadata: "true",
        cdmi_modify_value: "true",
        cdmi_modify_value_range: "true",
        cdmi_read_metadata: "true",
        cdmi_read_value: "true",
        cdmi_read_value_range: "true"
      },
      objectID: "#{oid}",
      objectName: "member/",
      objectType: "application/cdmi-capability",
      parentID: "#{parentid}",
      parentURI: "/cdmi_capabilities/domain/"
    }
    search_parm = get_domain_hash(system_domain_uri) <> "/cdmi_capabilities/domain/member/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
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
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the system domain object.
  """
  defp create_system_domain({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
      capabilitiesURI: "#{capabilities_uri}",
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
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the domain members container.
  """
  defp create_domain_members_container({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
      capabilitiesURI: "#{capabilities_uri}",
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
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the domain summary container.
  """
  defp create_domain_summary({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
      children: [
        "yearly/",
        "monthly/",
        "weekly/",
        "daily/"
      ],
      childrenrange: "0-3",
      completionStatus: "complete",
      domainURI: "/cdmi_domains/system_domain/",
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
      objectName: "cdmi_domain_summary/",
      objectType: "application/cdmi-container",
      parentID: "#{parentid}",
      parentURI: "/cdmi_domains/system_domain/"
    }
    search_parm = get_domain_hash(object.domainURI) <>
                  "/cdmi_domains/system_domain/cdmi_domain_summary/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the domain summary container for a given period
  """
  defp create_domain_summary_period({oid, key}, parentid, adminid, period) do
    timestamp = make_timestamp()
    object = %{
      capabilitiesURI: "/cdmi_capabilities/container/",
      completionStatus: "complete",
      domainURI: "/cdmi_domains/system_domain/",
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
      objectName: "#{period}",
      objectType: "application/cdmi-container",
      parentID: "#{parentid}",
      parentURI: "/cdmi_domains/system_domain/cdmi_domain_summary/#{period}/"
    }
    search_parm = get_domain_hash(object.domainURI) <>
                  "/cdmi_domains/system_domain/cdmi_domain_summary/#{period}/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the administrator member object.
  """
  defp create_administrator_member({oid, key}, parentid, adminid, pswd) do
    timestamp = make_timestamp()
    encrypted_pswd = encrypt(adminid, pswd)
    object = %{
      capabilitiesURI: "#{capabilities_uri}/dataobject/member",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri}",
      metadata: %{
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_member_credentials: "#{encrypted_pswd}",
        cdmi_member_enabled: "true",
        cdmi_member_groups: [],
        cdmi_member_name: "#{adminid}",
        cdmi_member_principal: "#{adminid}",
        cdmi_member_privileges: [
          "cross_domain",
          "administrator"
        ],
        cdmi_member_type: "user",
        cdmi_owner: "#{adminid}"
      },
      objectID: "#{oid}",
      objectName: "#{adminid}",
      objectType: "application/cdmi-domain",
      parentID: "#{parentid}",
      parentURI: "/cdmi_domains/"
    }
    search_parm = get_domain_hash(object.domainURI) <> "/cdmi_domains/system/domain/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the system configuration object.
  """
  defp create_sysconfig({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
      capabilitiesURI: "/cdmi_capabilities/container/permanent/",
      children: [
        "environment_variables",
        "domain_maps"
      ],
      childrenrange: "0-1",
      completionStatus: "complete",
      domainURI: "/cdmi_domains/system_domain/",
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
      objectName: "system_configuration/",
      objectType: "application/cdmi-container",
      parentID: "#{parentid}",
      parentURI: "/"
    }
    search_parm = get_domain_hash(object.domainURI) <> "/system_configuration/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the system configuration domain maps object.
  """
  defp create_domain_maps({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    value = "{}"
    {hash_method, hashed_value} = value_hash(value, value_hash_methods)
    object = %{
      capabilitiesURI: "/cdmi_capabilities/dataobject/permanent/",
      completionStatus: "complete",
      domainURI: "/cdmi_domains/system_domain/",
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
        cdmi_owner: "#{adminid}",
        cdmi_hash: "#{hashed_value}",
        cdmi_value_hash: "#{hash_method}"
      },
      objectID: "#{oid}",
      objectName: "domain_maps",
      objectType: "application/cdmi-object",
      parentID: "#{parentid}",
      parentURI: "/system_configuration/",
      value: "#{value}",
      valuerange: "0-1",
      valuetransferencoding: "utf-8"
    }
    search_parm = get_domain_hash(object.domainURI) <> "/system_configuration/domain_maps"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Create the system configuration environment variables object.
  """
  defp create_env_vars({oid, key}, parentid, adminid) do
    timestamp = make_timestamp()
    object = %{
      capabilitiesURI: "/cdmi_capabilities/container/permanent/",
      completionStatus: "complete",
      domainURI: "/cdmi_domains/system_domain/",
      metadata: %{
        cdmi_acls:
          [
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
      objectName: "environment_variables/",
      objectType: "application/cdmi-container",
      parentID: "#{parentid}",
      parentURI: "/system_configuration/"
    }
    search_parm = get_domain_hash(object.domainURI) <> "/system_configuration/environment_variables/"
    cdmi_object = %{cdmi: object, sp: "#{search_parm}"}
    GenServer.call(Metadata, {:put, key, cdmi_object})
  end

  @doc """
  Encrypt.
  """
  @spec encrypt(string, string) :: string
  def encrypt(key, message) do
    :crypto.hmac(:sha, key, message)
    |> Base.encode16
    |> String.downcase
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

  defp value_hash(value, methods) do
    hash_method = cond do
      "SHA512" in methods -> "SHA512"
      "SHA384" in methods -> "SHA384"
      "SHA256" in methods -> "SHA256"
      "SHA224" in methods -> "SHA224"
      "SHA1"   in methods -> "SHA1"
      "MD5"    in methods -> "MD5"
    end
    method = hash_method |> String.downcase |> String.to_atom
    hashed_value = :crypto.hash(method , value) |> Base.encode16 |> String.downcase
    {hash_method, hashed_value}
  end
end
