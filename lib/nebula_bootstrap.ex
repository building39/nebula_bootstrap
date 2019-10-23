defmodule NebulaBootstrap do
  require Logger

  defmacro acl_authenticated do
    quote do
      %{
        aceflags: "0x03",
        acemask: "0x1F",
        acetype: "0x00",
        identifier: "AUTHENTICATED@"
      }
    end
  end

  defmacro acl_authenticated_inherited do
    quote do
      %{
        aceflags: "0x83",
        acemask: "0x1F",
        acetype: "0x00",
        identifier: "AUTHENTICATED@"
      }
    end
  end

  defmacro acl_owner do
    quote do
      %{
        aceflags: "0x03",
        acemask: "0x1f07ff",
        acetype: "0x00",
        identifier: "OWNER@"
      }
    end
  end

  defmacro acl_owner_inherited do
    quote do
      %{
        aceflags: "0x83",
        acemask: "0x1f07ff",
        acetype: "0x00",
        identifier: "OWNER@"
      }
    end
  end

  defmacro capabilities_uri do
    "/cdmi_capabilities/"
  end

  defmacro default_domain_uri do
    "/cdmi_domains/default_domain/"
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
    IO.puts("ARGS: #{inspect(args)}")
    parms = args |> parse_args
    IO.puts("parms are: #{inspect(parms)}")
    process(parms)
  end

  def process({[], []}) do
    IO.puts("No arguments given")
  end

  def process({options, bootstrap_file}) do
    IO.puts("Bootstrapping from file: #{bootstrap_file}")
    for n <- options, do: IO.inspect(n)
    {:adminid, adminid} = List.keyfind(options, :adminid, 0)
    System.put_env("CRC16_NIF_PATH", System.cwd() <> "/deps/elcrc16/priv/")
    root_oid = Cdmioid.generate(45241)

    Logger.debug(fn ->
      "Creating root. oid: #{inspect(root_oid)} adminid: #{
        inspect(adminid)
      }"
    end)

    create_root(root_oid, adminid)

    capabilities_oid = Cdmioid.generate(45241)
    create_capabilities(capabilities_oid, root_oid, adminid)

    capabilities_container_oid = Cdmioid.generate(45241)

    create_capabilities_container(
      capabilities_container_oid,
      capabilities_oid,
      adminid
    )

    capabilities_dataobject_oid = Cdmioid.generate(45241)

    create_capabilities_dataobject(
      capabilities_dataobject_oid,
      capabilities_oid,
      adminid
    )

    capabilities_domain_oid = Cdmioid.generate(45241)

    create_capabilities_domain(
      capabilities_domain_oid,
      capabilities_oid,
      adminid
    )

    capabilities_container_perm_oid = Cdmioid.generate(45241)

    create_capabilities_container_perm(
      capabilities_container_perm_oid,
      capabilities_container_oid,
      adminid
    )

    capabilities_dataobject_perm_oid = Cdmioid.generate(45241)

    create_capabilities_dataobject_perm(
      capabilities_dataobject_perm_oid,
      capabilities_dataobject_oid,
      adminid
    )

    capabilities_domain_member_oid = Cdmioid.generate(45241)

    create_capabilities_domain_member(
      capabilities_domain_member_oid,
      capabilities_domain_oid,
      adminid
    )

    domaincontainer_oid = Cdmioid.generate(45241)
    create_domains_container(domaincontainer_oid, root_oid, adminid)

    sysdomain_oid = Cdmioid.generate(45241)
    create_system_domain(sysdomain_oid, domaincontainer_oid, adminid)

    defdomain_oid = Cdmioid.generate(45241)
    # create_default_domain(defdomain_oid, domaincontainer_oid, adminid)
    create_default_domain(defdomain_oid, defdomain_oid, adminid)

    members_oid = Cdmioid.generate(45241)
    create_domain_members_container(members_oid, sysdomain_oid, adminid)

    defmembers_oid = Cdmioid.generate(45241)

    create_default_domain_members_container(
      defmembers_oid,
      defdomain_oid,
      adminid
    )

    summary_oid = Cdmioid.generate(45241)
    create_domain_summary(summary_oid, sysdomain_oid, adminid)

    for period <- ["cumulative", "daily", "monthly", "yearly"] do
      period_oid = Cdmioid.generate(45241)
      create_domain_summary_period(period_oid, summary_oid, adminid, period)
    end

    defsummary_oid = Cdmioid.generate(45241)
    create_default_domain_summary(defsummary_oid, defdomain_oid, adminid)

    for period <- ["cumulative", "daily", "monthly", "yearly"] do
      period_oid = Cdmioid.generate(45241)

      create_default_domain_summary_period(
        period_oid,
        defsummary_oid,
        adminid,
        period
      )
    end

    {:adminpw, pswd} = List.keyfind(options, :adminpw, 0)
    admin_oid = Cdmioid.generate(45241)
    create_administrator_member(admin_oid, members_oid, adminid, pswd)

    sysconfig_oid = Cdmioid.generate(45241)
    create_sysconfig(sysconfig_oid, root_oid, adminid)

    domain_maps_oid = Cdmioid.generate(45241)
    create_domain_maps(domain_maps_oid, sysconfig_oid, adminid)

    env_vars_oid = Cdmioid.generate(45241)
    create_env_vars(env_vars_oid, sysconfig_oid, adminid)
  end

  defp parse_args(args) do
    {options, bootstrap_file, _errors} =
      OptionParser.parse(
        args,
        switches: [
          host: :string,
          port: :integer,
          adminid: :string,
          adminpw: :string,
          crc16nifpath: :string
        ]
      )

    IO.puts("options: #{inspect(options)} bootstrap_file: #{inspect(bootstrap_file)}")
    {options, bootstrap_file}
  end

  defp create_root(oid, adminid) do
    timestamp = make_timestamp()

    object = %{
      capabilitiesURI: "#{capabilities_uri()}",
      children: [
        "cdmi_domains/",
        "system_configuration/",
        "cdmi_capabilities/"
      ],
      childrenrange: "0-2",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner(),
          acl_authenticated()
        ],
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_owner: "#{adminid}"
      },
      objectID: "#{oid}",
      objectName: "/",
      objectType: "application/cdmi-container"
    }

    Logger.debug("Creating object: #{inspect(object, pretty: true)}")
    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_capabilities(oid, parentid, _adminid) do
    object = %{
      capabilities: %{
        cdmi_acl: "true",
        cdmi_copy_dataobject_from_queue: "false",
        cdmi_copy_domain: "false",
        cdmi_copy_queue_by_ID: "false",
        cdmi_copy_container: "false",
        cdmi_copy_dataobject: "false",
        cdmi_create_container: "true",
        cdmi_create_dataobject: "true",
        cdmi_create_domain: "true",
        cdmi_create_queue: "false",
        cdmi_create_reference: "false",
        cdmi_create_reference_by_ID: "false",
        cdmi_create_value_range_by_ID: "false",
        cdmi_dataobjects: "true",
        cdmi_delete_container: "true",
        cdmi_delete_dataobject: "true",
        cdmi_delete_domain: "true",
        cdmi_deserialize_dataobject_by_ID: "false",
        cdmi_deserialize_domain: "false",
        cdmi_deserialize_queue_by_ID: "false",
        cdmi_domains: "true",
        cdmi_export_cifs: "false",
        cdmi_export_iscsi: "false",
        cdmi_export_nfs: "false",
        cdmi_export_occi_iscsi: "false",
        cdmi_export_webdav: "false",
        cdmi_list_children: "true",
        cdmi_list_children_range: "true",
        cdmi_logging: "false",
        cdmi_metadata_maxitems: 1024,
        cdmi_metadata_maxsize: 8192,
        cdmi_metadata_maxtotalsize: 8_388_608,
        cdmi_modify_deserialize_dataobject: "false",
        cdmi_modify_metadata: "true",
        cdmi_move_container: "false",
        cdmi_move_dataobject: "false",
        cdmi_move_domain: "false",
        cdmi_multipart_mime: "false",
        cdmi_notification: "false",
        cdmi_object_access_by_ID: "true",
        cdmi_object_copy_from_local: "false",
        cdmi_object_copy_from_remote: "false",
        cdmi_object_move_from_ID: "false",
        cdmi_object_move_from_local: "false",
        cdmi_object_move_from_remote: "false",
        cdmi_object_move_to_ID: "false",
        cdmi_post_dataobject: "false",
        cdmi_post_dataobject_by_ID: "false",
        cdmi_post_queue_by_ID: "false",
        cdmi_post_queue: "false",
        cdmi_query: "false",
        cdmi_query_contains: "false",
        cdmi_query_regex: "false",
        cdmi_query_tags: "false",
        cdmi_query_value: "false",
        cdmi_queues: "false",
        cdmi_read_metadata: "true",
        cdmi_references: "false",
        cdmi_security_access_control: "true",
        cdmi_security_audit: "false",
        cdmi_security_data_integrity: "true",
        cdmi_security_immutability: "false",
        cdmi_security_sanitization: "false",
        cdmi_serialization_json: "false",
        cdmi_serialize_container_ID: "false",
        cdmi_serialize_dataobject_to_ID: "false",
        cdmi_serialize_domain_to_ID: "false",
        cdmi_serialize_queue_to_ID: "false",
        cdmi_serialize_container: "false",
        cdmi_serialize_dataobject: "false",
        cdmi_serialize_domain: "false",
        cdmi_serialize_queue: "false",
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

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_capabilities_container(oid, parentid, _adminid) do
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
        cdmi_security_access_control: "true",
        cdmi_serialize_container: "false",
        cdmi_serialize_dataobject: "false",
        cdmi_serialize_domain: "false",
        cdmi_serialize_queue: "false",
        cdmi_size: "true",
        cdmi_snapshot: "false",
        cdmi_throughput: "false",
        cdmi_value_hash: value_hash_methods()
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

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_capabilities_container_perm(oid, parentid, _adminid) do
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
        cdmi_security_access_control: "true",
        cdmi_serialize_container: "false",
        cdmi_serialize_dataobject: "false",
        cdmi_serialize_domain: "false",
        cdmi_serialize_queue: "false",
        cdmi_size: "true",
        cdmi_snapshot: "false",
        cdmi_throughput: "false",
        cdmi_value_hash: value_hash_methods()
      },
      objectID: "#{oid}",
      objectName: "permanent/",
      objectType: "application/cdmi-capability",
      parentID: "#{parentid}",
      parentURI: "/cdmi_capabilities/container/"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_capabilities_domain(oid, parentid, _adminid) do
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
        cdmi_security_access_control: "true",
        cdmi_size: "true",
        cdmi_throughput: "false",
        cdmi_value_hash: value_hash_methods()
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

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_capabilities_dataobject(oid, parentid, _adminid) do
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
        cdmi_security_access_control: "true",
        cdmi_size: "true",
        cdmi_throughput: "false",
        cdmi_value_hash: value_hash_methods()
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

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_capabilities_dataobject_perm(oid, parentid, _adminid) do
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
        cdmi_security_access_control: "true",
        cdmi_size: "true",
        cdmi_throughput: "false",
        cdmi_value_hash: value_hash_methods()
      },
      objectID: "#{oid}",
      objectName: "permanent/",
      objectType: "application/cdmi-capability",
      parentID: "#{parentid}",
      parentURI: "/cdmi_capabilities/dataobject/"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_capabilities_domain_member(oid, parentid, _adminid) do
    object = %{
      capabilities: %{
        cdmi_acl: "true",
        cdmi_delete_dataobject: "true",
        cdmi_modify_deserialize_dataobject: "false",
        cdmi_modify_metadata: "true",
        cdmi_modify_value: "true",
        cdmi_modify_value_range: "true",
        cdmi_read_metadata: "true",
        cdmi_read_value: "true",
        cdmi_read_value_range: "true",
        cdmi_security_access_control: "true"
      },
      objectID: "#{oid}",
      objectName: "member/",
      objectType: "application/cdmi-capability",
      parentID: "#{parentid}",
      parentURI: "/cdmi_capabilities/domain/"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_domains_container(oid, parentid, adminid) do
    timestamp = make_timestamp()

    object = %{
      capabilitiesURI: "#{capabilities_uri()}domain/",
      children: [
        "default_domain/",
        "system_domain/"
      ],
      childrenrange: "0-1",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner_inherited(),
          acl_authenticated_inherited()
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

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_default_domain(oid, parentid, adminid) do
    timestamp = make_timestamp()

    object = %{
      capabilitiesURI: "#{capabilities_uri()}domain/",
      children: [
        "cdmi_domain_members/",
        "cdmi_domain_summary/"
      ],
      childrenrange: "0-1",
      completionStatus: "complete",
      domainURI: "#{default_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner(),
          acl_authenticated(),
          acl_owner_inherited(),
          acl_authenticated_inherited()
        ],
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_owner: "#{adminid}",
        cdmi_domain_enabled: "true"
      },
      objectID: "#{oid}",
      objectName: "default_domain/",
      objectType: "application/cdmi-domain",
      parentID: "#{parentid}",
      parentURI: "/cdmi_domains/"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_system_domain(oid, parentid, adminid) do
    timestamp = make_timestamp()

    object = %{
      capabilitiesURI: "#{capabilities_uri()}domain/",
      children: [
        "cdmi_domain_members/",
        "cdmi_domain_summary/"
      ],
      childrenrange: "0-1",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner(),
          acl_authenticated(),
          acl_owner_inherited(),
          acl_authenticated_inherited()
        ],
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_owner: "#{adminid}",
        cdmi_domain_enabled: "true"
      },
      objectID: "#{oid}",
      objectName: "system_domain/",
      objectType: "application/cdmi-domain",
      parentID: "#{parentid}",
      parentURI: "/cdmi_domains/"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_domain_members_container(oid, parentid, adminid) do
    timestamp = make_timestamp()

    object = %{
      capabilitiesURI: "#{capabilities_uri()}domain/",
      children: [
        "#{adminid}"
      ],
      childrenrange: "0-0",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner(),
          acl_authenticated(),
          acl_owner_inherited(),
          acl_authenticated_inherited()
        ],
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_owner: "#{adminid}",
        cdmi_domain_enabled: "true"
      },
      objectID: "#{oid}",
      objectName: "cdmi_domain_members/",
      objectType: "application/cdmi-container",
      parentID: "#{parentid}",
      parentURI: "/cdmi_domains/system_domain/"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_default_domain_members_container(oid, parentid, adminid) do
    timestamp = make_timestamp()

    object = %{
      capabilitiesURI: "#{capabilities_uri()}container/",
      children: [],
      childrenrange: "",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner(),
          acl_authenticated(),
          acl_owner_inherited(),
          acl_authenticated_inherited()
        ],
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_owner: "#{adminid}",
        cdmi_domain_enabled: "true"
      },
      objectID: "#{oid}",
      objectName: "cdmi_domain_members/",
      objectType: "application/cdmi-container",
      parentID: "#{parentid}",
      parentURI: "/cdmi_domains/default_domain/"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_domain_summary(oid, parentid, adminid) do
    timestamp = make_timestamp()

    object = %{
      capabilitiesURI: "#{capabilities_uri()}domain/",
      children: [
        "cumulative/",
        "yearly/",
        "monthly/",
        "daily/"
      ],
      childrenrange: "0-3",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner(),
          acl_authenticated(),
          acl_owner_inherited(),
          acl_authenticated_inherited()
        ],
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_owner: "#{adminid}",
        cdmi_domain_enabled: "true"
      },
      objectID: "#{oid}",
      objectName: "cdmi_domain_summary/",
      objectType: "application/cdmi-container",
      parentID: "#{parentid}",
      parentURI: "/cdmi_domains/system_domain/"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_default_domain_summary(oid, parentid, adminid) do
    timestamp = make_timestamp()

    object = %{
      capabilitiesURI: "#{capabilities_uri()}domain/",
      children: [
        "cumulative/",
        "yearly/",
        "monthly/",
        "daily/"
      ],
      childrenrange: "0-3",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner(),
          acl_authenticated(),
          acl_owner_inherited(),
          acl_authenticated_inherited()
        ],
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_owner: "#{adminid}",
        cdmi_domain_enabled: "true"
      },
      objectID: "#{oid}",
      objectName: "cdmi_domain_summary/",
      objectType: "application/cdmi-container",
      parentID: "#{parentid}",
      parentURI: "/cdmi_domains/default_domain/"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_default_domain_summary_period(oid, parentid, adminid, period) do
    timestamp = make_timestamp()

    object = %{
      capabilitiesURI: "#{capabilities_uri()}domain/",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner(),
          acl_authenticated(),
          acl_owner_inherited(),
          acl_authenticated_inherited()
        ],
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_owner: "#{adminid}",
        cdmi_domain_enabled: "true"
      },
      objectID: "#{oid}",
      objectName: "#{period}/",
      objectType: "application/cdmi-container",
      parentID: "#{parentid}",
      parentURI: "/cdmi_domains/default_domain/cdmi_domain_summary/"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_domain_summary_period(oid, parentid, adminid, period) do
    timestamp = make_timestamp()

    object = %{
      capabilitiesURI: "#{capabilities_uri()}domain/",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner(),
          acl_authenticated(),
          acl_owner_inherited(),
          acl_authenticated_inherited()
        ],
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_owner: "#{adminid}",
        cdmi_domain_enabled: "true"
      },
      objectID: "#{oid}",
      objectName: "#{period}/",
      objectType: "application/cdmi-container",
      parentID: "#{parentid}",
      parentURI: "/cdmi_domains/system_domain/cdmi_domain_summary/"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_administrator_member(oid, parentid, adminid, pswd) do
    Logger.info("Creating domain member #{inspect(adminid)}")
    timestamp = make_timestamp()
    encrypted_pswd = encrypt(adminid, pswd)

    object = %{
      capabilitiesURI: "#{capabilities_uri()}domain/member/",
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
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      objectID: "#{oid}",
      objectName: "#{adminid}",
      objectType: "application/cdmi-object",
      parentID: "#{parentid}",
      parentURI: "/cdmi_domains/system_domain/cdmi_domain_members/"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_sysconfig(oid, parentid, adminid) do
    timestamp = make_timestamp()

    object = %{
      capabilitiesURI: "#{capabilities_uri()}container/permanent/",
      children: [
        "environment_variables",
        "domain_maps"
      ],
      childrenrange: "0-1",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner(),
          acl_authenticated(),
          acl_owner_inherited(),
          acl_authenticated_inherited()
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

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_domain_maps(oid, parentid, adminid) do
    timestamp = make_timestamp()
    value =
      "{\"cdmi.localhost.net\": \"system_domain/\", \"default.localhost.net\": \"default_domain/\"}"
    {hash_method, hashed_value} = value_hash(value, value_hash_methods())

    object = %{
      capabilitiesURI: "#{capabilities_uri()}dataobject/permanent/",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner(),
          acl_authenticated(),
          acl_owner_inherited(),
          acl_authenticated_inherited()
        ],
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_owner: "#{adminid}",
        cdmi_hash: "#{hashed_value}",
        cdmi_: "#{String.length(value)}"
      },
      objectID: "#{oid}",
      objectName: "domain_maps",
      objectType: "application/cdmi-object",
      parentID: "#{parentid}",
      parentURI: "/system_configuration/",
      value: "#{value}",
      valuetransferencoding: "utf-8"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  defp create_env_vars(oid, parentid, adminid) do
    timestamp = make_timestamp()
    value = "{}"
    {hash_method, hashed_value} = value_hash(value, value_hash_methods())

    object = %{
      capabilitiesURI: "#{capabilities_uri()}container/permanent/",
      completionStatus: "complete",
      domainURI: "#{system_domain_uri()}",
      metadata: %{
        cdmi_acl: [
          acl_owner(),
          acl_authenticated(),
          acl_owner_inherited(),
          acl_authenticated_inherited()
        ],
        cdmi_atime: "#{timestamp}",
        cdmi_ctime: "#{timestamp}",
        cdmi_mtime: "#{timestamp}",
        cdmi_owner: "#{adminid}",
        cdmi_hash: "#{hashed_value}",
        cdmi_value_hash: "#{hash_method}"
      },
      objectID: "#{oid}",
      objectName: "environment_variables",
      objectType: "application/cdmi-object",
      parentID: "#{parentid}",
      parentURI: "/system_configuration/",
      value: "#{value}",
      valuerange: "0-1",
      valuetransferencoding: "utf-8"
    }

    GenServer.call(Metadata, {:put, oid, object})
  end

  @doc """
  Encrypt.
  """
  @spec encrypt(String.t(), String.t()) :: String.t()
  def encrypt(key, message) do
    :crypto.hmac(:sha, key, message)
    |> Base.encode16()
    |> String.downcase()
  end

  @spec make_timestamp() :: String.t()
  defp make_timestamp() do
    {{year, month, day}, {hour, minute, second}} =
      :calendar.now_to_universal_time(:os.timestamp())

    List.flatten(
      :io_lib.format("~4..0w-~2..0w-~2..0wT~2..0w:~2..0w:~2..0w.000000Z", [
        year,
        month,
        day,
        hour,
        minute,
        second
      ])
    )
  end

  @spec value_hash(String.t(), list) :: tuple
  defp value_hash(value, methods) do
    hash_method =
      cond do
        "SHA512" in methods -> "SHA512"
        "SHA384" in methods -> "SHA384"
        "SHA256" in methods -> "SHA256"
        "SHA224" in methods -> "SHA224"
        "SHA1" in methods -> "SHA1"
        "MD5" in methods -> "MD5"
      end

    method = hash_method |> String.downcase() |> String.to_atom()
    hashed_value = :crypto.hash(method, value) |> Base.encode16() |> String.downcase()
    {hash_method, hashed_value}
  end
end
