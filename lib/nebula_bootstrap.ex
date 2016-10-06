defmodule NebulaBootstrap do

  require Logger
  
  def main(args) do
    args |> parse_args |> process
  end

  def process([]) do
    IO.puts("No arguments given")
  end
  def process({options, bootstrap_file}) do
    IO.puts("Bootstrapping from file: #{bootstrap_file}")
    for n <- options, do: IO.inspect(n)
    System.put_env("CRC16_NIF_PATH", System.cwd() <> "/deps/elcrc16/priv/")
    create_root()
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

  defp create_root() do
    {oid, key} = Cdmioid.generate(45241)
    timestamp = make_timestamp()
    object = %{capabilitiesURI: "/cdmi_capabilities/",
               children: [],
               completionStatus: "complete",
               domainURI: "/cdmi_domains/system_domain/",
               metadata:
                %{cdmi_acls: [
                  %{aceflags: "OBJECT_INHERIT, CONTAINER_INHERIT",
                    acemask: "ALL_PERMS",
                    acetype: "ALLOW",
                    identifier: "OWNER@"},
                  %{aceflags: "OBJECT_INHERIT, CONTAINER_INHERIT",
                    acemask: "READ",
                    acetype: "ALLOW",
                    identifier: "AUTHENTICATED@"}],
                cdmi_atime: timestamp,
                cdmi_ctime: timestamp,
                cdmi_mtime: timestamp,
                cdmi_owner: "administrator"},
              objectID: oid,
              objectName: "/",
              objectType: "application/cdmi-container"}
    cdmi_object = %{cdmi: object}
    response = GenServer.call(Metadata, {:put, key, cdmi_object})
    Logger.debug("Put response:")
    IO.inspect(response)
  end

  defp make_timestamp() do
    {{year, month, day}, {hour, minute, second}} =
      :calendar.now_to_universal_time(:os.timestamp)
    List.flatten(:io_lib.format("~4..0w-~2..0w-~2..0wT~2..0w:~2..0w:~2..0w.000000Z",
      [year, month, day, hour, minute, second]))
  end
end
