# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
use Mix.Config

# This configuration is loaded before any dependency and is restricted
# to this project. If another project depends on this project, this
# file won't be loaded nor affect the parent project. For this reason,
# if you want to provide default values for your application for
# 3rd-party users, it should be done in your "mix.exs" file.

# You can configure for your application as:
#
#     config :nebula_bootstrap, key: :value
#
# And access this configuration in your application as:
#
#     Application.get_env(:nebula_bootstrap, :key)
#
# Or configure a 3rd-party app:
#
#     config :logger, level: :info
#

# It is also possible to import configuration files, relative to this
# directory. For example, you can emulate configuration per environment
# by uncommenting the line below and defining dev.exs, test.exs and such.
# Configuration from the imported file will override the ones defined
# here (which is why it is important to import them last).
#
#     import_config "#{Mix.env}.exs"

config :memcache_client,
  transcoder: Memcache.Client.Transcoder.Json

config :pooler, pools:
  [
    [
      name: :riaklocal1,
      group: :riak,
      max_count: 10,
      init_count: 5,
      start_mfa: { Riak.Connection, :start_link, ['192.168.2.11', 8087] }
    ]
  ]

  config :logger,
    format: "[$level] $message\n",
    metadata: [:file, :line],
    backends: [{LoggerFileBackend, :info},
               {LoggerFileBackend, :debug},
               {LoggerFileBackend, :error}]

  config :logger, :debug,
    colors: [enabled: :true],
    metadata: [:pid, :file, :line],
    path: "/var/log/nebula/debug.log",
    format: "$time $date [$level] $levelpad $metadata $message\n",
    level: :debug

  config :logger, :error,
    colors: [enabled: :true],
    metadata: [:pid],
    path: "/var/log/nebula/error.log",
    format: "$time $date [$level] $levelpad $metadata $message\n",
    level: :error

  config :logger, :info,
    colors: [enabled: :true],
    metadata: [:pid],
    path: "/var/log/nebula/info.log",
    format: "$time $date [$level] $levelpad $metadata $message\n",
    level: :info
