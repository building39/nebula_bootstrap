defmodule NebulaBootstrap.Mixfile do
  use Mix.Project
#  @on_load :load_nifs

  def load_nifs() do
    :erlang.load_nif("./deps/crc16/priv/crc16", 0)
  end

  def project do
    [app: :nebula_bootstrap,
     version: "0.1.0",
     elixir: "~> 1.9",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     escript: [main_module: NebulaBootstrap],
     deps: deps()]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [applications: [:logger,
                    :nebula_metadata,
                    :elcrc16
                   ]
    ]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #Eltem
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [
      {:logger_file_backend, "~> 0.0.11"},
      {:poison, "~> 4.0", override: true},
      {:cdmioid, git: "https://github.com/building39/cdmioid.git", tag: "0.1.1"},
      {:nebula_metadata, git: "git@github.com:building39/nebula_metadata.git", tag: "v0.3.1"}
    ]
  end
end
