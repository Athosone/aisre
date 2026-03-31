{
  description = "AISRE - eBPF HTTP traffic capture dev environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      nixpkgs,
      ...
    }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
      };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        name = "aisre";

        packages = with pkgs; [
          # Go toolchain
          go
          delve
          gopls
          golangci-lint

          # eBPF toolchain
          clang
          llvm
          libbpf
          bpftools
          bpftrace
          linuxHeaders

          # Protobuf
          protobuf
          protoc-gen-go

          # Build tools
          gnumake
          pkg-config

        ];

        shellHook = ''
          echo "aisre dev shell loaded"
          echo "  Go:       $(go version)"
          echo "  Clang:    $(clang --version | head -1)"
          echo "  Protoc:   $(protoc --version)"
        '';

        env = {
          GOPRIVATE = "gitlab.michelin.com/*";
        };
      };
    };
}
