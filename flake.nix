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
          llvmPackages.clang-unwrapped # unwrapped clang for BPF target (no nix hardening flags)
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
          export BPF_CLANG="${pkgs.llvmPackages.clang-unwrapped}/bin/clang"
          export BPF_CFLAGS="-O2 -g -target bpf -I ${pkgs.libbpf}/include -I ./ebpf/c"
          echo "aisre dev shell loaded"
          echo "  Go:       $(go version)"
          echo "  Clang:    $(clang --version | head -1)"
          echo "  BPF Clang: $BPF_CLANG"
          echo "  Protoc:   $(protoc --version)"
        '';

        env = {
          GOPRIVATE = "gitlab.michelin.com/*";
        };
      };
    };
}
