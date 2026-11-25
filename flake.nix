{
  description = "Kopuz with native Qobuz support";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/a7331f828844e45246485f65ef5773bf6971bc2d";
  # A flake input, not fetchFromGitHub + import: evaluation must not need a
  # build, or the release gate's no-build retained-root evaluation fails.
  inputs.crane.url = "github:ipetkov/crane/95e62def851e9d650f0eab63cb4f59a3306e20bd";
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay/639e209cc8eecd0c307fd95c8aabc011bf047c41";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs =
    {
      self,
      nixpkgs,
      crane,
      rust-overlay,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
          config.allowUnfree = false;
        };
      packagesFor =
        system:
        let
          pkgs = pkgsFor system;
        in
        pkgs.callPackage ./nix/package.nix {
          gitRev = self.rev or self.dirtyRev or null;
          craneLib = (crane.mkLib pkgs).overrideToolchain (
            p: p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml
          );
        };
    in
    {
      packages = nixpkgs.lib.genAttrs systems (system: {
        default = packagesFor system;
        kopuz = packagesFor system;
      });
      checks = nixpkgs.lib.genAttrs systems (system: {
        qobuz = (packagesFor system).qobuzTests;
      });
      devShells = nixpkgs.lib.genAttrs systems (
        system:
        let
          pkgs = pkgsFor system;
          app = packagesFor system;
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ app.buildPackage ];
            packages = [
              (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml)
              pkgs.clang
              pkgs.gitleaks
            ];
            RUSTY_V8_ARCHIVE = app.RUSTY_V8_ARCHIVE;
            SQLX_OFFLINE = "true";
          };
        }
      );
    };
}
