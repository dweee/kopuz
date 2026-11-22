{
  description = "Kopuz with native Qobuz support";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/2b7835143e80140e6fd6b37a2e6f323f74d429c9";
  # A flake input, not fetchFromGitHub + import: evaluation must not need a
  # build, or the release gate's no-build retained-root evaluation fails.
  inputs.crane.url = "github:ipetkov/crane/95e62def851e9d650f0eab63cb4f59a3306e20bd";
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay/e013376c32a8fcf07ddb6ec71739552bc118b7bd";
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
