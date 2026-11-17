{
  description = "Kopuz with native Qobuz support";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/d77d6df4729d457ab9118868df8cedba0e76bf9e";
  # A flake input, not fetchFromGitHub + import: evaluation must not need a
  # build, or the release gate's no-build retained-root evaluation fails.
  inputs.crane.url = "github:ipetkov/crane/dbd1288af7a7ec997cb912c034b1a1962938173e";
  outputs = {
    self,
    nixpkgs,
    crane,
    ...
  }: let
    systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin"];
    pkgsFor = system:
      import nixpkgs {
        inherit system;
        config.allowUnfree = false;
      };
    packagesFor = system: let
      pkgs = pkgsFor system;
    in
      pkgs.callPackage ./nix/package.nix {
        gitRev = self.rev or self.dirtyRev or null;
        craneLib = crane.mkLib pkgs;
      };
  in {
    packages = nixpkgs.lib.genAttrs systems (system: {
      default = packagesFor system;
      kopuz = packagesFor system;
    });
    checks = nixpkgs.lib.genAttrs systems (system: {qobuz = (packagesFor system).qobuzTests;});
    devShells = nixpkgs.lib.genAttrs systems (system: let
      pkgs = pkgsFor system;
      app = packagesFor system;
    in {
      default = pkgs.mkShell {
        inputsFrom = [app.buildPackage];
        packages = with pkgs; [cargo rustc rustfmt clippy clang gitleaks];
        RUSTY_V8_ARCHIVE = app.RUSTY_V8_ARCHIVE;
        SQLX_OFFLINE = "true";
      };
    });
  };
}
