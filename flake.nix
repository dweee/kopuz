{
  description = "Kopuz with native Qobuz support";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/5f9880cb30e73e4f8090e9e69acba3b14c0bd5bd";
  # A flake input, not fetchFromGitHub + import: evaluation must not need a
  # build, or the release gate's no-build retained-root evaluation fails.
  inputs.crane.url = "github:ipetkov/crane/80db5bdc391be8a1794f6d8a2d56e3a84ebcede2";
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
