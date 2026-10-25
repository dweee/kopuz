{
  description = "Kopuz with native Qobuz support";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/6410bcfef90b64c0416d57858c7aec1ec3042d4f";
  outputs = {
    self,
    nixpkgs,
    ...
  }: let
    systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin"];
    pkgsFor = system:
      import nixpkgs {
        inherit system;
        config.allowUnfree = false;
      };
    packagesFor = system: let pkgs = pkgsFor system; in pkgs.callPackage ./nix/package.nix {gitRev = self.rev or self.dirtyRev or null;};
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
