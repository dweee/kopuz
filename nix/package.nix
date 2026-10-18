{
  pkgs,
  lib,
  source ? ../.,
  gitRev ? null,
  ...
}: let
  upstreamSource = pkgs.fetchFromGitHub {
    owner = "Kopuz-org";
    repo = "kopuz";
    rev = "552400339461ef09c09d4db133bf356ea8fead18";
    hash = "sha256-NbWq8mMYI14pJTlC1EXRJi5nEeRx+zvzaQVleRA1ZLY=";
  };
  craneSource = pkgs.fetchFromGitHub {
    owner = "ipetkov";
    repo = "crane";
    rev = "80db5bdc391be8a1794f6d8a2d56e3a84ebcede2";
    hash = "sha256-G6R9IT/xwFuu+CYBWDUAok6AdC4ERC4ZfPPFtEpxnZE=";
  };
  craneLib = import craneSource {inherit pkgs;};
  upstream = pkgs.callPackage (upstreamSource + /packaging/nix/crane.nix) {
    inherit craneLib;
  };
  qobuzTests = upstream.overrideAttrs (_: {
    pname = "kopuz-qobuz-tests";
    src = source;
    cargoArtifacts = compiled;
    doInstallCargoArtifacts = false;
    # rustls-platform-verifier initializes its trust store when Client is built,
    # including for loopback fixture tests. The sandbox has no host /etc/ssl.
    SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
    buildPhase = ''
      runHook preBuild
      cargo test --release --offline --frozen \
        -p kopuz-server -p kopuz-daemon -p kopuz-db \
        --lib --test normalized qobuz
      runHook postBuild
    '';
    installPhase = "mkdir -p $out; touch $out/passed";
    preFixup = "";
    dontFixup = true;
  });
  compiled = upstream.overrideAttrs (old: {
    version = "0.21.0-qobuz";
    src = source;
    __intentionallyOverridingVersion = true;
    KOPUZ_GIT_COMMIT =
      if gitRev == null
      then "qobuz-fork"
      else gitRev;
    nativeBuildInputs = old.nativeBuildInputs ++ [pkgs.makeWrapper];
    # Keep upstream's resource-directory wrapper and include the existing external
    # YouTube downloader in both GUI and daemon PATHs. Pin the dlopen path so
    # libraries inherited from a host app cannot override Nix glibc/libm.
    preFixup =
      builtins.replaceStrings
      [(lib.makeBinPath [pkgs.ffmpeg]) "--prefix LD_LIBRARY_PATH :" "--prefix PATH :"]
      [(lib.makeBinPath [pkgs.ffmpeg pkgs.yt-dlp]) "--set LD_LIBRARY_PATH" "--run 'umask 077' --prefix PATH :"]
      old.preFixup;
    installPhase =
      old.installPhase
      + lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
        mkdir -p "$out/Applications"
        mv "$out/bin/kopuz.app" "$out/Applications/Kopuz.app"
        rm "$out/bin/kopuz"
        binary=$(find "$out/Applications/Kopuz.app/Contents/MacOS" -maxdepth 1 -type f -print -quit)
        test -n "$binary"
        makeWrapper "$binary" "$out/bin/kopuz" \
          --run 'umask 077' \
          --prefix PATH : ${lib.makeBinPath [pkgs.ffmpeg pkgs.yt-dlp]}
      '';
    passthru =
      (old.passthru or {})
      // {
        qobuzEnabled = true;
        inherit upstreamSource qobuzTests;
      };
    meta =
      old.meta
      // {
        description = "Kopuz with native Qobuz sources, lossless playback and word-synced lyrics";
        homepage = "https://github.com/dweee/kopuz";
      };
  });
in
  pkgs.runCommand compiled.name {
    inherit (compiled) pname version meta;
    nativeBuildInputs = [pkgs.removeReferencesTo];
    passthru =
      compiled.passthru
      // {
        buildPackage = compiled;
        inherit (compiled) RUSTY_V8_ARCHIVE;
      };
    # Crane's mkCargoDerivation also installs a large target archive. Keep it
    # available for development builds, but exclude it from runtime closures.
    disallowedReferences = [compiled compiled.cargoVendorDir];
  } ''
    mkdir -p "$out"
    cp -R ${compiled}/bin "$out/bin"
    for directory in share Applications; do
      if [ -d "${compiled}/$directory" ]; then
        cp -R "${compiled}/$directory" "$out/$directory"
      fi
    done
    chmod -R u+w "$out"
    # Rust panic locations in the CLI retain Cargo's vendor path. These are
    # diagnostics, not runtime assets; avoid retaining the entire source tree.
    find "$out" -type f -exec remove-references-to -t ${compiled.cargoVendorDir} '{}' +
    substituteInPlace "$out/bin/kopuz" --replace-fail '${compiled}' "$out"
    ${lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
      substituteInPlace "$out/bin/kopuzd" \
        "$out/share/applications/moe.kopuz.kopuz.desktop" \
        "$out/share/systemd/user/kopuzd.service" \
        --replace-fail '${compiled}' "$out"
      # Preserve an explicitly supplied trust store; otherwise also work on hosts
      # without a conventional /etc/ssl directory.
      sed -i '2i export SSL_CERT_FILE="''${SSL_CERT_FILE:-${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt}"' \
        "$out/bin/kopuz" "$out/bin/kopuzd"
    ''}
  ''
