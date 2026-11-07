{
  description = "Bouncer passkey-authenticated reverse proxy";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          bouncer = pkgs.buildGo127Module rec {
            pname = "bouncer";
            version = "0.2.1";
            src = pkgs.lib.cleanSource ./.;
            vendorHash = "sha256-0fLE5GkB+LttC97Y7qEAreBA5gfsybZQfNHomz7PtZI=";
            subPackages = [ "." ];
            env.CGO_ENABLED = "0";
            ldflags = [
              "-s"
              "-w"
              "-X main.version=${version}"
            ];
            nativeBuildInputs = [ pkgs.gnumake ];
            checkPhase = ''
              runHook preCheck
              export GOFLAGS="''${GOFLAGS//-trimpath/} -p=$NIX_BUILD_CORES"
              make test
              runHook postCheck
            '';
            meta = {
              description = "Passkey-authenticated HTTP reverse proxy with local TLS and explicit ingresses";
              homepage = "https://github.com/rcarmo/bouncer";
              license = pkgs.lib.licenses.mit;
              mainProgram = "bouncer";
              platforms = systems;
            };
          };
        in
        {
          inherit bouncer;
          default = bouncer;
        }
      );

      apps = nixpkgs.lib.genAttrs systems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/bouncer";
          meta.description = self.packages.${system}.default.meta.description;
        };
      });

      checks = nixpkgs.lib.genAttrs systems (system: {
        package = self.packages.${system}.default;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.go_1_27
            pkgs.gnumake
            pkgs.git
            pkgs.openssl
            pkgs.bun
          ];
          GOTOOLCHAIN = "local";
          LINT_TOOLCHAIN = "local";
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
