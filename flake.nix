{
  description = "Snapshot installed Nix packages and match them against vulnerability advisories";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python3;
        in
        {
          default = python.pkgs.buildPythonApplication {
            pname = "pkgvuln";
            version = "0.1.0";
            pyproject = true;
            src = self;
            build-system = [ python.pkgs.setuptools ];
            doCheck = true;
            checkPhase = ''
              runHook preCheck
              python -m unittest pkgvuln.test_pkgvuln
              runHook postCheck
            '';
            meta = {
              description = "Vulnerability scanning and version snapshots for Nix packages";
              mainProgram = "pkgvuln";
            };
          };
        });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/pkgvuln";
        };
      });
    };
}