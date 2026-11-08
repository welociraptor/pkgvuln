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
          python = pkgs.python315;
        in
        {
          default = python.pkgs.buildPythonApplication {
            pname = "pkgvuln";
            version = "0.1.0";
            pyproject = true;
            src = self;
            build-system = [ python.pkgs.uv-build ];
            doCheck = true;
            checkPhase = ''
              runHook preCheck
              PYTHONPATH=src python -m unittest discover -s tests
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

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          python = pkgs.python315;
        in
        {
          default = pkgs.mkShell {
            packages = [ pkgs.uv python ];
            shellHook = ''
              # Use the interpreter from the shell; never download one.
              export UV_PYTHON=${python}/bin/python
              export UV_PYTHON_DOWNLOADS=never
            '';
          };
        });
    };
}