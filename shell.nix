{ pkgs ? import <nixos> {}
}:

with pkgs;

mkShell {
  name = "servant-auth";
  buildInputs = [
    ghc
    stack zlib
  ];
}
