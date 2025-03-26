#!/usr/bin/env just --justfile
set shell := ["zsh", "-cu"]
set fallback

default:
  just -u --list

test:
  npx @wong2/mcp-cli uv run python -m crystaldba.postgres_mcp

dev:
  uv run mcp dev -e . crystaldba/postgres_mcp/server.py

nix-claude-desktop:
  NIXPKGS_ALLOW_UNFREE=1 nix run "github:k3d3/claude-desktop-linux-flake#claude-desktop-with-fhs" --impure

