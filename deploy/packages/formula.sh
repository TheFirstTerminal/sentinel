#!/bin/sh
# Writes the Homebrew formula for a release from its checksums:
#   deploy/packages/formula.sh 0.14.0 dist/checksums.txt > Formula/sentinel.rb
set -eu
v=$1 sums=$2
sha() { grep " sentinel-$v-$1\$" "$sums" | cut -d' ' -f1; }
base="https://github.com/TheFirstTerminal/sentinel/releases/download/v$v"
cat <<EOF
# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "$v"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "$base/sentinel-$v-darwin-arm64"
      sha256 "$(sha darwin-arm64)"
    end
    on_intel do
      url "$base/sentinel-$v-darwin-amd64"
      sha256 "$(sha darwin-amd64)"
    end
  end
  on_linux do
    on_arm do
      url "$base/sentinel-$v-linux-arm64"
      sha256 "$(sha linux-arm64)"
    end
    on_intel do
      url "$base/sentinel-$v-linux-amd64"
      sha256 "$(sha linux-amd64)"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
EOF
