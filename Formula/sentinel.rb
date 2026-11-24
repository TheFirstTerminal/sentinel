# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.17.9"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.9/sentinel-0.17.9-darwin-arm64"
      sha256 "db2b2528ac4ae5a456631241b39c0bc0669a3624fdc61664dbb72d0249095f04"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.9/sentinel-0.17.9-darwin-amd64"
      sha256 "8a24ad4e432b2d33f830d7a7d3de7af0874f9e9a00dc4726fef96d4190d6672e"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.9/sentinel-0.17.9-linux-arm64"
      sha256 "1901aad0fe8e706ceffda2c314eb4b81af2115cf212765533535aea52778e627"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.9/sentinel-0.17.9-linux-amd64"
      sha256 "e19e077e6d8afb81ef20447e14a4bbf979d7c48ba8ca4c4f77c6a5c403d1e42d"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
