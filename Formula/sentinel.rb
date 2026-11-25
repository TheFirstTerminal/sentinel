# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.18.1"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.18.1/sentinel-0.18.1-darwin-arm64"
      sha256 "f91337c82f9a9fb5c20541ba229210f355f4d9563c140f3869637b26feb032e7"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.18.1/sentinel-0.18.1-darwin-amd64"
      sha256 "b2c90e538b2be7f009e2955f8e7a1e011b4e7019785ea3a9916dc9c1d9db7a77"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.18.1/sentinel-0.18.1-linux-arm64"
      sha256 "e4766e071e1be324eac7e2804e3d888128ebcee410075e409812afb408a1e1dc"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.18.1/sentinel-0.18.1-linux-amd64"
      sha256 "3cbf306fb8564fe4bcfe72144b2ad07f1be869a17d87409813f48d711da1aee9"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
