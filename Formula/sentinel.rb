# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.17.1"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.1/sentinel-0.17.1-darwin-arm64"
      sha256 "729ee9575735df488639b4d413df9f27f686124fd8afcf7cd8fe0a6fe0562e0c"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.1/sentinel-0.17.1-darwin-amd64"
      sha256 "1825048d0af5f2d33ca8951e6a24ed9fe4e6bdee02750064dbb7d76b0562939c"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.1/sentinel-0.17.1-linux-arm64"
      sha256 "c64d0b383b189ebdbd330d3ddc09a0912da46d7ea12e8207425eb2481f3e536d"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.1/sentinel-0.17.1-linux-amd64"
      sha256 "7be56f17f57b0368d040289bfdf166371a6a9025750b86e0fe9fd7b08b217c19"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
