# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.19.0"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.19.0/sentinel-0.19.0-darwin-arm64"
      sha256 "cc3994323f08b4104be4acdc1c447a6145090d6b89b04fd603baca699261ab88"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.19.0/sentinel-0.19.0-darwin-amd64"
      sha256 "20cfa5d5b84de13d29e184eece7311f1f1296f5aa373321aba6a79cf5958a7ad"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.19.0/sentinel-0.19.0-linux-arm64"
      sha256 "eaaba5c9b21fae570687727693c9ac1e6a77abf5abb9d16b7c6c4bddd5e8e253"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.19.0/sentinel-0.19.0-linux-amd64"
      sha256 "6e64d9ce80386fc0e09b58adb545295084cfc3349770497e1456e64bf79140fa"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
