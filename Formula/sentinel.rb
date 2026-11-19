# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.16.4"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.16.4/sentinel-0.16.4-darwin-arm64"
      sha256 "09120ef577b8f31071c8b85c223abd1e6a3410b4e20f3ff51665d8d3cc761646"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.16.4/sentinel-0.16.4-darwin-amd64"
      sha256 "a3a4998c56aa8ad683f05b51fb7c49d24f4391682826ab3e1961a54ee9000d14"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.16.4/sentinel-0.16.4-linux-arm64"
      sha256 "be62f8ddb4824839695aebc4d61785ad2fc8d680e4fa10659801e7aa12549a4d"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.16.4/sentinel-0.16.4-linux-amd64"
      sha256 "e69401de2790b30451f7ee22e9a4104c0599e511eb4c330140fab4d9b46ba7b6"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
