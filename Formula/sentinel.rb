# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.18.0"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.18.0/sentinel-0.18.0-darwin-arm64"
      sha256 "7030ea1fb92a6378106a27f92f73bd236712b7bd46d4b6c34a802c7595eabe47"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.18.0/sentinel-0.18.0-darwin-amd64"
      sha256 "f7468664e2bce25b51a50dbd2bbc6258384df1f04e5d3091315665ebd62f3e4e"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.18.0/sentinel-0.18.0-linux-arm64"
      sha256 "520687069d70dacbffe052de55bab5a5ae4ae8c63534257663fe52b0d35f50b0"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.18.0/sentinel-0.18.0-linux-amd64"
      sha256 "e5d3b5f4b1ba793071158432278f8d2772e18ca4876792aecbab44e4c682a419"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
