# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.17.3"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.3/sentinel-0.17.3-darwin-arm64"
      sha256 "d890343f6f32d215b1bad15ffe117ee25c6e4b6d74c6a5bd585e8a56705bf33d"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.3/sentinel-0.17.3-darwin-amd64"
      sha256 "c68cd063567e73a80b273dc95f70e505082d20a4631c24ead95e4f8e937a43c4"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.3/sentinel-0.17.3-linux-arm64"
      sha256 "f639952005def600008927745285a239757a111e529fb18def54635c5acf32fc"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.3/sentinel-0.17.3-linux-amd64"
      sha256 "53e4afc4f018db6984d2702b140b08f02e7e378d34b798604a6467a02a72685c"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
