# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.16.2"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.16.2/sentinel-0.16.2-darwin-arm64"
      sha256 "1eebb891b74decbf72179b6a8997c59ca46bd06e4a8ea884450036c5192fd235"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.16.2/sentinel-0.16.2-darwin-amd64"
      sha256 "1604d11c97ae295c03cdbf74def434fb7dab00b0b988b2b98b502e9368866e5b"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.16.2/sentinel-0.16.2-linux-arm64"
      sha256 "1f2d174ec0bed9332dd2e3f50b82769d605f6ac7452b90bac382a34dc55d40ef"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.16.2/sentinel-0.16.2-linux-amd64"
      sha256 "85111d39746321936cee27b38c2738d6fb3eb47f497b1dfcd5bf8def681f412e"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
