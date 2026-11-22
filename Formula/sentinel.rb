# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.17.4"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.4/sentinel-0.17.4-darwin-arm64"
      sha256 "b7effc5a12d48cd916352fd1320a3757e99738d031ac2e2ee0bd1866e9e46a1f"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.4/sentinel-0.17.4-darwin-amd64"
      sha256 "5aa975b7e854fad2ba834ee946db4584c154178f18c6927ba1e6c23e365187df"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.4/sentinel-0.17.4-linux-arm64"
      sha256 "01f20b7923d7cae55c6f8ae625c115e7faf4b2986abbb5a791dfbea1768722a8"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.4/sentinel-0.17.4-linux-amd64"
      sha256 "f7698212dfa1d761ee76800d11274d2edef23c47a4e774fcb691793be3d4900c"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
