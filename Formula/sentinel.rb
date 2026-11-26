# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.19.2"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.19.2/sentinel-0.19.2-darwin-arm64"
      sha256 "7fd96b6f45dedd7d5f90458c817638f4b4cc06fcb3d24755d7ec3d8c93b80719"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.19.2/sentinel-0.19.2-darwin-amd64"
      sha256 "3143e12d9c349d8808e68ef05d447d665a36071a73f48f078761ec03b8076afd"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.19.2/sentinel-0.19.2-linux-arm64"
      sha256 "e2df8ad3525fcad713c47d8903470661deeeccb1c4dacd9d2065aada3d69302b"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.19.2/sentinel-0.19.2-linux-amd64"
      sha256 "83620f907fbc9c06e2cf702c75d14add293269ea1ff60a84e5d8ebbadf7e2ad4"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
