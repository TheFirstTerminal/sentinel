# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.17.5"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.5/sentinel-0.17.5-darwin-arm64"
      sha256 "c15861c67b9f121de2d480e95f2a0003b5a664c34ea5829f4e38c18d4b956dfe"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.5/sentinel-0.17.5-darwin-amd64"
      sha256 "d0fba24466558714f949e23a07d5e2423d967d847021a84f9a0ab2ba1418a57b"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.5/sentinel-0.17.5-linux-arm64"
      sha256 "6b4d03ccd0e4c1b86819213bc28f201c279b9ba0d49ff862f41f1a905408200b"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.5/sentinel-0.17.5-linux-amd64"
      sha256 "88b4a78732b82b0c57bd4357a9502ad022c095678756bde87b00606d78b89199"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
