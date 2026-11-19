# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.17.0"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.0/sentinel-0.17.0-darwin-arm64"
      sha256 "a28a4c0770e84bd155195080d9ba4b6b3af47f5e1795272037207b3e54102030"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.0/sentinel-0.17.0-darwin-amd64"
      sha256 "5a639b387612acf3fc8f8456471e7748693d7db3cf6427a48879b1ba0400f391"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.0/sentinel-0.17.0-linux-arm64"
      sha256 "f4bc96c1685ba5fac36393dc64d8254b15184f5f126b4f858e47f603cca4af47"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.0/sentinel-0.17.0-linux-amd64"
      sha256 "1e8692fa94404a873177398a4c306d7736d677c714faa8c1f31aea26b7dc20ed"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
