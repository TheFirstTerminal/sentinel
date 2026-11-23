# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.17.7"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.7/sentinel-0.17.7-darwin-arm64"
      sha256 "774e3e8af5e1461154ff50c0aa2ce2f6d69e95082fdca5f40355546e846466a6"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.7/sentinel-0.17.7-darwin-amd64"
      sha256 "731a5cda1c4601f6eb7904f4c268ebe87f380ba7a6ab939afae753567b1b47ab"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.7/sentinel-0.17.7-linux-arm64"
      sha256 "322410b0b97b3b16ba85dc2081097c2211e50f86e2525f53b3d6e5bf83df5241"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.7/sentinel-0.17.7-linux-amd64"
      sha256 "ba17dd1e10bcbe5e553b3d0d3922234f2a40b9f094c55ad461ef2ea062927436"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
