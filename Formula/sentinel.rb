# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.17.2"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.2/sentinel-0.17.2-darwin-arm64"
      sha256 "7609cd5931040e5407018fa3b9f9b1813c8e4ce057c51caa966bd0ac7cac5f2d"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.2/sentinel-0.17.2-darwin-amd64"
      sha256 "077997b553ffd0a056dd5a6a7b903315cf4339259d3be3718cc34580ac3e32d8"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.2/sentinel-0.17.2-linux-arm64"
      sha256 "11c5f81d878a5cc6c381d4d58bd4d4d282b39396a58571878f7269b464541757"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.2/sentinel-0.17.2-linux-amd64"
      sha256 "685498015e76ea6fe96cd2643af2f4f2dabb0cd071a659b66068c1be21e79f61"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
