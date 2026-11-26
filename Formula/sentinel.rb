# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.19.1"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.19.1/sentinel-0.19.1-darwin-arm64"
      sha256 "bb402093b0eee0c28284eab849baf1e3eadd5a2828b61757485e9648ff9ae433"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.19.1/sentinel-0.19.1-darwin-amd64"
      sha256 "5683c6014e1bd644851af758051925c9761633e202b07c07c0d25796f3f2d727"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.19.1/sentinel-0.19.1-linux-arm64"
      sha256 "1be37a0a206d99f297396d91c88209c5fbf950acae548d2ccc584b93b05321d7"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.19.1/sentinel-0.19.1-linux-amd64"
      sha256 "64560725123d5af98c75611595f3f5f8f7c747ebf4fa9ada13686833cba85857"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
