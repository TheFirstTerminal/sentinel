# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.17.6"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.6/sentinel-0.17.6-darwin-arm64"
      sha256 "e75c786d25a6a5db2b36d32876cafc458499d450fc8eaa01837445add16225e3"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.6/sentinel-0.17.6-darwin-amd64"
      sha256 "46b7231cd564aa36d90e4783aa0ab177103f84fc4ccb087b140020af5087ed0d"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.6/sentinel-0.17.6-linux-arm64"
      sha256 "3b9fd03f120ce9c29310828ba4135ad1141f076bcf361277105ff0f2586167db"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.6/sentinel-0.17.6-linux-amd64"
      sha256 "956d68ff547ca1c8e23bd6617ae03f39f547432bdef7868e6dd517686361eb89"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
