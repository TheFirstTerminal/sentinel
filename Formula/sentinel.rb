# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.17.8"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.8/sentinel-0.17.8-darwin-arm64"
      sha256 "d32405c0eb77f169b526c8d31fd95a6798b96d660d3a12cb0e757c3e324bb152"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.8/sentinel-0.17.8-darwin-amd64"
      sha256 "f220546d5613593a539a6a1fc1b282af2d2cb1045d2f286827987e09642cf994"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.8/sentinel-0.17.8-linux-arm64"
      sha256 "7b9f773c38ba29b37ed9292b4252b71f84d836dec652f6f5eaaa0dd16b51fef6"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.17.8/sentinel-0.17.8-linux-amd64"
      sha256 "a3600cb3957514a0034598b3717467ee4ccb8902adb785f4c0352edb01b705e7"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
