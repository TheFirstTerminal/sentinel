# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap tsxmamii/sentinel https://github.com/tsxmamii/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/tsxmamii/sentinel"
  version "0.16.0"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.16.0/sentinel-0.16.0-darwin-arm64"
      sha256 "b9dfe47069ffb4006bbad8db11169d3ab83d1a08b618401754cec271a2bc1734"
    end
    on_intel do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.16.0/sentinel-0.16.0-darwin-amd64"
      sha256 "56ec940329e94cfcd28f98027e14365eade4f9379f9b5250672be854d022d06d"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.16.0/sentinel-0.16.0-linux-arm64"
      sha256 "9c85d98285e1e9433f90e8c733339701366d3f7f8c826653ef6c3764397a8ac3"
    end
    on_intel do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.16.0/sentinel-0.16.0-linux-amd64"
      sha256 "88e286cabb1aaa48a2aee2343df63c3ebcc4225e724b6513a596f61cb2ede7cb"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
