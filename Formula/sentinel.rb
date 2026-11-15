# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap tsxmamii/sentinel https://github.com/tsxmamii/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/tsxmamii/sentinel"
  version "0.14.0"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.14.0/sentinel-0.14.0-darwin-arm64"
      sha256 "6b87b2e7dc6232a481baff049a37dc972b290fae7857e811c6efdb47c5bf7ed8"
    end
    on_intel do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.14.0/sentinel-0.14.0-darwin-amd64"
      sha256 "9c548fb974a23e05a247ac0c0289a6c63fa54784812590ddc85ecb6fd4533149"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.14.0/sentinel-0.14.0-linux-arm64"
      sha256 "f8dbb085eda0c255177b2d9afc4992bacca042979ab89ec1a229d3f8b831f58e"
    end
    on_intel do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.14.0/sentinel-0.14.0-linux-amd64"
      sha256 "59d6fa1fcbcce0f0a5f24f6ffbc1570d66913d5019be9dcf37f79a98b5586e29"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
