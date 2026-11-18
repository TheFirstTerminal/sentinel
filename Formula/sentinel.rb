# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap tsxmamii/sentinel https://github.com/tsxmamii/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/tsxmamii/sentinel"
  version "0.16.1"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.16.1/sentinel-0.16.1-darwin-arm64"
      sha256 "51262b4f1fb7df0f87a05d9f0ec663031c653fe3bada0fa951f6b5231606416a"
    end
    on_intel do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.16.1/sentinel-0.16.1-darwin-amd64"
      sha256 "7edf745b39b33b874d52c49d62192af3915232081d60769ec5f4ab84a63d1c87"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.16.1/sentinel-0.16.1-linux-arm64"
      sha256 "34c4ffc186f72754102f08a936a93367fa5c6b0176a10518489438e9eca0bc0d"
    end
    on_intel do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.16.1/sentinel-0.16.1-linux-amd64"
      sha256 "8d55bceab7b3da3752f96a69d5dbe800f92069a38d7e928cee58472a805fe453"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
