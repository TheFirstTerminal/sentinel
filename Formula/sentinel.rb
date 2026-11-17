# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap tsxmamii/sentinel https://github.com/tsxmamii/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/tsxmamii/sentinel"
  version "0.15.0"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.15.0/sentinel-0.15.0-darwin-arm64"
      sha256 "17180760c6dec87e99fec0e036906f7f33c4f8f14864649994a4349d9b8a1389"
    end
    on_intel do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.15.0/sentinel-0.15.0-darwin-amd64"
      sha256 "6368226433a8af1495c4c3deaa3086e67ce8d7d2590c413b6c76f19f579c3fab"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.15.0/sentinel-0.15.0-linux-arm64"
      sha256 "f7ef1407ad339dbd0d76d45b064dd8bf3a52011b14a69fd1e9294c59e9914e94"
    end
    on_intel do
      url "https://github.com/tsxmamii/sentinel/releases/download/v0.15.0/sentinel-0.15.0-linux-amd64"
      sha256 "28b93ab01c429059cc957fde42dd9683f4ec573993c42bf6d3dbb18aabe00791"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
