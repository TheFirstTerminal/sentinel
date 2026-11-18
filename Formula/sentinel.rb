# Homebrew formula for Sentinel, updated by the release workflow.
#   brew tap thefirstterminal/sentinel https://github.com/TheFirstTerminal/sentinel
#   brew install sentinel
class Sentinel < Formula
  desc "Security gateway for web apps, APIs and AI endpoints that explains every decision"
  homepage "https://github.com/TheFirstTerminal/sentinel"
  version "0.16.3"
  license :cannot_represent # PolyForm Shield 1.0.0

  on_macos do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.16.3/sentinel-0.16.3-darwin-arm64"
      sha256 "f2386453ad630e693d76edeb7aa091a03c64632f35f4cc0d8fed526b6041b91e"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.16.3/sentinel-0.16.3-darwin-amd64"
      sha256 "413542f08313732c10c6648d3617726692bb843d1bbfff59f083928c368dd3ba"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.16.3/sentinel-0.16.3-linux-arm64"
      sha256 "d079127cffbf73a936d1d92d299505ad1680285d56ba3980bf040fec2a6562c5"
    end
    on_intel do
      url "https://github.com/TheFirstTerminal/sentinel/releases/download/v0.16.3/sentinel-0.16.3-linux-amd64"
      sha256 "5a3d3c77f8beaea7e34909f01839600ecfa0f06907d0c146446622575c09f734"
    end
  end

  def install
    bin.install Dir["sentinel-*"].first => "sentinel"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sentinel version")
  end
end
