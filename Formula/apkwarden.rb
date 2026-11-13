class Apkwarden < Formula
  desc "Fast, reachability-first Android security analyzer"
  homepage "https://github.com/no-hup/apkwarden"
  url "https://github.com/no-hup/apkwarden/releases/download/v0.1.0/apkwarden-v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"

  depends_on "openjdk@17"

  def install
    rm_f Dir["bin/*.bat"]
    libexec.install %w[bin lib]
    (bin/"apkwarden").write_env_script libexec/"bin/apkwarden",
                                        Language::Java.overridable_java_home_env("17")
  end

  test do
    assert_match "APKwarden: Fast, reachability-first Android security analyzer",
                 shell_output("#{bin}/apkwarden --help")
  end
end
