Pod::Spec.new do |s|
  s.name             = 'TangemBlsSignature'
  s.version          = '0.0.1'
  s.summary          = 'BLS_Signature crypto library for Swift'

  s.description      = <<-DESC
BLS-iOS includes crypto functions that can be used in pure Swift.
                       DESC

  s.homepage         = 'https://github.com/tangem/blst-ios'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  # s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Tangem AG' => '' }
  s.source           = { :path => '.' }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.ios.deployment_target = '13.0'
  
  s.vendored_frameworks = '**/Bls_Signature.xcframework'

end
