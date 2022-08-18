Pod::Spec.new do |spec|

  spec.name         = "DidcommSDK"
  spec.version      = "0.3.4"
  spec.summary      = "Didcomm v2 created from rust."

  spec.description  = "Didcomm v2 created from rust. UNIFFI was used to convert from rust to Swift."
  spec.homepage     = "https://github.com/sicpa-dlab/didcomm-rust"

  spec.license      =  { :type => 'Apache License 2.0', :file => 'LICENSE.txt' }

  spec.authors      = { "Sicpa-Dlab" => "dlab@sicpa.com" }
  spec.platforms    = { :ios => "10.0" }
  spec.source           = { :http => 'https://github.com/sicpa-dlab/didcomm-rust/releases/download/v0.3.4/didcomm-swift-0.3.4.tar.gz'}
  spec.swift_version = '4.0'

  spec.ios.vendored_library = '*.a'
  spec.source_files = ['didcomm.swift', 'didcommFFI.h']

  spec.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64 i386' }
  spec.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64 i386' }

end
