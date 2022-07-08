require "json"


Pod::Spec.new do |s|
  s.name         = "didcomm-swift"
  s.version      = "0.3.1"
  s.summary      = "Swift wrapper for DIDComm messaging library"
  s.description  = "Swift wrapper for DIDComm messaging library"
  s.homepage     = "https://github.com/sicpa-dlab/didcomm-rust.git"

  s.license      =  { :type => 'Apache License 2.0', :file => 'LICENSE' }
  s.authors      = { "Sicpa-Dlab" => "dlab@sicpa.com" }
  s.platforms    = { :ios => "10.0" }
  s.source           = { :http => 'https://github.com/sicpa-dlab/didcomm-rust/releases/download/v0.3.1/didcomm-swift-0.3.1.tar.gz' }
  s.swift_version = '4.0'

  s.public_header_files = 'didcomm-swift/*.h'
  s.ios.vendored_library = 'didcomm-swift/*.a'

end