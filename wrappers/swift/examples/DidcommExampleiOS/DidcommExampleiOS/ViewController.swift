import UIKit
import DidcommSDK

class ViewController: UIViewController {

    let msg = Message(id: "1234567890",
                      typ: "application/didcomm-plain+json",
                      type: "http://example.com/protocols/lets_do_lunch/1.0/proposal",
                      body: "{\"messagespecificattribute\": \"and its value\"}",
                      from: "did:example:alice",
                      to: ["did:example:bob"],
                      thid: nil,
                      pthid: nil,
                      extraHeaders: [:],
                      createdTime: 1516269022,
                      expiresTime: 1516385931,
                      fromPrior: nil,
                      attachments: nil)
    
    override func viewDidLoad() {
        super.viewDidLoad()
        placeLabel()
        nonRepudiableEncryption(msg)
        plainText(msg)
        packSignedUnencrypted(msg)
    }
    
    private func placeLabel() {
        let title = UILabel()
        title.text = "Didcomm Swift Demo Initialized:\nSee Xcode logs."
        title.numberOfLines = 2
        title.sizeToFit()
        title.textAlignment = .center
        title.center = self.view.center
        self.view.addSubview(title)
    }
    
    private func packSignedUnencrypted(_ msg : Message) {
        let didResolver = ExampleDidResolver(knownDids: [ALICE_DID_DOC, BOB_DID_DOC])
        let secretsResolver = ExampleSecretsResolver(knownSecrets: ALICE_SECRETS)
        let _ = DidComm(didResolver: didResolver, secretResolver: secretsResolver)
            .packSigned(msg: msg, signBy: ALICE_DID, cb: self)
    }
    
    private func plainText(_ msg : Message) {
        let didResolver = ExampleDidResolver(knownDids: [ALICE_DID_DOC, BOB_DID_DOC])
        let secretsResolver = ExampleSecretsResolver(knownSecrets: [])
        let _ = DidComm(didResolver: didResolver, secretResolver: secretsResolver)
            .packPlaintext(msg: msg, cb: self)
    }
    
    private func nonRepudiableEncryption(_ msg : Message) {
                
        let didResolver = ExampleDidResolver(knownDids: [ALICE_DID_DOC, BOB_DID_DOC])
        let secretsResolver = ExampleSecretsResolver(knownSecrets: ALICE_SECRETS)
        
        /**
         This is the standard options for Encrypting.
         */
        let options = PackEncryptedOptions(protectSender: false,
                                           forward: false,
                                           forwardHeaders: [:],
                                           messagingService: nil,
                                           encAlgAuth: .a256cbcHs512Ecdh1puA256kw,
                                           encAlgAnon: .xc20pEcdhEsA256kw)
        
        let _ = DidComm(didResolver: didResolver, secretResolver: secretsResolver)
            .packEncrypted(msg: msg,
                                          to: BOB_DID,
                                          from: ALICE_DID,
                                          signBy: ALICE_DID,
                                          options: options,
                                          cb: self)
    }
    
    
    
    /**
     Helper function to unpack a message.
    */
    private func unpackDids(msg: String,
                            knownDids: [DidDoc],
                            knownSecrets: [Secret],
                            packOpt: UnpackOptions = .init(expectDecryptByAllKeys: false,
                                                           unwrapReWrappingForward: false)) {
        
        let didResolver = ExampleDidResolver(knownDids: knownDids)
        let secretsResolver = ExampleSecretsResolver(knownSecrets: knownSecrets)
        let _ = DidComm(didResolver: didResolver, secretResolver: secretsResolver)
            .unpack(msg: msg, options: packOpt, cb: self)
    }
}



extension ViewController: OnPackEncryptedResult, OnPackPlaintextResult, OnPackSignedResult, OnUnpackResult {
    
    func success(result: String, metadata: PackSignedMetadata) {
        print("[PackSigned] SUCESS\n")
        print("Result: ", result)
        print("Metadata: ", metadata)
        
        self.unpackDids(msg: result, knownDids: [ALICE_DID_DOC, BOB_DID_DOC], knownSecrets: [])
    }
    
    func success(result: String) {
        print("[OnPackPlaintext] SUCESS\n")
        print("Result: ", result)
        
        self.unpackDids(msg: result, knownDids: [ALICE_DID_DOC, BOB_DID_DOC], knownSecrets: [])
    }
    
    func success(result: String, metadata: PackEncryptedMetadata) {
        print("[PackEncrypted] SUCESS:\n")
        print("Result: ", result)
        print("Metadata: ", metadata)
        
        self.unpackDids(msg: result, knownDids: [ALICE_DID_DOC, BOB_DID_DOC], knownSecrets: BOB_SECRETS)
    }
    
    func success(result: Message, metadata: UnpackMetadata) {
        print("[Unpack] SUCESS:\n")
        print("Result: ", result)
    }
    
    /// This function implements the error protocol for `OnPackEncryptedResult`, `OnPackPlaintextResult`, `OnPackSignedResult` and `OnUnpackResult`.
    func error(err: ErrorKind, msg: String) {
        print("[ERROR]:\n")
        print(err)
        print(msg)
    }
}
