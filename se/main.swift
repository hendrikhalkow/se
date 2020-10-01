//    se – Secure Enclave command line interface
//    Copyright (C) 2020  Hendrik M Halkow
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <https://www.gnu.org/licenses/>.

import ArgumentParser
import CryptoKit
import CoreData
import Foundation
import LocalAuthentication
import Logging

var logger = Logger(label: "com.halkow.se")

class SecretManager {
    private let persistentContainer = NSPersistentContainer(name: "se")

    public init() {
        if !SecureEnclave.isAvailable {
            logger.error("Secure Enclave is NOT available.")
            exit(1)
        }
        persistentContainer.loadPersistentStores(completionHandler: { (_, error) in
            if let error = error {
                logger.error("Unable to load persistent store:  \(error)")
                exit(1)
            }
        })
    }

    private func loadKeyAndSalt() throws -> (SecureEnclave.P256.KeyAgreement.PrivateKey, Data)? {
        guard let keyData = UserDefaults.standard.data(forKey: "key") else {
            return nil
        }
        guard let salt = UserDefaults.standard.data(forKey: "salt") else {
            return nil
        }

        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: keyData,
            authenticationContext: LAContext()
        )

        return (key, salt)
    }

    private static func randomData(length: Int) -> Data {
        var data = Data(count: length)
        _ = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!)
        }
        return data
    }

    private func generateKeyAndSalt() throws -> (SecureEnclave.P256.KeyAgreement.PrivateKey, Data) {

        let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     [.privateKeyUsage, .biometryCurrentSet],
                                                     nil)!

        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: access,
            authenticationContext: LAContext())

        let salt = SecretManager.randomData(length: 32)

        UserDefaults.standard.set(key.dataRepresentation, forKey: "key")
        UserDefaults.standard.set(salt, forKey: "salt")

        return (key, salt)
    }

    private func getSymmetricKey() throws -> SymmetricKey {
        // Try to load key and salt, if they don't exist generate them
        let (key, salt) = try loadKeyAndSalt() ?? generateKeyAndSalt()

        let sharedSecret = try key.sharedSecretFromKeyAgreement(with: key.publicKey)
        return sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self,
                                                    salt: salt,
                                                    sharedInfo: key.publicKey.rawRepresentation,
                                                    outputByteCount: 32)
    }

    public func get(key: String) throws {
        logger.debug("get \(key)")

        let fetchRequest = NSFetchRequest<NSFetchRequestResult>(entityName: "Entry")
        fetchRequest.fetchLimit = 1
        fetchRequest.predicate = NSPredicate(format: "key = %@", key)

        let managedContext = persistentContainer.newBackgroundContext()
        let fetchResult = try managedContext.fetch(fetchRequest)

        if fetchResult.count == 0 {
            logger.warning("No value found.")
            return
        }

        let entry = fetchResult[0] as! Entry // swiftlint:disable:this force_cast
        let encryptedValue = entry.encryptedValue!
        logger.debug("encrypted value: \(encryptedValue.base64EncodedString())")

        let sealedBox = try ChaChaPoly.SealedBox(combined: encryptedValue)
        let decryptionKey = try getSymmetricKey()
        let value = String(data: try ChaChaPoly.open(sealedBox, using: decryptionKey), encoding: .utf8)!

        print(value)
    }

    public func set(key: String) throws {
        logger.trace("set \(key)")

        guard let value = readLine() else {
            logger.error("Unable to read from stdin")
            return
        }

        let encryptionKey = try getSymmetricKey()
        let encryptedValue = try ChaChaPoly.seal(value.data(using: .utf8)!, using: encryptionKey).combined
        logger.debug("Encrypted value: \(encryptedValue.base64EncodedString())")

        let fetchRequest = NSFetchRequest<NSFetchRequestResult>(entityName: "Entry")
        fetchRequest.fetchLimit = 1
        fetchRequest.predicate = NSPredicate(format: "key = %@", key)
        let managedContext = persistentContainer.newBackgroundContext()
        let fetchResult = try managedContext.fetch(fetchRequest)
        if fetchResult.count == 0 {
            // Create new entry because it doesn't exit
            let entryEntity = NSEntityDescription.entity(forEntityName: "Entry", in: managedContext)!
            let entry = NSManagedObject(entity: entryEntity,
                                        insertInto: managedContext) as! Entry // swiftlint:disable:this force_cast
            entry.key = key
            entry.encryptedValue = encryptedValue
        } else {
            // Update existing entry
            let entry = fetchResult[0] as! Entry // swiftlint:disable:this force_cast
            entry.encryptedValue = encryptedValue
        }

        if managedContext.hasChanges {
            logger.debug("Saving changes")
            try managedContext.save()
        } else {
            logger.debug("No changes")
        }

        logger.info("Value for \(key) has been saved.")
    }
}

struct se: ParsableCommand { // swiftlint:disable:this type_name

    @Option(name: .shortAndLong, help: "The log level")
    private var logLevel: String?

    @Argument(help: "The command")
    private var command: String

    @Argument(help: "The key")
    private var key: String

    public mutating func run() throws {

        if logLevel != nil {
            logger.logLevel = Logger.Level(rawValue: logLevel!)!
        }

        let secretManager = SecretManager()

        if command == "get" {
            try secretManager.get(key: key)
        } else if command == "set" {
            try secretManager.set(key: key)
        }
    }
}

se.main()
