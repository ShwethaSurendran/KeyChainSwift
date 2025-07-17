// The Swift Programming Language
// https://docs.swift.org/swift-book

import Foundation

enum KeychainError: Error {
  case duplicateItem
  case invalidData
  case status(String?)
  case nullValue
}

@available(iOS 13.0.0, *)
public final actor KeyChainSwift {
    
    private var accessGroup: String?
    
    public init() {}
    
    public func setAccessGroup(_ group: String) {
        accessGroup = group
    }
    
    public func set(_ value: String,
                    forKey: String,
                    withAccessType: CFString? = nil) throws -> Bool {
        guard let data = value.data(using: String.Encoding.utf8) else {
            throw KeychainError.invalidData
        }
        
        return try set(data, forKey: forKey, withAccessType: withAccessType)
    }
    
    public func set(_ value: Bool,
                    forKey: String,
                    withAccessType: CFString? = nil) throws -> Bool {
        let bool: UInt8 = value ? 1 : 0
        
        return try set(Data([bool]), forKey: forKey, withAccessType: withAccessType)
    }
    
    public func set(_ data: Data,
                    forKey: String,
                    withAccessType: CFString? = nil) throws -> Bool {
        var query : [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecValueData as String: data,
            kSecAttrAccessible as String: withAccessType ?? kSecAttrAccessibleWhenUnlocked,
            kSecAttrAccount as String: forKey
        ]
        
        addAccessGroupIfAvailable(&query)
        
        let resultStatus = SecItemAdd(query as CFDictionary, nil)
        if resultStatus == noErr {
            return true
        } else {
            throw KeychainError.status(getSecCopyErrorMessage(resultStatus))
        }
    }
    
}

@available(iOS 13.0.0, *)
extension KeyChainSwift {
    public func getValueFor(_ key: String, withAccessType: CFString? = nil) throws -> String {
        guard let data = try getDataFor(key, withAccessType: withAccessType) else {
            throw KeychainError.nullValue
        }
        guard let stringFromData = String(data: data, encoding: .utf8) else {
            throw KeychainError.invalidData
        }
        
        return stringFromData
    }
    
    public func getBoolValueFor(_ key: String, withAccessType: CFString? = nil) throws -> Bool {
        guard let data = try getDataFor(key, withAccessType: withAccessType),
              let firstItem =  data.first  else {
            throw KeychainError.nullValue
        }
        
        return firstItem == 1
    }
    
    public func getDataFor(_ key: String, withAccessType: CFString? = nil) throws -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String : kCFBooleanTrue ?? true , // Request data return
            kSecMatchLimitOne as String: kCFBooleanTrue ?? true, // Expect single result
            kSecAttrAccessible as String: withAccessType ?? kSecAttrAccessibleWhenUnlocked,
        ]
        
        addAccessGroupIfAvailable(&query)
        
        var dataRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataRef)
        if status == errSecItemNotFound {
            return nil // No data found
        } else if status != errSecSuccess {
            throw KeychainError.status(getSecCopyErrorMessage(status))
        }
        
        guard let data = dataRef as? Data else {
            throw KeychainError.invalidData
        }
        return data
    }
}

@available(iOS 13.0.0, *)
internal extension KeyChainSwift {
    func getSecCopyErrorMessage(_ status: OSStatus) -> String? {
        SecCopyErrorMessageString(status, nil) as? String
    }
}

@available(iOS 13.0.0, *)
extension KeyChainSwift {
    func addAccessGroupIfAvailable(_ items:inout [String:Any]) {
        guard let accessGroup else {return}
        items[kSecAttrAccessGroup as String] = accessGroup
    }
}
